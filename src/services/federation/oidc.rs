// OpenID Connect (OIDC) Identity Provider Implementation
// Supports OIDC Authorization Code Flow with PKCE

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use super::{AuthRequest, AuthResponse, IdentityProvider, IdentityProviderConfig, UserInfo};

/// OIDC Identity Provider
pub struct OidcIdentityProvider {
    /// Provider configuration
    config: IdentityProviderConfig,
    /// OIDC issuer URL
    issuer_url: String,
    /// OAuth client ID
    client_id: String,
    /// OAuth client secret
    client_secret: String,
    /// OAuth redirect URI
    redirect_uri: String,
    /// Token endpoint URL
    token_endpoint: String,
    /// UserInfo endpoint URL
    userinfo_endpoint: String,
    /// End session endpoint URL
    end_session_endpoint: String,
    /// JWKS URI for token validation
    jwks_uri: String,
    /// HTTP client for API calls
    http_client: Client,
    /// JWKS cache (public keys for JWT validation)
    jwks_cache: Arc<DashMap<String, DecodingKey>>,
}

impl OidcIdentityProvider {
    /// Create new OIDC identity provider
    pub async fn new(config: IdentityProviderConfig) -> Result<Self> {
        let issuer_url = config
            .config
            .get("issuer_url")
            .ok_or_else(|| anyhow!("Missing issuer_url in OIDC config"))?
            .clone();

        let client_id = config
            .config
            .get("client_id")
            .ok_or_else(|| anyhow!("Missing client_id in OIDC config"))?
            .clone();

        let client_secret = config
            .config
            .get("client_secret")
            .ok_or_else(|| anyhow!("Missing client_secret in OIDC config"))?
            .clone();

        let redirect_uri = config
            .config
            .get("redirect_uri")
            .ok_or_else(|| anyhow!("Missing redirect_uri in OIDC config"))?
            .clone();

        // Try to discover endpoints from well-known configuration
        let http_client = Client::new();
        let (token_endpoint, userinfo_endpoint, end_session_endpoint, jwks_uri) =
            Self::discover_endpoints(&http_client, &issuer_url, &config.config).await?;

        Ok(Self {
            config,
            issuer_url,
            client_id,
            client_secret,
            redirect_uri,
            token_endpoint,
            userinfo_endpoint,
            end_session_endpoint,
            jwks_uri,
            http_client,
            jwks_cache: Arc::new(DashMap::new()),
        })
    }

    /// Discover OIDC endpoints from well-known configuration
    async fn discover_endpoints(
        client: &Client,
        issuer_url: &str,
        config: &HashMap<String, String>,
    ) -> Result<(String, String, String, String)> {
        // Check if endpoints are manually configured
        if let Some(token_endpoint) = config.get("token_endpoint") {
            let userinfo_endpoint = config
                .get("userinfo_endpoint")
                .ok_or_else(|| anyhow!("Missing userinfo_endpoint"))?;
            let end_session_endpoint = config
                .get("end_session_endpoint")
                .unwrap_or(&"".to_string())
                .clone();
            let jwks_uri = config
                .get("jwks_uri")
                .ok_or_else(|| anyhow!("Missing jwks_uri"))?;

            return Ok((
                token_endpoint.clone(),
                userinfo_endpoint.clone(),
                end_session_endpoint,
                jwks_uri.clone(),
            ));
        }

        // Try OIDC discovery
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        match client.get(&discovery_url).send().await {
            Ok(response) => {
                let discovery: OidcDiscovery = response.json().await?;
                Ok((
                    discovery.token_endpoint,
                    discovery.userinfo_endpoint,
                    discovery.end_session_endpoint.unwrap_or_default(),
                    discovery.jwks_uri,
                ))
            }
            Err(e) => Err(anyhow!(
                "OIDC discovery failed: {}. Please configure endpoints manually.",
                e
            )),
        }
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("redirect_uri", &self.redirect_uri),
        ];

        // Add PKCE code verifier if provided
        let code_verifier_owned;
        if let Some(verifier) = code_verifier {
            code_verifier_owned = verifier.to_string();
            params.push(("code_verifier", &code_verifier_owned));
        }

        let response = self
            .http_client
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Token exchange failed: {}", error_text));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Fetch JWKS (JSON Web Key Set) from provider
    async fn fetch_jwks(&self) -> Result<Jwks> {
        let response = self.http_client.get(&self.jwks_uri).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch JWKS"));
        }

        let jwks: Jwks = response.json().await?;
        Ok(jwks)
    }

    /// Get or cache public key for JWT validation
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey> {
        // Check cache first
        if let Some(key) = self.jwks_cache.get(kid) {
            return Ok(key.clone());
        }

        // Fetch JWKS
        let jwks = self.fetch_jwks().await?;

        // Find key with matching kid
        for key in jwks.keys {
            if key.kid == kid {
                let decoding_key = if key.kty == "RSA" {
                    // RSA key
                    if let (Some(n), Some(e)) = (key.n, key.e) {
                        DecodingKey::from_rsa_components(&n, &e)?
                    } else {
                        return Err(anyhow!("Invalid RSA key"));
                    }
                } else if key.kty == "EC" {
                    // EC key (not fully supported by jsonwebtoken, but we try)
                    return Err(anyhow!("EC keys not yet fully supported"));
                } else {
                    return Err(anyhow!("Unsupported key type: {}", key.kty));
                };

                // Cache the key
                self.jwks_cache
                    .insert(kid.to_string(), decoding_key.clone());
                return Ok(decoding_key);
            }
        }

        Err(anyhow!("Key with kid {} not found in JWKS", kid))
    }

    /// Validate ID token JWT
    async fn validate_id_token(&self, id_token: &str) -> Result<IdTokenClaims> {
        // Decode header to get kid
        let header = decode_header(id_token)?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow!("Missing kid in token header"))?;

        // Get decoding key
        let decoding_key = self.get_decoding_key(&kid).await?;

        // Set up validation rules
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer_url]);
        validation.set_audience(&[&self.client_id]);

        // Decode and validate token
        let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)?;

        Ok(token_data.claims)
    }

    /// Call userinfo endpoint
    async fn call_userinfo_endpoint(&self, access_token: &str) -> Result<UserInfo> {
        let response = self
            .http_client
            .get(&self.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("UserInfo request failed: {}", error_text));
        }

        let userinfo: OidcUserInfo = response.json().await?;
        Ok(self.map_oidc_to_user_info(userinfo))
    }

    /// Map OIDC userinfo to UserInfo structure
    fn map_oidc_to_user_info(&self, oidc: OidcUserInfo) -> UserInfo {
        UserInfo {
            id: oidc.sub,
            username: oidc.preferred_username,
            email: oidc.email,
            first_name: oidc.given_name,
            last_name: oidc.family_name,
            groups: oidc.groups.unwrap_or_default(),
            roles: oidc.roles.unwrap_or_default(),
            attributes: HashMap::new(),
        }
    }

    /// Revoke token (access or refresh)
    async fn revoke_token(&self, token: &str, token_type_hint: &str) -> Result<()> {
        // Check if provider supports token revocation
        let revocation_endpoint = self.config.config.get("revocation_endpoint");

        if let Some(endpoint) = revocation_endpoint {
            let params = vec![
                ("token", token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("token_type_hint", token_type_hint),
            ];

            let response = self.http_client.post(endpoint).form(&params).send().await?;

            if !response.status().is_success() {
                tracing::warn!("Token revocation failed: {}", response.status());
            }
        } else {
            tracing::debug!("Provider does not support token revocation");
        }

        Ok(())
    }
}

#[async_trait]
impl IdentityProvider for OidcIdentityProvider {
    async fn authenticate(&self, request: &AuthRequest) -> Result<AuthResponse> {
        if let Some(code) = &request.oidc_code {
            // Extract PKCE code verifier from parameters
            let code_verifier = request.parameters.get("code_verifier").map(|s| s.as_str());

            // Exchange authorization code for tokens
            let token_response = match self.exchange_code(code, code_verifier).await {
                Ok(tokens) => tokens,
                Err(e) => {
                    return Ok(AuthResponse {
                        success: false,
                        user_id: None,
                        username: None,
                        email: None,
                        groups: vec![],
                        roles: vec![],
                        attributes: HashMap::new(),
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some(format!("Token exchange failed: {}", e)),
                    });
                }
            };

            // Validate ID token
            let id_token_claims = match self.validate_id_token(&token_response.id_token).await {
                Ok(claims) => claims,
                Err(e) => {
                    return Ok(AuthResponse {
                        success: false,
                        user_id: None,
                        username: None,
                        email: None,
                        groups: vec![],
                        roles: vec![],
                        attributes: HashMap::new(),
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some(format!("ID token validation failed: {}", e)),
                    });
                }
            };

            // Get additional user info from userinfo endpoint
            let user_info = self
                .call_userinfo_endpoint(&token_response.access_token)
                .await
                .unwrap_or_else(|_| UserInfo {
                    id: id_token_claims.sub.clone(),
                    username: id_token_claims.preferred_username.clone(),
                    email: id_token_claims.email.clone(),
                    first_name: id_token_claims.given_name.clone(),
                    last_name: id_token_claims.family_name.clone(),
                    groups: vec![],
                    roles: vec![],
                    attributes: HashMap::new(),
                });

            Ok(AuthResponse {
                success: true,
                user_id: Some(user_info.id.clone()),
                username: user_info.username.clone(),
                email: user_info.email.clone(),
                groups: user_info.groups.clone(),
                roles: user_info.roles.clone(),
                attributes: user_info.attributes.clone(),
                token: Some(token_response.access_token),
                refresh_token: token_response.refresh_token,
                expires_at: Some(token_response.expires_in as u64),
                error: None,
            })
        } else {
            Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("No OIDC code provided".to_string()),
            })
        }
    }

    async fn get_user_info(&self, token: &str) -> Result<UserInfo> {
        self.call_userinfo_endpoint(token).await
    }

    async fn validate_token(&self, token: &str) -> Result<bool> {
        // Validate JWT access token or ID token
        // Try to decode as JWT first
        if let Ok(header) = decode_header(token) {
            if let Some(kid) = header.kid {
                if let Ok(decoding_key) = self.get_decoding_key(&kid).await {
                    let mut validation = Validation::new(header.alg);
                    validation.set_issuer(&[&self.issuer_url]);
                    // For access tokens, audience might be different - don't validate
                    let empty_audiences: &[&str] = &[];
                    validation.set_audience(empty_audiences);
                    validation.validate_aud = false; // Explicitly disable audience validation

                    if decode::<serde_json::Value>(token, &decoding_key, &validation).is_ok() {
                        return Ok(true);
                    }
                }
            }
        }

        // If JWT validation fails, try token introspection endpoint
        if let Some(introspection_endpoint) = self.config.config.get("introspection_endpoint") {
            let params = vec![
                ("token", token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ];

            if let Ok(response) = self
                .http_client
                .post(introspection_endpoint)
                .form(&params)
                .send()
                .await
            {
                if let Ok(introspection) = response.json::<TokenIntrospection>().await {
                    return Ok(introspection.active);
                }
            }
        }

        Ok(false)
    }

    async fn logout(&self, token: &str) -> Result<()> {
        // Revoke access token
        self.revoke_token(token, "access_token").await?;

        // If end_session_endpoint is configured, user should be redirected there
        if !self.end_session_endpoint.is_empty() {
            tracing::info!(
                "User should be redirected to: {}",
                self.end_session_endpoint
            );
        }

        Ok(())
    }
}

/// OIDC Discovery document
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
}

/// Token response from token endpoint
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    id_token: String,
}

/// ID Token claims (JWT payload)
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    /// Subject (user ID)
    sub: String,
    /// Issuer
    iss: String,
    /// Audience
    aud: String,
    /// Expiration time
    exp: i64,
    /// Issued at time
    iat: i64,
    /// Nonce (optional)
    nonce: Option<String>,
    /// Preferred username
    preferred_username: Option<String>,
    /// Email
    email: Option<String>,
    /// Email verified
    email_verified: Option<bool>,
    /// Given name
    given_name: Option<String>,
    /// Family name
    family_name: Option<String>,
}

/// UserInfo response from userinfo endpoint
#[derive(Debug, Deserialize)]
struct OidcUserInfo {
    sub: String,
    preferred_username: Option<String>,
    email: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    groups: Option<Vec<String>>,
    roles: Option<Vec<String>>,
}

/// JWKS (JSON Web Key Set)
#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

/// JWK (JSON Web Key)
#[derive(Debug, Deserialize)]
struct JwkKey {
    /// Key type (RSA, EC, etc.)
    kty: String,
    /// Key ID
    kid: String,
    /// Algorithm
    alg: Option<String>,
    /// RSA modulus
    n: Option<String>,
    /// RSA exponent
    e: Option<String>,
}

/// Token introspection response
#[derive(Debug, Deserialize)]
struct TokenIntrospection {
    active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_userinfo_mapping() {
        let oidc_info = OidcUserInfo {
            sub: "123456".to_string(),
            preferred_username: Some("john.doe".to_string()),
            email: Some("john@example.com".to_string()),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            groups: Some(vec!["admins".to_string()]),
            roles: Some(vec!["admin".to_string()]),
        };

        // This would require an OidcIdentityProvider instance
        // For now, just verify the structs compile
        assert_eq!(oidc_info.sub, "123456");
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_oidc_discovery() {
        // This test requires network access to a real OIDC provider
        // Run with: cargo test --features test -- --ignored
    }
}
