use crate::crypto::ed25519_keys::{get_ed25519_jwk, ED25519_KEYPAIR};
use crate::error::AuthencError;
use crate::utils::crypto_monitor::CryptoMonitor;
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{Json, Redirect},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcAuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<String>,
}

/// Generate JWT token using Ed25519 - secure replacement for RSA
pub fn generate_ed25519_jwt(
    sub: &str,
    aud: &str,
    email: Option<&str>,
    name: Option<&str>,
    role: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();

    let header = Ed25519JwtHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
        kid: "authence-ed25519-key".to_string(),
    };

    let claims = OidcIdTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: now + 3600,
        iat: now,
        email: email.map(|e| e.to_string()),
        name: name.map(|n| n.to_string()),
        role: role.map(|r| r.to_string()),
    };

    // Monitor Ed25519 operations for security
    CryptoMonitor::monitor_rsa_operation("ed25519_jwt_signing", || {
        // Encode header and payload
        let header_json = serde_json::to_string(&header).unwrap();
        let claims_json = serde_json::to_string(&claims).unwrap();

        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(claims_json.as_bytes());

        // Create signing input
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with Ed25519
        let signature: Signature = ED25519_KEYPAIR.sign(signing_input.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        format!("{}.{}", signing_input, signature_b64)
    })
}

/// OIDC JWKS endpoint with Ed25519 keys - replaces RSA JWKS
pub async fn oidc_jwks_ed25519() -> Result<Json<serde_json::Value>, AuthencError> {
    let jwk = get_ed25519_jwk();
    let jwks = serde_json::json!({
        "keys": [jwk]
    });
    Ok(Json(jwks))
}

/// OIDC token endpoint using Ed25519 - secure replacement for RSA
pub async fn oidc_token_ed25519(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Simplified token endpoint for demonstration
    let grant_type = params
        .get("grant_type")
        .ok_or(AuthencError::validation("Bad request"))?;

    if grant_type != "authorization_code" {
        return Err(AuthencError::validation("Bad request"));
    }

    // Generate tokens using Ed25519
    let access_token = generate_ed25519_jwt(
        "demo_user",
        "demo_client",
        Some("user@example.com"),
        Some("Demo User"),
        Some("user"),
    );

    let id_token = generate_ed25519_jwt(
        "demo_user",
        "demo_client",
        Some("user@example.com"),
        Some("Demo User"),
        Some("user"),
    );

    let response = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": "openid profile email"
    });

    Ok(Json(response))
}

/// OIDC discovery endpoint with Ed25519 algorithm support
pub async fn oidc_discovery_ed25519() -> Result<Json<serde_json::Value>, AuthencError> {
    let discovery = serde_json::json!({
        "issuer": "http://localhost:8080/v1",
        "authorization_endpoint": "http://localhost:8080/v1/oidc/authorize",
        "token_endpoint": "http://localhost:8080/v1/oidc/token",
        "jwks_uri": "http://localhost:8080/v1/oidc/jwks",
        "userinfo_endpoint": "http://localhost:8080/v1/oidc/userinfo",
        "response_types_supported": ["code", "id_token", "token id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "email", "name", "role"]
    });

    Ok(Json(discovery))
}

/// OIDC userinfo endpoint with Ed25519 - secure replacement for RSA
pub async fn oidc_userinfo_ed25519(
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Extract Authorization header
    let _auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AuthencError::unauthorized("Unauthorized"))?;

    // In a real implementation, this would:
    // 1. Validate the access token
    // 2. Extract user information from the token
    // 3. Return appropriate user claims based on scope

    // For demonstration, return mock user info
    let userinfo = serde_json::json!({
        "sub": "user123",
        "email": "user@example.com",
        "email_verified": true,
        "name": "Demo User",
        "role": "user",
        "updated_at": chrono::Utc::now().timestamp()
    });

    Ok(Json(userinfo))
}

/// OIDC authorize endpoint with Ed25519 - secure replacement for RSA
pub async fn oidc_authorize_ed25519(
    Query(params): Query<OidcAuthorizeQuery>,
) -> Result<Redirect, StatusCode> {
    // Validate required parameters
    if params.response_type != "code"
        && params.response_type != "id_token"
        && params.response_type != "token id_token"
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // In a real implementation, this would:
    // 1. Validate client_id and redirect_uri
    // 2. Check user authentication
    // 3. Generate authorization code
    // 4. Store code with associated data
    // 5. Redirect back to client

    // For demonstration, generate a mock authorization code
    let auth_code = "mock_auth_code_12345";

    // Build redirect URI with authorization code
    let mut redirect_uri = params.redirect_uri.clone();
    redirect_uri.push_str(&format!("?code={}", auth_code));

    if let Some(state) = params.state {
        redirect_uri.push_str(&format!("&state={}", state));
    }

    Ok(Redirect::to(&redirect_uri))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_jwt_generation() {
        let token = generate_ed25519_jwt(
            "user123",
            "test-audience",
            Some("user@example.com"),
            Some("Test User"),
            Some("admin"),
        );

        // Token should have 3 parts
        assert_eq!(token.split('.').count(), 3);

        // Should contain proper header
        let parts: Vec<&str> = token.split('.').collect();
        let header_json =
            String::from_utf8(Base64UrlUnpadded::decode_vec(parts[0]).unwrap()).unwrap();
        let header: Ed25519JwtHeader = serde_json::from_str(&header_json).unwrap();
        assert_eq!(header.alg, "EdDSA");
    }

    #[tokio::test]
    async fn test_oidc_jwks_endpoint() {
        let result = oidc_jwks_ed25519().await;
        assert!(result.is_ok());

        let jwks = result.unwrap().0;
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_oidc_discovery_endpoint() {
        let result = oidc_discovery_ed25519().await;
        assert!(result.is_ok());

        let discovery = result.unwrap().0;
        assert_eq!(discovery["issuer"], "http://localhost:8080/v1");
        assert!(discovery["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("EdDSA".to_string())));
    }
}
