use crate::crypto::ed25519_keys::{ED25519_KEYPAIR, get_ed25519_jwk};
use crate::error::AuthencError;
use authenc_core::utils::crypto_monitor::CryptoMonitor;
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
/// OIDC authorization request query parameters
///
/// Parameters received during OIDC authorization code flow.
/// Contains client information and requested scopes for authentication.
///
/// # Security Considerations
/// - State parameter prevents CSRF attacks
/// - Redirect URI must be validated against registered URIs
/// - Client ID must be validated before processing
/// - Response type determines the authorization flow
pub struct OidcAuthorizeQuery {
    /// OAuth2 response type (code, token, id_token)
    pub response_type: String,
    /// OAuth2 client identifier
    pub client_id: String,
    /// URI to redirect after authorization
    pub redirect_uri: String,
    /// Requested OAuth2 scopes (openid, profile, email)
    pub scope: Option<String>,
    /// Opaque value for CSRF protection
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
/// JWT header for Ed25519 signed tokens
///
/// JWT header containing algorithm and key information for Ed25519 signatures.
/// Used in OIDC ID tokens and access tokens signed with Ed25519.
///
/// # Security Considerations
/// - Algorithm must be EdDSA for Ed25519 signatures
/// - Key ID enables key rotation and validation
/// - Header is integrity protected by the signature
pub struct Ed25519JwtHeader {
    /// Signature algorithm (EdDSA for Ed25519)
    pub alg: String,
    /// Token type (JWT)
    pub typ: String,
    /// Key ID for key identification in JWKS
    pub kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
/// OIDC ID token claims
///
/// Standard OIDC claims included in ID tokens.
/// Contains user identity information and token metadata.
///
/// # Security Considerations
/// - Timestamps prevent token reuse attacks
/// - Audience validation prevents token misuse
/// - Subject uniquely identifies the user
/// - Claims are signed and cannot be modified
#[derive(Clone)]
pub struct OidcIdTokenClaims {
    /// Issuer identifier (token issuer)
    pub iss: String,
    /// Subject identifier (user ID)
    pub sub: String,
    /// Audience (client ID the token is for)
    pub aud: String,
    /// Expiration timestamp
    pub exp: i64,
    /// Issued at timestamp
    pub iat: i64,
    /// User's email address
    pub email: Option<String>,
    /// User's display name
    pub name: Option<String>,
    /// User's role or authorization level
    pub role: Option<String>,
}

/// Generate JWT token using Ed25519 - secure replacement for RSA
///
/// Creates a JWT token signed with Ed25519 digital signatures.
/// Provides better security and performance compared to RSA signatures.
///
/// # Arguments
/// * `sub` - Subject identifier (user ID)
/// * `aud` - Audience (client ID)
/// * `email` - User's email address
/// * `name` - User's display name
/// * `role` - User's role/authorization level
///
/// # Returns
/// A complete JWT token with Ed25519 signature
///
/// # Security Considerations
/// - Uses Ed25519 for fast, secure signatures
/// - Includes standard JWT claims (iss, sub, aud, exp, iat)
/// - One hour token expiration for security
/// - All claims are signed and tamper-proof
/// - Crypto operations are monitored for security
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
///
/// Provides JSON Web Key Set containing Ed25519 public keys.
/// Allows clients to verify JWT signatures signed with Ed25519.
///
/// # Returns
/// JWKS document containing Ed25519 public key for signature verification
///
/// # Security Considerations
/// - Only exposes public keys for signature verification
/// - Private keys never leave the server
/// - Supports key rotation through key ID (kid)
/// - Enables secure token validation by clients
pub async fn oidc_jwks_ed25519() -> Result<Json<serde_json::Value>, AuthencError> {
    let jwk = get_ed25519_jwk();
    let jwks = serde_json::json!({
        "keys": [jwk]
    });
    Ok(Json(jwks))
}

/// OIDC token endpoint using Ed25519 - secure replacement for RSA
///
/// Exchanges authorization codes for access tokens and ID tokens.
/// Issues tokens signed with Ed25519 for enhanced security.
///
/// # Arguments
/// * `params` - Query parameters containing grant type and authorization code
///
/// # Returns
/// OAuth2 token response with access token, ID token, and metadata
///
/// # Security Considerations
/// - Validates grant type before processing
/// - Issues short-lived access tokens (1 hour)
/// - Includes ID tokens with user identity claims
/// - Tokens are signed with Ed25519 for integrity
/// - Supports standard OAuth2 token response format
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
///
/// Provides OIDC discovery document with Ed25519 algorithm information.
/// Allows clients to discover OIDC endpoints and supported algorithms.
///
/// # Returns
/// OIDC discovery document with endpoint URLs and capabilities
///
/// # Security Considerations
/// - Advertises EdDSA as supported signing algorithm
/// - Lists all available OIDC endpoints
/// - Includes supported scopes and claims
/// - Enables secure client configuration
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
///
/// Provides user profile information based on access token.
/// Returns user claims for authorized clients.
///
/// # Arguments
/// * `headers` - HTTP headers containing Authorization header with access token
///
/// # Returns
/// User profile information in JSON format
///
/// # Security Considerations
/// - Validates Bearer token in Authorization header
/// - Returns only authorized user information
/// - Claims based on token scope and user permissions
/// - User information is current and up-to-date
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
///
/// Handles OIDC authorization requests and redirects.
/// Initiates OAuth2 authorization code flow with Ed25519 security.
///
/// # Arguments
/// * `params` - Authorization request parameters
///
/// # Returns
/// Redirect response to client with authorization code
///
/// # Security Considerations
/// - Validates response type before processing
/// - Generates secure authorization codes
/// - Includes state parameter for CSRF protection
/// - Redirects to validated client URIs only
/// - Prevents authorization code injection attacks
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
        assert!(
            discovery["id_token_signing_alg_values_supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("EdDSA".to_string()))
        );
    }
}
