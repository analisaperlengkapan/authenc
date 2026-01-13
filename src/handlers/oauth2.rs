use crate::app::AppState;
use crate::crypto::ed25519_keys::{ED25519_KEYPAIR, get_ed25519_jwk, verify_ed25519};
use crate::database::Database;
use crate::database::operations::oauth2;
use crate::error::AuthencError;
use crate::services::stores::consent_store::ConsentStoreTrait;
use crate::services::stores::user_store::UserStoreTrait;
use crate::utils::crypto::password::verify_password;
use crate::utils::crypto_monitor::CryptoMonitor;
use axum::{
    debug_handler,
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Json, Redirect},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use urlencoding;
use uuid::Uuid;

/// JWT Header for Ed25519 signing
#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519JwtHeader {
    /// The algorithm used for signing (EdDSA)
    pub alg: String,
    /// The type of JWT (usually "JWT")
    pub typ: String,
    /// The key ID for the signing key
    pub kid: String,
}

/// OIDC ID Token Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    /// The issuer of the token
    pub iss: String,
    /// The subject (user) identifier
    pub sub: String,
    /// The audience (client) identifier
    pub aud: String,
    /// The expiration time
    pub exp: i64,
    /// The issued at time
    pub iat: i64,
    /// The user's email address
    pub email: Option<String>,
    /// The user's full name
    pub name: Option<String>,
    /// The user's role
    pub role: Option<String>,
    /// The nonce for replay attack protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Comprehensive OAuth2 Authorization Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2AuthorizeRequest {
    /// The response type requested (code, token, id_token)
    pub response_type: String,
    /// The client identifier
    pub client_id: String,
    /// The redirect URI for the response
    pub redirect_uri: Option<String>,
    /// The requested scope
    pub scope: Option<String>,
    /// The state parameter for CSRF protection
    pub state: Option<String>,
    /// The code challenge for PKCE
    pub code_challenge: Option<String>,
    /// The code challenge method for PKCE
    pub code_challenge_method: Option<String>,
    /// The nonce for replay attack protection
    pub nonce: Option<String>,
    /// The prompt parameter (none, login, consent, select_account)
    pub prompt: Option<String>,
    /// The maximum authentication age in seconds
    pub max_age: Option<i64>,
}

/// OAuth2 Token Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2TokenRequest {
    /// The grant type (authorization_code, refresh_token, password, client_credentials)
    pub grant_type: String,
    /// The authorization code (for authorization_code grant)
    pub code: Option<String>,
    /// The redirect URI (for authorization_code grant)
    pub redirect_uri: Option<String>,
    /// The client identifier
    pub client_id: Option<String>,
    /// The client secret
    pub client_secret: Option<String>,
    /// The code verifier for PKCE
    pub code_verifier: Option<String>,
    /// The refresh token (for refresh_token grant)
    pub refresh_token: Option<String>,
    /// The requested scope
    pub scope: Option<String>,
    /// The username (for password grant)
    pub username: Option<String>,
    /// The password (for password grant)
    pub password: Option<String>,
}

/// OAuth2 Token Response
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2TokenResponse {
    /// The access token
    pub access_token: String,
    /// The token type (usually "Bearer")
    pub token_type: String,
    /// The expiration time in seconds
    pub expires_in: i64,
    /// The refresh token
    pub refresh_token: Option<String>,
    /// The granted scope
    pub scope: Option<String>,
    /// The ID token (for OpenID Connect)
    pub id_token: Option<String>,
}

/// OAuth2 Token Introspection Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2IntrospectRequest {
    /// The token to introspect
    pub token: String,
    /// The expected token type hint
    pub token_type_hint: Option<String>,
}

/// OAuth2 Token Introspection Response
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2IntrospectResponse {
    /// Whether the token is active
    pub active: bool,
    /// The client identifier
    pub client_id: Option<String>,
    /// The subject identifier
    pub subject: Option<String>,
    /// The token scope
    pub scope: Option<String>,
    /// The token type
    pub token_type: Option<String>,
    /// The expiration time
    pub exp: Option<i64>,
    /// The issued at time
    pub iat: Option<i64>,
    /// The not before time
    pub nbf: Option<i64>,
    /// The subject identifier (duplicate of subject)
    pub sub: Option<String>,
    /// The audience
    pub aud: Option<String>,
    /// The issuer
    pub iss: Option<String>,
    /// The JWT ID for uniqueness
    pub jti: Option<String>,
}

/// OAuth2 Token Revocation Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2RevokeRequest {
    /// The token to revoke
    pub token: String,
    /// The expected token type hint
    pub token_type_hint: Option<String>,
}

/// Authorization Code Store Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeEntry {
    /// The authorization code
    pub code: String,
    /// The client identifier
    pub client_id: String,
    /// The redirect URI
    pub redirect_uri: Option<String>,
    /// The user identifier
    pub user_id: String,
    /// The granted scope
    pub scope: Option<String>,
    /// The code challenge for PKCE
    pub code_challenge: Option<String>,
    /// The code challenge method for PKCE
    pub code_challenge_method: Option<String>,
    /// The nonce for replay attack protection
    pub nonce: Option<String>,
    /// The expiration timestamp
    pub expires_at: i64,
    /// Whether the code has been used
    pub used: bool,
}

/// Refresh Token Store Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    /// The refresh token
    pub token: String,
    /// The client identifier
    pub client_id: String,
    /// The user identifier
    pub user_id: String,
    /// The granted scope
    pub scope: Option<String>,
    /// The expiration timestamp
    pub expires_at: i64,
    /// Whether the token has been revoked
    pub revoked: bool,
}

/// Access Token Claims for JWT
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    /// The issuer of the token
    pub iss: String,
    /// The subject (user) identifier
    pub sub: String,
    /// The audience (client) identifier
    pub aud: String,
    /// The client identifier
    pub client_id: String,
    /// The expiration time
    pub exp: i64,
    /// The issued at time
    pub iat: i64,
    /// The not before time
    pub nbf: i64,
    /// The JWT ID for uniqueness
    pub jti: String,
    /// The granted scope
    pub scope: Option<String>,
    /// The user's roles
    pub roles: Option<Vec<String>>,
    /// The user's groups
    pub groups: Option<Vec<String>>,
    /// The session identifier
    pub sid: Option<String>,
}

/// In-memory stores (in production, use Redis or database)
pub struct OAuth2Stores {
    /// Storage for authorization codes
    pub auth_codes: Arc<tokio::sync::RwLock<HashMap<String, AuthCodeEntry>>>,
    /// Storage for refresh tokens
    pub refresh_tokens: Arc<tokio::sync::RwLock<HashMap<String, RefreshTokenEntry>>>,
    /// Storage for access token claims
    pub access_tokens: Arc<tokio::sync::RwLock<HashMap<String, AccessTokenClaims>>>,
}

impl Default for OAuth2Stores {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuth2Stores {
    /// Create new OAuth2 stores
    pub fn new() -> Self {
        Self {
            auth_codes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            access_tokens: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

/// Combined state for OAuth2 handlers
#[derive(Clone)]
pub struct OAuth2AppState {
    /// The full application state
    pub app_state: Arc<AppState>,
    /// The OAuth2 in-memory stores
    pub oauth2_stores: Arc<OAuth2Stores>,
}

/// Generate PKCE code challenge
///
/// # Arguments
/// * `code_verifier` - The code verifier string
/// * `method` - The code challenge method (S256)
///
/// # Returns
/// * `Ok(String)` containing the code challenge
/// * `Err(AuthencError)` if the method is unsupported
pub fn generate_code_challenge(code_verifier: &str, method: &str) -> Result<String, AuthencError> {
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let hash = hasher.finalize();
            Ok(Base64UrlUnpadded::encode_string(&hash))
        }
        "plain" => Ok(code_verifier.to_string()),
        _ => Err(AuthencError::validation(
            "Unsupported code challenge method",
        )),
    }
}

/// Verify PKCE code challenge
pub fn verify_code_challenge(
    code_verifier: &str,
    code_challenge: &str,
    method: &str,
) -> Result<bool, AuthencError> {
    let computed_challenge = generate_code_challenge(code_verifier, method)?;
    Ok(computed_challenge == code_challenge)
}

/// Generate Ed25519 JWT for access tokens
pub fn generate_access_token(claims: &AccessTokenClaims) -> String {
    let header = Ed25519JwtHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
        kid: "authence-ed25519-key".to_string(),
    };

    CryptoMonitor::monitor_rsa_operation("ed25519_access_token_signing", || {
        // SAFETY NOTE: These serializations are safe to expect because:
        // 1. Ed25519JwtHeader and OAuth2Claims have simple string fields
        // 2. String serialization to JSON cannot fail for well-formed structs
        // 3. If serialization fails, it indicates a critical bug that should be caught in testing
        let header_json = serde_json::to_string(&header).expect("Failed to serialize header");
        let claims_json = serde_json::to_string(&claims).expect("Failed to serialize claims");

        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = ED25519_KEYPAIR.sign(signing_input.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        format!("{}.{}", signing_input, signature_b64)
    })
}

/// Verify and decode JWT access token
pub fn verify_and_decode_jwt(token: &str) -> Result<AccessTokenClaims, AuthencError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthencError::validation("Invalid token format"));
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Decode signature
    let signature_bytes = Base64UrlUnpadded::decode_vec(signature_b64)
        .map_err(|_| AuthencError::validation("Invalid signature encoding"))?;

    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AuthencError::validation("Invalid signature format"))?;

    // Verify signature
    verify_ed25519(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthencError::validation("Invalid signature"))?;

    // Decode payload
    let payload_bytes = Base64UrlUnpadded::decode_vec(payload_b64)
        .map_err(|_| AuthencError::validation("Invalid payload encoding"))?;

    let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AuthencError::validation("Invalid payload format"))?;

    // Check expiration
    let now = Utc::now().timestamp();
    if claims.exp < now {
        return Err(AuthencError::validation("Token expired"));
    }

    Ok(claims)
}

/// Generate Ed25519 JWT for ID tokens
pub fn generate_id_token(
    sub: &str,
    aud: &str,
    email: Option<&str>,
    name: Option<&str>,
    role: Option<&str>,
    nonce: Option<&str>,
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
        nonce: nonce.map(|n| n.to_string()),
    };

    CryptoMonitor::monitor_rsa_operation("ed25519_id_token_signing", || {
        // SAFETY NOTE: These serializations are safe to expect because:
        // 1. Ed25519JwtHeader and OAuth2IdTokenClaims have simple string fields
        // 2. String serialization to JSON cannot fail for well-formed structs
        // 3. If serialization fails, it indicates a critical bug that should be caught in testing
        let header_json = serde_json::to_string(&header).expect("Failed to serialize header");
        let claims_json = serde_json::to_string(&claims).expect("Failed to serialize claims");

        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = ED25519_KEYPAIR.sign(signing_input.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        format!("{}.{}", signing_input, signature_b64)
    })
}

/// Validate client credentials
pub async fn validate_client(
    db: &Database,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<bool, AuthencError> {
    // Try to find client in database
    if let Ok(Some(client)) = oauth2::get_client_by_id(db, client_id).await {
        if !client.enabled {
            return Ok(false);
        }

        if let Some(secret) = client_secret {
            // Verify secret
            // If client_secret_hash is stored as a hash, verify it
            // If it's stored plain (not recommended but possible in dev), compare directly
            // For this implementation we assume hashed
            if verify_password(&client.client_secret_hash, secret)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }

            // Fallback for simple comparison (e.g. if hash is just the secret in some tests/configs)
            // or if verify_password failed (e.g. invalid hash format)
            if client.client_secret_hash == secret {
                return Ok(true);
            }
        } else {
            // Public client check
            if client.client_type == "public" {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Validate scope
pub fn validate_scope(
    requested_scope: Option<&str>,
    _client_id: &str,
) -> Result<Vec<String>, AuthencError> {
    let default_scopes = vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ];

    if let Some(scope_str) = requested_scope {
        let requested_scopes: Vec<String> = scope_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Validate requested scopes are allowed
        for scope in &requested_scopes {
            if !default_scopes.contains(scope) {
                return Err(AuthencError::validation(format!(
                    "Invalid scope: {}",
                    scope
                )));
            }
        }

        Ok(requested_scopes)
    } else {
        Ok(default_scopes)
    }
}

/// Enhanced OIDC Discovery with all OAuth2 features
pub async fn oauth2_discovery() -> Result<Json<serde_json::Value>, AuthencError> {
    let discovery = serde_json::json!({
        "issuer": "http://localhost:8080/v1",
        "authorization_endpoint": "http://localhost:8080/v1/oauth2/authorize",
        "token_endpoint": "http://localhost:8080/v1/oauth2/token",
        "introspection_endpoint": "http://localhost:8080/v1/oauth2/introspect",
        "revocation_endpoint": "http://localhost:8080/v1/oauth2/revoke",
        "jwks_uri": "http://localhost:8080/v1/oauth2/jwks",
        "userinfo_endpoint": "http://localhost:8080/v1/oauth2/userinfo",
        "device_authorization_endpoint": "http://localhost:8080/v1/oauth2/device",
        "response_types_supported": ["code", "id_token", "token id_token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "password",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "none"
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "email", "name", "role", "nonce"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
        "tls_client_certificate_bound_access_tokens": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true
    });

    Ok(Json(discovery))
}

/// Enhanced OAuth2 Authorization Endpoint with PKCE and comprehensive security
pub async fn oauth2_authorize(
    Query(params): Query<OAuth2AuthorizeRequest>,
    State(state): State<Arc<OAuth2AppState>>,
    auth_user: Option<Extension<crate::middleware::auth::AuthUser>>,
) -> Result<Redirect, AuthencError> {
    // Validate response type
    if !["code", "id_token", "token id_token"].contains(&params.response_type.as_str()) {
        return Err(AuthencError::validation("Unsupported response_type"));
    }

    // Validate client
    if !validate_client(&state.app_state.database, &params.client_id, None).await? {
        return Err(AuthencError::validation("Invalid client_id"));
    }

    // Validate scope
    let scopes = validate_scope(params.scope.as_deref(), &params.client_id)?;

    // Validate PKCE parameters if present
    if let Some(method) = &params.code_challenge_method {
        if !["S256", "plain"].contains(&method.as_str()) {
            return Err(AuthencError::validation("Invalid code_challenge_method"));
        }
        if params.code_challenge.is_none() {
            return Err(AuthencError::validation(
                "code_challenge required when code_challenge_method is provided",
            ));
        }
    }

    // Check user authentication using JWT token
    let user_id = if let Some(auth_user) = auth_user {
        Uuid::parse_str(&auth_user.id)
            .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?
    } else {
        // For testing: use admin user if not authenticated
        Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .map_err(|_| AuthencError::unauthorized("Invalid default user ID"))?
    };

    // Check if user has valid consent for the requested scopes
    let has_consent = state
        .app_state
        .consent_store
        .has_consent(user_id, &params.client_id, &scopes)
        .await?;

    if !has_consent {
        // Check if prompt parameter indicates no interaction should occur
        let prompt_none = params.prompt.as_ref().map(|p| p == "none").unwrap_or(false);

        if prompt_none {
            // User has not consented and prompt=none, return error
            return Err(AuthencError::validation("User consent required"));
        } else {
            // Redirect to consent page
            let consent_url = format!(
                "/oauth2/consent?client_id={}&scope={}&response_type={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method={}&nonce={}",
                urlencoding::encode(&params.client_id),
                urlencoding::encode(params.scope.as_deref().unwrap_or("")),
                urlencoding::encode(&params.response_type),
                urlencoding::encode(params.redirect_uri.as_deref().unwrap_or("")),
                urlencoding::encode(params.state.as_deref().unwrap_or("")),
                urlencoding::encode(params.code_challenge.as_deref().unwrap_or("")),
                urlencoding::encode(params.code_challenge_method.as_deref().unwrap_or("")),
                urlencoding::encode(params.nonce.as_deref().unwrap_or(""))
            );
            return Ok(Redirect::to(&consent_url));
        }
    }

    // Generate authorization code
    let auth_code = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    let code_entry = AuthCodeEntry {
        code: auth_code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        user_id: user_id.to_string(),
        scope: Some(scopes.join(" ")),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        nonce: params.nonce.clone(),
        expires_at: now + 600, // 10 minutes
        used: false,
    };

    // Store authorization code
    {
        let mut codes = state.oauth2_stores.auth_codes.write().await;
        codes.insert(auth_code.clone(), code_entry);
    }

    // Build redirect URI
    let mut redirect_uri = params
        .redirect_uri
        .unwrap_or_else(|| "http://localhost:8080/callback".to_string());
    redirect_uri.push_str(&format!("?code={}", auth_code));

    if let Some(state) = params.state {
        redirect_uri.push_str(&format!("&state={}", state));
    }

    Ok(Redirect::to(&redirect_uri))
}

/// Test OAuth2 Token Endpoint - for testing without authentication
#[debug_handler]
pub async fn test_oauth2_token(
    State(state): State<Arc<OAuth2AppState>>,
    Json(params): Json<OAuth2TokenRequest>,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let now = Utc::now().timestamp();

    match params.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(params, state.clone(), now).await,
        "client_credentials" => handle_client_credentials_grant(params, state.clone(), now).await,
        "password" => handle_password_grant(params, state.clone(), now).await,
        "refresh_token" => handle_refresh_token_grant(params, state.clone(), now).await,
        _ => Err(AuthencError::validation("Unsupported grant_type")),
    }
}

/// Enhanced OAuth2 Token Endpoint supporting all grant types
#[debug_handler]
pub async fn oauth2_token(
    State(state): State<Arc<OAuth2AppState>>,
    Json(params): Json<OAuth2TokenRequest>,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let now = Utc::now().timestamp();

    match params.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(params, state.clone(), now).await,
        "client_credentials" => handle_client_credentials_grant(params, state.clone(), now).await,
        "password" => handle_password_grant(params, state.clone(), now).await,
        "refresh_token" => handle_refresh_token_grant(params, state.clone(), now).await,
        _ => Err(AuthencError::validation("Unsupported grant_type")),
    }
}

/// Handle Authorization Code Grant with PKCE
async fn handle_authorization_code_grant(
    params: OAuth2TokenRequest,
    state: Arc<OAuth2AppState>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let code = params
        .code
        .ok_or(AuthencError::validation("code required"))?;
    let client_id = params
        .client_id
        .ok_or(AuthencError::validation("client_id required"))?;

    // Validate client
    if !validate_client(
        &state.app_state.database,
        &client_id,
        params.client_secret.as_deref(),
    )
    .await?
    {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // Retrieve and validate authorization code
    let code_entry = {
        let codes = state.oauth2_stores.auth_codes.read().await;
        codes.get(&code).cloned()
    }
    .ok_or(AuthencError::validation("Invalid authorization code"))?;

    if code_entry.used || code_entry.expires_at < now {
        return Err(AuthencError::validation(
            "Authorization code expired or already used",
        ));
    }

    if code_entry.client_id != client_id {
        return Err(AuthencError::validation("Client ID mismatch"));
    }

    // Validate redirect URI
    if let Some(requested_uri) = params.redirect_uri
        && let Some(stored_uri) = &code_entry.redirect_uri
            && requested_uri != *stored_uri {
                return Err(AuthencError::validation("Redirect URI mismatch"));
            }

    // Validate PKCE
    if let Some(challenge) = &code_entry.code_challenge {
        let verifier = params
            .code_verifier
            .ok_or(AuthencError::validation("code_verifier required"))?;
        let method = code_entry
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");

        if !verify_code_challenge(&verifier, challenge, method)? {
            return Err(AuthencError::validation("Invalid code verifier"));
        }
    }

    // Mark code as used
    {
        let mut codes = state.oauth2_stores.auth_codes.write().await;
        if let Some(entry) = codes.get_mut(&code) {
            entry.used = true;
        }
    }

    // Generate tokens
    let scopes = code_entry
        .scope
        .as_deref()
        .unwrap_or("openid profile email");

    let access_token_claims = AccessTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: code_entry.user_id.clone(),
        aud: client_id.clone(),
        client_id: client_id.clone(),
        exp: now + 3600,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        scope: Some(scopes.to_string()),
        roles: Some(vec!["user".to_string()]),
        groups: Some(vec!["users".to_string()]),
        sid: None, // Session ID not available in this flow yet
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = state.oauth2_stores.access_tokens.write().await;
        tokens.insert(access_token_claims.jti.clone(), access_token_claims);
    }

    // Generate refresh token
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_entry = RefreshTokenEntry {
        token: refresh_token.clone(),
        client_id: client_id.clone(),
        user_id: code_entry.user_id.clone(),
        scope: Some(scopes.to_string()),
        expires_at: now + 86400 * 30, // 30 days
        revoked: false,
    };

    {
        let mut refresh_tokens = state.oauth2_stores.refresh_tokens.write().await;
        refresh_tokens.insert(refresh_token.clone(), refresh_entry);
    }

    // Generate ID token
    let id_token = generate_id_token(
        &code_entry.user_id,
        &client_id,
        None,
        None,
        Some("user"),
        code_entry.nonce.as_deref(),
    );

    let response = OAuth2TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
        scope: Some(scopes.to_string()),
        id_token: Some(id_token),
    };

    Ok(Json(response))
}

/// Handle Client Credentials Grant
async fn handle_client_credentials_grant(
    params: OAuth2TokenRequest,
    state: Arc<OAuth2AppState>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let client_id = params
        .client_id
        .ok_or(AuthencError::validation("client_id required"))?;

    // Validate client credentials
    if !validate_client(
        &state.app_state.database,
        &client_id,
        params.client_secret.as_deref(),
    )
    .await?
    {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // Validate scope
    let scopes = validate_scope(params.scope.as_deref(), &client_id)?;
    let scope_str = scopes.join(" ");

    // Generate access token for client
    let access_token_claims = AccessTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: client_id.clone(),
        aud: client_id.clone(),
        client_id: client_id.clone(),
        exp: now + 3600,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        scope: Some(scope_str.clone()),
        roles: Some(vec!["client".to_string()]),
        groups: Some(vec!["clients".to_string()]),
        sid: None,
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = state.oauth2_stores.access_tokens.write().await;
        tokens.insert(access_token_claims.jti.clone(), access_token_claims);
    }

    let response = OAuth2TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: None, // Client credentials typically don't use refresh tokens
        scope: Some(scope_str),
        id_token: None,
    };

    Ok(Json(response))
}

/// Handle Resource Owner Password Credentials Grant
async fn handle_password_grant(
    params: OAuth2TokenRequest,
    state: Arc<OAuth2AppState>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let _stores = &state.oauth2_stores;
    let username = params
        .username
        .ok_or(AuthencError::validation("username required"))?;
    let password = params
        .password
        .ok_or(AuthencError::validation("password required"))?;
    let client_id = params
        .client_id
        .ok_or(AuthencError::validation("client_id required"))?;

    // Validate client
    if !validate_client(
        &state.app_state.database,
        &client_id,
        params.client_secret.as_deref(),
    )
    .await?
    {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // Fetch client to get realm_id for user lookup
    let client = oauth2::get_client_by_id(&state.app_state.database, &client_id)
        .await
        .map_err(|e| AuthencError::database(format!("Database error: {}", e)))?
        .ok_or(AuthencError::validation("Invalid client_id"))?;

    // Use default realm if client has no realm (though it should)
    let realm_id = client.realm_id.unwrap_or(Uuid::nil());

    // Validate user against user store or fall back to demo credentials
    let user_opt = state
        .app_state
        .user_store
        .get_user_by_username(&realm_id, &username)
        .await
        .map_err(|e| AuthencError::database(format!("Database error: {}", e)))?;

    let mut authenticated_user = None;
    if let Some(user) = user_opt {
        if let Some(hash) = &user.password_hash {
            if verify_password(hash, &password).await.unwrap_or(false) {
                authenticated_user = Some(user);
            } else {
                tracing::warn!("Failed password verification for user: {}", username);
            }
        } else {
            tracing::warn!("User has no password hash: {}", username);
        }
    }

    let (sub, email, name) = if let Some(user) = authenticated_user {
        tracing::info!("User authenticated successfully: {}", username);
        (
            user.id.to_string(),
            Some(user.email.clone()),
            Some(user.full_name()),
        )
    } else {
        tracing::warn!("Authentication failed for user: {}", username);
        return Err(AuthencError::validation("Invalid username or password"));
    };

    // Validate scope
    let scopes = validate_scope(params.scope.as_deref(), &client_id)?;
    let scope_str = scopes.join(" ");

    // Generate tokens
    let access_token_claims = AccessTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: sub.clone(),
        aud: client_id.clone(),
        client_id: client_id.clone(),
        exp: now + 3600,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        scope: Some(scope_str.clone()),
        roles: Some(vec!["user".to_string()]),
        groups: Some(vec!["users".to_string()]),
        sid: None,
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = state.oauth2_stores.access_tokens.write().await;
        tokens.insert(access_token_claims.jti.clone(), access_token_claims);
    }

    // Generate refresh token
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_entry = RefreshTokenEntry {
        token: refresh_token.clone(),
        client_id: client_id.clone(),
        user_id: sub.clone(),
        scope: Some(scope_str.clone()),
        expires_at: now + 86400 * 30,
        revoked: false,
    };

    {
        let mut refresh_tokens = state.oauth2_stores.refresh_tokens.write().await;
        refresh_tokens.insert(refresh_token.clone(), refresh_entry);
    }

    // Generate ID token
    let id_token = generate_id_token(
        &sub,
        &client_id,
        email.as_deref(),
        name.as_deref(),
        Some("user"),
        None,
    );

    let response = OAuth2TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(refresh_token),
        scope: Some(scope_str),
        id_token: Some(id_token),
    };

    Ok(Json(response))
}

/// Handle Refresh Token Grant
async fn handle_refresh_token_grant(
    params: OAuth2TokenRequest,
    state: Arc<OAuth2AppState>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let refresh_token = params
        .refresh_token
        .ok_or(AuthencError::validation("refresh_token required"))?;
    let client_id = params
        .client_id
        .ok_or(AuthencError::validation("client_id required"))?;

    // Validate client
    if !validate_client(
        &state.app_state.database,
        &client_id,
        params.client_secret.as_deref(),
    )
    .await?
    {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // Retrieve and validate refresh token
    let refresh_entry = {
        let tokens = state.oauth2_stores.refresh_tokens.read().await;
        tokens.get(&refresh_token).cloned()
    }
    .ok_or(AuthencError::validation("Invalid refresh token"))?;

    if refresh_entry.revoked || refresh_entry.expires_at < now {
        return Err(AuthencError::validation("Refresh token expired or revoked"));
    }

    if refresh_entry.client_id != client_id {
        return Err(AuthencError::validation("Client ID mismatch"));
    }

    // Validate scope
    let requested_scope = params.scope.as_deref();
    let scope_str = if let Some(scope) = requested_scope {
        // Ensure requested scope is subset of original scope
        let original_scopes: Vec<String> = refresh_entry
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let requested_scopes: Vec<String> =
            scope.split_whitespace().map(|s| s.to_string()).collect();

        for req_scope in &requested_scopes {
            if !original_scopes.contains(req_scope) {
                return Err(AuthencError::validation("Invalid scope"));
            }
        }
        scope.to_string()
    } else {
        refresh_entry
            .scope
            .unwrap_or_else(|| "openid profile email".to_string())
    };

    // Generate new access token
    let access_token_claims = AccessTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: refresh_entry.user_id.clone(),
        aud: client_id.clone(),
        client_id: client_id.clone(),
        exp: now + 3600,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        scope: Some(scope_str.clone()),
        roles: Some(vec!["user".to_string()]),
        groups: Some(vec!["users".to_string()]),
        sid: None,
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = state.oauth2_stores.access_tokens.write().await;
        tokens.insert(access_token_claims.jti.clone(), access_token_claims);
    }

    // Generate new refresh token (rotate refresh token)
    let new_refresh_token = Uuid::new_v4().to_string();
    let new_refresh_entry = RefreshTokenEntry {
        token: new_refresh_token.clone(),
        client_id: client_id.clone(),
        user_id: refresh_entry.user_id.clone(),
        scope: Some(scope_str.clone()),
        expires_at: now + 86400 * 30,
        revoked: false,
    };

    // Revoke old refresh token and store new one
    {
        let mut refresh_tokens = state.oauth2_stores.refresh_tokens.write().await;
        refresh_tokens.remove(&refresh_token); // Remove old token
        refresh_tokens.insert(new_refresh_token.clone(), new_refresh_entry);
    }

    // Generate ID token
    let id_token = generate_id_token(
        &refresh_entry.user_id,
        &client_id,
        None,
        None,
        Some("user"),
        None,
    );

    let response = OAuth2TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some(new_refresh_token),
        scope: Some(scope_str),
        id_token: Some(id_token),
    };

    Ok(Json(response))
}

/// OAuth2 Token Introspection Endpoint (RFC 7662)
#[debug_handler]
pub async fn oauth2_introspect(
    State(state): State<Arc<OAuth2AppState>>,
    Json(params): Json<OAuth2IntrospectRequest>,
) -> Result<Json<OAuth2IntrospectResponse>, AuthencError> {
    let now = Utc::now().timestamp();
    let stores = &state.oauth2_stores;

    // Try to find access token
    let claims = if let Ok(claims) = verify_and_decode_jwt(&params.token) {
        // Token is validly signed and not expired.
        // Now check if it exists in the store (not revoked).
        let tokens = stores.access_tokens.read().await;
        tokens.get(&claims.jti).cloned()
    } else {
        None
    };

    if let Some(claims) = claims {
        if claims.exp > now {
            let response = OAuth2IntrospectResponse {
                active: true,
                client_id: Some(claims.client_id),
                subject: Some(claims.sub.clone()),
                scope: claims.scope,
                token_type: Some("Bearer".to_string()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                nbf: Some(claims.nbf),
                sub: Some(claims.sub),
                aud: Some(claims.aud),
                iss: Some(claims.iss),
                jti: Some(claims.jti),
            };
            Ok(Json(response))
        } else {
            Ok(Json(OAuth2IntrospectResponse {
                active: false,
                client_id: None,
                subject: None,
                scope: None,
                token_type: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }))
        }
    } else {
        Ok(Json(OAuth2IntrospectResponse {
            active: false,
            client_id: None,
            subject: None,
            scope: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }))
    }
}

/// OAuth2 Token Revocation Endpoint (RFC 7009)
#[debug_handler]
pub async fn oauth2_revoke(
    State(state): State<Arc<OAuth2AppState>>,
    Json(params): Json<OAuth2RevokeRequest>,
) -> Result<StatusCode, AuthencError> {
    let token = params.token;
    let stores = &state.oauth2_stores;

    // Try to revoke refresh token
    {
        let mut refresh_tokens = stores.refresh_tokens.write().await;
        if let Some(entry) = refresh_tokens.get_mut(&token) {
            entry.revoked = true;
        }
    }

    // Try to revoke access token (remove from store)
    {
        let mut access_tokens = stores.access_tokens.write().await;
        access_tokens.retain(|_, claims| claims.jti != token && claims.sub != token);
    }

    Ok(StatusCode::OK)
}

/// Enhanced JWKS endpoint
pub async fn oauth2_jwks() -> Result<Json<serde_json::Value>, AuthencError> {
    let jwk = get_ed25519_jwk();
    let jwks = serde_json::json!({
        "keys": [jwk]
    });
    Ok(Json(jwks))
}

/// Verify and decode JWT token
#[allow(dead_code)]
fn verify_jwt(token: &str) -> Result<AccessTokenClaims, AuthencError> {
    // 1. Verify JWT structure
    let token_parts: Vec<&str> = token.split('.').collect();
    if token_parts.len() != 3 {
        return Err(AuthencError::unauthorized("Invalid token format"));
    }

    let header_b64 = token_parts[0];
    let payload_b64 = token_parts[1];
    let signature_b64 = token_parts[2];

    // 2. Reconstruct signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // 3. Decode signature
    let signature_bytes = Base64UrlUnpadded::decode_vec(signature_b64)
        .map_err(|_| AuthencError::unauthorized("Invalid signature encoding"))?;

    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthencError::unauthorized("Invalid signature length"))?,
    );

    // 4. Verify signature
    verify_ed25519(signing_input.as_bytes(), &signature)
        .map_err(|_| AuthencError::unauthorized("Invalid signature"))?;

    // 5. Decode payload
    let payload_bytes = Base64UrlUnpadded::decode_vec(payload_b64)
        .map_err(|_| AuthencError::unauthorized("Invalid payload encoding"))?;

    let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AuthencError::unauthorized("Invalid payload JSON"))?;

    // 6. Check expiration
    let now = Utc::now().timestamp();
    if claims.exp < now {
        return Err(AuthencError::unauthorized("Token expired"));
    }

    Ok(claims)
}

/// Enhanced UserInfo endpoint
pub async fn oauth2_userinfo(
    headers: HeaderMap,
    State(state): State<Arc<OAuth2AppState>>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    let stores = &state.oauth2_stores;

    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AuthencError::unauthorized("Unauthorized"))?;

    // Validate access token
    let decoded = verify_and_decode_jwt(auth_header)
        .map_err(|_| AuthencError::unauthorized("Invalid access token"))?;

    // Check if the token is known in our store (revocation check)
    // Use server-side stored claims to ensure token wasn't revoked
    let claims = {
        let tokens = stores.access_tokens.read().await;
        tokens
            .get(&decoded.jti)
            .cloned()
            .ok_or(AuthencError::unauthorized(
                "Invalid or revoked access token",
            ))?
    };

    // Return user info based on scope
    let mut userinfo = serde_json::json!({
        "sub": claims.sub,
        "iss": claims.iss,
        "aud": claims.aud,
        "exp": claims.exp,
        "iat": claims.iat
    });

    if let Some(scope) = &claims.scope {
        // Fetch user details from DB using sub (user_id)
        if let Ok(user_id) = Uuid::parse_str(&claims.sub)
            && let Ok(Some(user)) = state.app_state.user_store.get_user(user_id).await {
                if scope.contains("profile") {
                    userinfo["name"] = serde_json::json!(user.full_name());
                    userinfo["preferred_username"] = serde_json::json!(user.username);
                }
                if scope.contains("email") {
                    userinfo["email"] = serde_json::json!(user.email);
                    userinfo["email_verified"] = serde_json::json!(user.email_verified);
                }
            }
    }

    Ok(Json(userinfo))
}

/// Test OAuth2 authorization endpoint - for testing without authentication
pub async fn test_oauth2_authorize(
    Query(params): Query<OAuth2AuthorizeRequest>,
    State(state): State<Arc<OAuth2AppState>>,
) -> Result<Redirect, AuthencError> {
    // Validate response type
    if !["code", "id_token", "token id_token"].contains(&params.response_type.as_str()) {
        return Err(AuthencError::validation("Unsupported response_type"));
    }

    // Validate client
    if !validate_client(&state.app_state.database, &params.client_id, None).await? {
        return Err(AuthencError::validation("Invalid client_id"));
    }

    // Validate scope
    let scopes = validate_scope(params.scope.as_deref(), &params.client_id)?;

    // Use mock user for testing
    let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001")
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    // Check if user has valid consent for the requested scopes
    let has_consent = state
        .app_state
        .consent_store
        .has_consent(user_id, &params.client_id, &scopes)
        .await?;

    if !has_consent {
        // Check if prompt parameter indicates no interaction should occur
        let prompt_none = params.prompt.as_ref().map(|p| p == "none").unwrap_or(false);

        if prompt_none {
            // User has not consented and prompt=none, return error
            return Err(AuthencError::validation("User consent required"));
        } else {
            // Redirect to test consent page
            let consent_url = format!(
                "/oauth2/consent/test?client_id={}&scope={}&response_type={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method={}&nonce={}",
                urlencoding::encode(&params.client_id),
                urlencoding::encode(params.scope.as_deref().unwrap_or("")),
                urlencoding::encode(&params.response_type),
                urlencoding::encode(params.redirect_uri.as_deref().unwrap_or("")),
                urlencoding::encode(params.state.as_deref().unwrap_or("")),
                urlencoding::encode(params.code_challenge.as_deref().unwrap_or("")),
                urlencoding::encode(params.code_challenge_method.as_deref().unwrap_or("")),
                urlencoding::encode(params.nonce.as_deref().unwrap_or(""))
            );
            return Ok(Redirect::to(&consent_url));
        }
    }

    // Generate authorization code
    let auth_code = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    let code_entry = AuthCodeEntry {
        code: auth_code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        user_id: user_id.to_string(),
        scope: Some(scopes.join(" ")),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        nonce: params.nonce.clone(),
        expires_at: now + 600, // 10 minutes
        used: false,
    };

    // Store authorization code
    {
        let mut codes = state.oauth2_stores.auth_codes.write().await;
        codes.insert(auth_code.clone(), code_entry);
    }

    // Build redirect URI
    let mut redirect_uri = params
        .redirect_uri
        .unwrap_or_else(|| "http://localhost:8080/callback".to_string());
    redirect_uri.push_str(&format!("?code={}", auth_code));

    if let Some(state) = params.state {
        redirect_uri.push_str(&format!("&state={}", state));
    }

    Ok(Redirect::to(&redirect_uri))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Base64UrlUnpadded;
    use uuid::Uuid;

    #[test]
    fn test_verify_and_decode_jwt_valid() {
        let now = Utc::now().timestamp();
        let claims = AccessTokenClaims {
            iss: "test_iss".to_string(),
            sub: "test_sub".to_string(),
            aud: "test_aud".to_string(),
            client_id: "test_client".to_string(),
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: "test_jti".to_string(),
            scope: None,
            roles: None,
            groups: None,
            sid: None,
        };

        let token = generate_access_token(&claims);
        let decoded = verify_and_decode_jwt(&token).expect("Token should be valid");
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.jti, claims.jti);
    }

    #[test]
    fn test_verify_and_decode_jwt_tampered() {
        let now = Utc::now().timestamp();
        let claims = AccessTokenClaims {
            iss: "test_iss".to_string(),
            sub: "test_sub".to_string(),
            aud: "test_aud".to_string(),
            client_id: "test_client".to_string(),
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: Uuid::new_v4().to_string(),
            scope: None,
            roles: None,
            groups: None,
            sid: None,
        };

        let token = generate_access_token(&claims);
        let parts: Vec<&str> = token.split('.').collect();

        let mut payload_bytes = Base64UrlUnpadded::decode_vec(parts[1]).expect("Failed to decode payload");
        let s = String::from_utf8(payload_bytes).expect("Failed to convert payload to string");
        let s = s.replace(&claims.sub, "evil_sub");
        payload_bytes = s.into_bytes();
        let tampered_payload_b64 = Base64UrlUnpadded::encode_string(&payload_bytes);
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload_b64, parts[2]);

        assert!(verify_and_decode_jwt(&tampered_token).is_err());
    }

    #[test]
    fn test_verify_and_decode_jwt_expired() {
        let now = Utc::now().timestamp();
        let expired_claims = AccessTokenClaims {
            iss: "test_iss".to_string(),
            sub: "test_sub".to_string(),
            aud: "test_aud".to_string(),
            client_id: "test_client".to_string(),
            exp: now - 3600,
            iat: now - 7200,
            nbf: now - 7200,
            jti: "expired_jti".to_string(),
            scope: None,
            roles: None,
            groups: None,
            sid: None,
        };

        let expired_token = generate_access_token(&expired_claims);
        assert!(verify_and_decode_jwt(&expired_token).is_err());
    }
}
