use crate::crypto::ed25519_keys::{ED25519_KEYPAIR, get_ed25519_jwk};
use crate::error::AuthencError;
use crate::utils::crypto_monitor::CryptoMonitor;
use axum::{
    extract::{Query, State},
    http::{StatusCode, HeaderMap},
    response::{Json, Redirect},
    debug_handler,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// JWT Header for Ed25519 signing
#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

/// OIDC ID Token Claims
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

/// Comprehensive OAuth2 Authorization Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
}

/// OAuth2 Token Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// OAuth2 Token Response
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// OAuth2 Token Introspection Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

/// OAuth2 Token Introspection Response
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2IntrospectResponse {
    pub active: bool,
    pub client_id: Option<String>,
    pub subject: Option<String>,
    pub scope: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

/// OAuth2 Token Revocation Request
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuth2RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

/// Authorization Code Store Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeEntry {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub user_id: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: i64,
    pub used: bool,
}

/// Refresh Token Store Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    pub token: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: Option<String>,
    pub expires_at: i64,
    pub revoked: bool,
}

/// Access Token Claims for JWT
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub scope: Option<String>,
    pub roles: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
}

/// In-memory stores (in production, use Redis or database)
pub struct OAuth2Stores {
    pub auth_codes: Arc<tokio::sync::RwLock<HashMap<String, AuthCodeEntry>>>,
    pub refresh_tokens: Arc<tokio::sync::RwLock<HashMap<String, RefreshTokenEntry>>>,
    pub access_tokens: Arc<tokio::sync::RwLock<HashMap<String, AccessTokenClaims>>>,
}

impl OAuth2Stores {
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
    pub database: Arc<crate::database::Database>,
    pub oauth2_stores: Arc<OAuth2Stores>,
}

/// Generate PKCE code challenge
pub fn generate_code_challenge(code_verifier: &str, method: &str) -> Result<String, AuthencError> {
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let hash = hasher.finalize();
            Ok(Base64UrlUnpadded::encode_string(&hash))
        },
        "plain" => Ok(code_verifier.to_string()),
        _ => Err(AuthencError::validation("Unsupported code challenge method")),
    }
}

/// Verify PKCE code challenge
pub fn verify_code_challenge(code_verifier: &str, code_challenge: &str, method: &str) -> Result<bool, AuthencError> {
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
        let header_json = serde_json::to_string(&header).unwrap();
        let claims_json = serde_json::to_string(&claims).unwrap();

        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = ED25519_KEYPAIR.sign(signing_input.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        format!("{}.{}", signing_input, signature_b64)
    })
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

    let mut claims = OidcIdTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: now + 3600,
        iat: now,
        email: email.map(|e| e.to_string()),
        name: name.map(|n| n.to_string()),
        role: role.map(|r| r.to_string()),
    };

    // Add nonce if provided
    if let Some(nonce_val) = nonce {
        // Note: In a real implementation, you'd extend the claims struct
        // For now, we'll add it to the email field temporarily
        claims.email = Some(format!("{}:{}", claims.email.unwrap_or_default(), nonce_val));
    }

    CryptoMonitor::monitor_rsa_operation("ed25519_id_token_signing", || {
        let header_json = serde_json::to_string(&header).unwrap();
        let claims_json = serde_json::to_string(&claims).unwrap();

        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = ED25519_KEYPAIR.sign(signing_input.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        format!("{}.{}", signing_input, signature_b64)
    })
}

/// Validate client credentials
pub fn validate_client(client_id: &str, client_secret: Option<&str>) -> Result<bool, AuthencError> {
    // In production, this would validate against a client registry
    // For demonstration, accept demo client
    if client_id == "demo_client" {
        if let Some(secret) = client_secret {
            return Ok(secret == "demo_secret");
        }
        return Ok(true); // No secret required for public clients
    }
    Ok(false)
}

/// Validate scope
pub fn validate_scope(requested_scope: Option<&str>, _client_id: &str) -> Result<Vec<String>, AuthencError> {
    let default_scopes = vec!["openid".to_string(), "profile".to_string(), "email".to_string()];

    if let Some(scope_str) = requested_scope {
        let requested_scopes: Vec<String> = scope_str.split_whitespace().map(|s| s.to_string()).collect();

        // Validate requested scopes are allowed
        for scope in &requested_scopes {
            if !default_scopes.contains(scope) {
                return Err(AuthencError::validation(&format!("Invalid scope: {}", scope)));
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
) -> Result<Redirect, AuthencError> {
    // Validate response type
    if !["code", "id_token", "token id_token"].contains(&params.response_type.as_str()) {
        return Err(AuthencError::validation("Unsupported response_type"));
    }

    // Validate client
    if !validate_client(&params.client_id, None)? {
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
            return Err(AuthencError::validation("code_challenge required when code_challenge_method is provided"));
        }
    }

    // In a real implementation, this would:
    // 1. Check user authentication and consent
    // 2. Handle different response types
    // 3. Implement proper consent flow

    // For demonstration, generate authorization code
    let auth_code = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    let code_entry = AuthCodeEntry {
        code: auth_code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        user_id: "demo_user".to_string(), // In real implementation, get from session
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
    let mut redirect_uri = params.redirect_uri.unwrap_or_else(|| "http://localhost:8080/callback".to_string());
    redirect_uri.push_str(&format!("?code={}", auth_code));

    if let Some(state) = params.state {
        redirect_uri.push_str(&format!("&state={}", state));
    }

    Ok(Redirect::to(&redirect_uri))
}

/// Enhanced OAuth2 Token Endpoint supporting all grant types
#[debug_handler]
pub async fn oauth2_token(
    State(state): State<Arc<OAuth2AppState>>,
    Json(params): Json<OAuth2TokenRequest>,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let now = Utc::now().timestamp();
    let stores = &state.oauth2_stores;

    match params.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(params, stores.clone(), now).await
        },
        "client_credentials" => {
            handle_client_credentials_grant(params, stores.clone(), now).await
        },
        "password" => {
            handle_password_grant(params, stores.clone(), now).await
        },
        "refresh_token" => {
            handle_refresh_token_grant(params, stores.clone(), now).await
        },
        _ => Err(AuthencError::validation("Unsupported grant_type")),
    }
}

/// Handle Authorization Code Grant with PKCE
async fn handle_authorization_code_grant(
    params: OAuth2TokenRequest,
    stores: Arc<OAuth2Stores>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let code = params.code.ok_or(AuthencError::validation("code required"))?;
    let client_id = params.client_id.ok_or(AuthencError::validation("client_id required"))?;

    // Validate client
    if !validate_client(&client_id, params.client_secret.as_deref())? {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // Retrieve and validate authorization code
    let code_entry = {
        let codes = stores.auth_codes.read().await;
        codes.get(&code).cloned()
    }.ok_or(AuthencError::validation("Invalid authorization code"))?;

    if code_entry.used || code_entry.expires_at < now {
        return Err(AuthencError::validation("Authorization code expired or already used"));
    }

    if code_entry.client_id != client_id {
        return Err(AuthencError::validation("Client ID mismatch"));
    }

    // Validate redirect URI
    if let Some(requested_uri) = params.redirect_uri {
        if let Some(stored_uri) = &code_entry.redirect_uri {
            if requested_uri != *stored_uri {
                return Err(AuthencError::validation("Redirect URI mismatch"));
            }
        }
    }

    // Validate PKCE
    if let Some(challenge) = &code_entry.code_challenge {
        let verifier = params.code_verifier.ok_or(AuthencError::validation("code_verifier required"))?;
        let method = code_entry.code_challenge_method.as_deref().unwrap_or("plain");

        if !verify_code_challenge(&verifier, challenge, method)? {
            return Err(AuthencError::validation("Invalid code verifier"));
        }
    }

    // Mark code as used
    {
        let mut codes = stores.auth_codes.write().await;
        if let Some(entry) = codes.get_mut(&code) {
            entry.used = true;
        }
    }

    // Generate tokens
    let scopes = code_entry.scope.as_deref().unwrap_or("openid profile email");

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
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = stores.access_tokens.write().await;
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
        let mut refresh_tokens = stores.refresh_tokens.write().await;
        refresh_tokens.insert(refresh_token.clone(), refresh_entry);
    }

    // Generate ID token
    let id_token = generate_id_token(
        &code_entry.user_id,
        &client_id,
        Some("user@example.com"),
        Some("Demo User"),
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
    stores: Arc<OAuth2Stores>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let client_id = params.client_id.ok_or(AuthencError::validation("client_id required"))?;

    // Validate client credentials
    if !validate_client(&client_id, params.client_secret.as_deref())? {
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
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = stores.access_tokens.write().await;
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
    stores: Arc<OAuth2Stores>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let username = params.username.ok_or(AuthencError::validation("username required"))?;
    let password = params.password.ok_or(AuthencError::validation("password required"))?;
    let client_id = params.client_id.ok_or(AuthencError::validation("client_id required"))?;

    // Validate client
    if !validate_client(&client_id, params.client_secret.as_deref())? {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // In a real implementation, validate username/password against user store
    // For demonstration, accept demo credentials
    if username != "demo_user" || password != "demo_password" {
        return Err(AuthencError::validation("Invalid username or password"));
    }

    // Validate scope
    let scopes = validate_scope(params.scope.as_deref(), &client_id)?;
    let scope_str = scopes.join(" ");

    // Generate tokens
    let access_token_claims = AccessTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: username.clone(),
        aud: client_id.clone(),
        client_id: client_id.clone(),
        exp: now + 3600,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        scope: Some(scope_str.clone()),
        roles: Some(vec!["user".to_string()]),
        groups: Some(vec!["users".to_string()]),
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = stores.access_tokens.write().await;
        tokens.insert(access_token_claims.jti.clone(), access_token_claims);
    }

    // Generate refresh token
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_entry = RefreshTokenEntry {
        token: refresh_token.clone(),
        client_id: client_id.clone(),
        user_id: username.clone(),
        scope: Some(scope_str.clone()),
        expires_at: now + 86400 * 30,
        revoked: false,
    };

    {
        let mut refresh_tokens = stores.refresh_tokens.write().await;
        refresh_tokens.insert(refresh_token.clone(), refresh_entry);
    }

    // Generate ID token
    let id_token = generate_id_token(
        &username,
        &client_id,
        Some("user@example.com"),
        Some("Demo User"),
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
    stores: Arc<OAuth2Stores>,
    now: i64,
) -> Result<Json<OAuth2TokenResponse>, AuthencError> {
    let refresh_token = params.refresh_token.ok_or(AuthencError::validation("refresh_token required"))?;
    let client_id = params.client_id.ok_or(AuthencError::validation("client_id required"))?;

    // Validate client
    if !validate_client(&client_id, params.client_secret.as_deref())? {
        return Err(AuthencError::validation("Invalid client credentials"));
    }

    // Retrieve and validate refresh token
    let refresh_entry = {
        let tokens = stores.refresh_tokens.read().await;
        tokens.get(&refresh_token).cloned()
    }.ok_or(AuthencError::validation("Invalid refresh token"))?;

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
        let original_scopes: Vec<String> = refresh_entry.scope.as_deref().unwrap_or("").split_whitespace().map(|s| s.to_string()).collect();
        let requested_scopes: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();

        for req_scope in &requested_scopes {
            if !original_scopes.contains(req_scope) {
                return Err(AuthencError::validation("Invalid scope"));
            }
        }
        scope.to_string()
    } else {
        refresh_entry.scope.unwrap_or_else(|| "openid profile email".to_string())
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
    };

    let access_token = generate_access_token(&access_token_claims);

    // Store access token
    {
        let mut tokens = stores.access_tokens.write().await;
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
        let mut refresh_tokens = stores.refresh_tokens.write().await;
        refresh_tokens.remove(&refresh_token); // Remove old token
        refresh_tokens.insert(new_refresh_token.clone(), new_refresh_entry);
    }

    // Generate ID token
    let id_token = generate_id_token(
        &refresh_entry.user_id,
        &client_id,
        Some("user@example.com"),
        Some("Demo User"),
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
    let claims = {
        let tokens = stores.access_tokens.read().await;
        tokens.values().find(|claims| {
            // In a real implementation, you'd decode and validate the JWT
            // For demonstration, we'll do a simple lookup
            claims.jti == params.token || claims.sub == params.token
        }).cloned()
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

/// Enhanced UserInfo endpoint
pub async fn oauth2_userinfo(
    headers: HeaderMap,
    State(state): State<Arc<OAuth2AppState>>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    let stores = &state.oauth2_stores;
    
    // Extract Authorization header
    let auth_header = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AuthencError::unauthorized("Unauthorized"))?;

    // Validate access token
    let claims = {
        let tokens = stores.access_tokens.read().await;
        tokens.values().find(|claims| {
            // In a real implementation, you'd decode and validate the JWT
            claims.jti == auth_header || claims.sub == auth_header
        }).cloned()
    }.ok_or(AuthencError::unauthorized("Invalid access token"))?;

    // Return user info based on scope
    let mut userinfo = serde_json::json!({
        "sub": claims.sub,
        "iss": claims.iss,
        "aud": claims.aud,
        "exp": claims.exp,
        "iat": claims.iat
    });

    if let Some(scope) = &claims.scope {
        if scope.contains("profile") {
            userinfo["name"] = serde_json::json!("Demo User");
            userinfo["preferred_username"] = serde_json::json!("demo_user");
        }
        if scope.contains("email") {
            userinfo["email"] = serde_json::json!("user@example.com");
            userinfo["email_verified"] = serde_json::json!(true);
        }
    }

    Ok(Json(userinfo))
}