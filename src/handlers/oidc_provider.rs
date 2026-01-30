//! OIDC Provider handlers for Axum
//!
//! This module provides OIDC provider endpoints using Ed25519 signatures.
//! Ed25519 provides better security and performance compared to RSA.
//!
//! NOTE: RSA support has been removed due to security vulnerabilities
//! (RUSTSEC-2023-0071). All JWT signing uses Ed25519 (EdDSA).

use crate::crypto::ed25519_keys::{ED25519_KEYPAIR, get_ed25519_jwk};
use crate::handlers::oidc_ed25519::OidcIdTokenClaims;
use crate::models::audit_log::AuditLog;
use crate::services::stores::oidc_client_store::OidcClientStore;
use crate::services::stores::oidc_code_store::OidcCodeStore;
use crate::services::stores::pg_audit_log_store::PgAuditLogStore;
use crate::services::stores::user_store::UserStore;
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// JWT header for Ed25519 signed tokens
#[derive(Debug, Serialize, Deserialize)]
struct Ed25519JwtHeader {
    /// Algorithm (EdDSA)
    pub alg: String,
    /// Token type (JWT)
    pub typ: String,
    /// Key ID
    pub kid: String,
}

/// Generate an Ed25519 signed ID token
///
/// Creates a JWT token signed with Ed25519 for OIDC ID tokens and access tokens.
fn generate_ed25519_id_token(
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
}

/// Verify an Ed25519 signed JWT and extract claims
///
/// Validates the JWT signature using Ed25519 and returns the claims if valid.
fn verify_ed25519_jwt(token: &str) -> Result<OidcIdTokenClaims, &'static str> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format");
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Verify signature
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature_bytes =
        Base64UrlUnpadded::decode_vec(signature_b64).map_err(|_| "Invalid signature encoding")?;

    if signature_bytes.len() != 64 {
        return Err("Invalid signature length");
    }

    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| "Invalid signature format")?;

    // Get public key from keypair
    let public_key = ED25519_KEYPAIR.verifying_key();
    public_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "Signature verification failed")?;

    // Decode and parse claims
    let claims_bytes =
        Base64UrlUnpadded::decode_vec(payload_b64).map_err(|_| "Invalid payload encoding")?;
    let claims: OidcIdTokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| "Invalid claims format")?;

    // Verify expiration
    let now = Utc::now().timestamp();
    if claims.exp < now {
        return Err("Token expired");
    }

    Ok(claims)
}

/// State for OIDC provider handlers
pub struct OidcProviderState {
    /// Code store for authorization codes
    pub code_store: Arc<OidcCodeStore>,
    /// Client store for client validation
    pub client_store: Arc<OidcClientStore>,
    /// User store for user lookup
    pub user_store: Arc<UserStore>,
    /// Audit log store for logging
    pub audit_log_store: Arc<PgAuditLogStore>,
}

impl OidcProviderState {
    /// Create new OIDC provider state
    pub fn new(
        code_store: Arc<OidcCodeStore>,
        client_store: Arc<OidcClientStore>,
        user_store: Arc<UserStore>,
        audit_log_store: Arc<PgAuditLogStore>,
    ) -> Self {
        Self {
            code_store,
            client_store,
            user_store,
            audit_log_store,
        }
    }
}

/// OIDC Authorization query parameters
#[derive(Debug, Deserialize)]
pub struct OidcAuthorizeQuery {
    /// Client identifier
    pub client_id: String,
    /// Redirect URI after authorization
    pub redirect_uri: String,
    /// Response type (code, id_token, token id_token)
    pub response_type: String,
    /// Requested scopes
    pub scope: Option<String>,
    /// State parameter for CSRF protection
    pub state: Option<String>,
}

/// OIDC Login form data
#[derive(Debug, Deserialize)]
pub struct OidcLoginForm {
    /// Client ID
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Response type
    pub response_type: String,
    /// Scope
    pub scope: Option<String>,
    /// State
    pub state: Option<String>,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

/// OIDC Token request
#[derive(Debug, Deserialize)]
pub struct OidcTokenRequest {
    /// Grant type (authorization_code)
    pub grant_type: String,
    /// Authorization code
    pub code: String,
    /// Redirect URI (must match authorization request)
    pub redirect_uri: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: Option<String>,
}

/// OIDC Token response
#[derive(Debug, Serialize)]
pub struct OidcTokenResponse {
    /// Access token
    pub access_token: String,
    /// ID token
    pub id_token: String,
    /// Token type
    pub token_type: String,
    /// Token expiration in seconds
    pub expires_in: u64,
}

/// OIDC Discovery response
#[derive(Debug, Serialize)]
pub struct OidcDiscoveryResponse {
    /// Issuer URL
    pub issuer: String,
    /// Authorization endpoint
    pub authorization_endpoint: String,
    /// Token endpoint
    pub token_endpoint: String,
    /// Userinfo endpoint
    pub userinfo_endpoint: String,
    /// JWKS URI
    pub jwks_uri: String,
    /// Supported response types
    pub response_types_supported: Vec<String>,
    /// Supported subject types
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes
    pub scopes_supported: Vec<String>,
    /// Supported token endpoint auth methods
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// OIDC Userinfo response
#[derive(Debug, Serialize)]
pub struct OidcUserinfoResponse {
    /// Subject identifier
    pub sub: String,
    /// User email
    pub email: String,
    /// User name
    pub name: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error code
    pub error: String,
    /// Error description
    pub error_description: Option<String>,
}

/// OIDC Discovery endpoint
///
/// GET /.well-known/openid-configuration
pub async fn oidc_discovery() -> Json<OidcDiscoveryResponse> {
    Json(OidcDiscoveryResponse {
        issuer: "http://localhost:8080/v1".to_string(),
        authorization_endpoint: "http://localhost:8080/v1/oidc/authorize".to_string(),
        token_endpoint: "http://localhost:8080/v1/oidc/token".to_string(),
        userinfo_endpoint: "http://localhost:8080/v1/oidc/userinfo".to_string(),
        jwks_uri: "http://localhost:8080/v1/oidc/jwks".to_string(),
        response_types_supported: vec![
            "code".to_string(),
            "id_token".to_string(),
            "token id_token".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string()],
    })
}

/// OIDC Login form
///
/// GET /oidc/login
pub async fn oidc_login(Query(query): Query<OidcAuthorizeQuery>) -> Html<String> {
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>OIDC Login</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                h2 {{ color: #333; }}
                form {{ display: flex; flex-direction: column; gap: 15px; }}
                input {{ padding: 10px; border: 1px solid #ccc; border-radius: 4px; }}
                input[type="submit"] {{ background-color: #007bff; color: white; cursor: pointer; }}
                input[type="submit"]:hover {{ background-color: #0056b3; }}
            </style>
        </head>
        <body>
            <h2>OIDC Login</h2>
            <form method="post" action="/v1/oidc/login">
                <input type="hidden" name="client_id" value="{}"/>
                <input type="hidden" name="redirect_uri" value="{}"/>
                <input type="hidden" name="response_type" value="{}"/>
                <input type="hidden" name="scope" value="{}"/>
                <input type="hidden" name="state" value="{}"/>
                <input name="username" placeholder="Username" required/>
                <input name="password" type="password" placeholder="Password" required/>
                <input type="submit" value="Login"/>
            </form>
        </body>
        </html>
    "#,
        query.client_id,
        query.redirect_uri,
        query.response_type,
        query.scope.clone().unwrap_or_default(),
        query.state.clone().unwrap_or_default()
    );
    Html(html)
}

/// OIDC Login POST handler
///
/// POST /oidc/login
pub async fn oidc_login_post(
    State(state): State<Arc<OidcProviderState>>,
    Form(form): Form<OidcLoginForm>,
) -> Response {
    use crate::services::stores::user_store::UserStoreTrait;
    use crate::utils::crypto::password::verify_password;

    // Verify user credentials
    // Note: OIDC provider in this implementation seems to lack realm context in the form.
    // Assuming default realm or handling lookup differently.
    // For now, we will fetch the client first to get the realm_id if possible,
    // but the login form typically comes after authorization request where client_id is known.
    // In this form post, client_id is present.

    // Lookup client to get realm_id
    let client = match state.client_store.get(&form.client_id).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response(),
    };

    // Use client's realm_id for user lookup
    let user = match state.user_store.get_user_by_username(&client.realm_id, &form.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            let _ = state
                .audit_log_store
                .add_log(&AuditLog {
                    timestamp: Utc::now(),
                    event: "oidc_login".to_string(),
                    user_id: None,
                    client_id: Some(form.client_id.clone()),
                    status: "failure".to_string(),
                    detail: Some("User not found".to_string()),
                })
                .await;
            return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
        }
        Err(e) => {
            tracing::error!("User store error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Authentication error").into_response();
        }
    };

    // Verify password using the password hash from user
    let password_hash = match &user.password_hash {
        Some(hash) => hash,
        None => {
            tracing::error!("User has no password hash");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Authentication error").into_response();
        }
    };
    let password_ok = match verify_password(password_hash, &form.password).await {
        Ok(ok) => ok,
        Err(e) => {
            tracing::error!("Password verification error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Authentication error").into_response();
        }
    };

    if !password_ok {
        let _ = state
            .audit_log_store
            .add_log(&AuditLog {
                timestamp: Utc::now(),
                event: "oidc_login".to_string(),
                user_id: Some(user.id.to_string()),
                client_id: Some(form.client_id.clone()),
                status: "failure".to_string(),
                detail: Some("Invalid password".to_string()),
            })
            .await;
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let user_id = user.id.to_string();

    // Log successful login
    let _ = state
        .audit_log_store
        .add_log(&AuditLog {
            timestamp: Utc::now(),
            event: "oidc_login".to_string(),
            user_id: Some(user_id.clone()),
            client_id: Some(form.client_id.clone()),
            status: "success".to_string(),
            detail: None,
        })
        .await;

    // Build redirect URL to authorization endpoint
    let uri = format!(
        "/v1/oidc/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
        form.client_id,
        form.redirect_uri,
        form.response_type,
        form.scope.unwrap_or_default(),
        form.state.unwrap_or_default()
    );

    // Set cookie and redirect
    Response::builder()
        .status(StatusCode::FOUND)
        .header(
            "Set-Cookie",
            format!("auth_user_id={}; Path=/; HttpOnly; SameSite=Lax", user_id),
        )
        .header("Location", uri)
        .body(axum::body::Body::empty())
        .unwrap()
}

/// OIDC Authorization endpoint
///
/// GET /oidc/authorize
pub async fn oidc_authorize(
    State(state): State<Arc<OidcProviderState>>,
    Query(query): Query<OidcAuthorizeQuery>,
    jar: CookieJar,
) -> Response {
    // Validate client
    let client = match state.client_store.get(&query.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            let _ = state
                .audit_log_store
                .add_log(&AuditLog {
                    timestamp: Utc::now(),
                    event: "oidc_authorize".to_string(),
                    user_id: None,
                    client_id: Some(query.client_id.clone()),
                    status: "failure".to_string(),
                    detail: Some("Client not found".to_string()),
                })
                .await;
            return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response();
        }
        Err(e) => {
            tracing::error!("Client store error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Client store error").into_response();
        }
    };

    // Check if client is enabled and redirect_uri is valid
    if !client.enabled || !client.redirect_uris.contains(&query.redirect_uri) {
        let _ = state
            .audit_log_store
            .add_log(&AuditLog {
                timestamp: Utc::now(),
                event: "oidc_authorize".to_string(),
                user_id: None,
                client_id: Some(query.client_id.clone()),
                status: "failure".to_string(),
                detail: Some("Invalid client_id or redirect_uri".to_string()),
            })
            .await;
        return (StatusCode::BAD_REQUEST, "Invalid client_id or redirect_uri").into_response();
    }

    // Check for user session cookie
    let user_id = match jar.get("auth_user_id") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            // Redirect to login
            let uri = format!(
                "/v1/oidc/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
                query.client_id,
                query.redirect_uri,
                query.response_type,
                query.scope.clone().unwrap_or_default(),
                query.state.clone().unwrap_or_default()
            );
            return Redirect::to(&uri).into_response();
        }
    };

    // Check for consent prompt
    let scope = query.scope.as_deref().unwrap_or("");
    if scope.contains("consent") {
        let html = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Consent Required</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
                    h2 {{ color: #333; }}
                    input[type="submit"] {{ padding: 10px 20px; background-color: #28a745; color: white; border: none; cursor: pointer; border-radius: 4px; }}
                </style>
            </head>
            <body>
                <h2>Consent Required</h2>
                <p>Application <strong>{}</strong> is requesting access to your account.</p>
                <form method="get" action="/v1/oidc/authorize">
                    <input type="hidden" name="client_id" value="{}"/>
                    <input type="hidden" name="redirect_uri" value="{}"/>
                    <input type="hidden" name="response_type" value="{}"/>
                    <input type="hidden" name="scope" value="openid profile email"/>
                    <input type="hidden" name="state" value="{}"/>
                    <input type="submit" value="Approve"/>
                </form>
            </body>
            </html>
        "#,
            client.name,
            query.client_id,
            query.redirect_uri,
            query.response_type,
            query.state.clone().unwrap_or_default()
        );
        return Html(html).into_response();
    }

    // Issue authorization code
    let code = uuid::Uuid::new_v4().to_string();
    let scopes = query
        .scope
        .clone()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_else(|| vec!["openid".to_string()]);

    if let Err(e) = state
        .code_store
        .insert(
            code.clone(),
            query.client_id.clone(),
            user_id.clone(),
            query.redirect_uri.clone(),
            scopes,
            None, // code_challenge
            None, // code_challenge_method
        )
        .await
    {
        tracing::error!("Code store error: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Code store error").into_response();
    }

    // Build redirect URL with code
    let mut redirect_url = format!("{}?code={}", query.redirect_uri, code);
    if let Some(state_param) = &query.state {
        redirect_url.push_str(&format!("&state={}", state_param));
    }

    // Log successful authorization
    let _ = state
        .audit_log_store
        .add_log(&AuditLog {
            timestamp: Utc::now(),
            event: "oidc_authorize".to_string(),
            user_id: Some(user_id),
            client_id: Some(query.client_id.clone()),
            status: "success".to_string(),
            detail: None,
        })
        .await;

    Redirect::to(&redirect_url).into_response()
}

/// OIDC Token endpoint
///
/// POST /oidc/token
pub async fn oidc_token(
    State(state): State<Arc<OidcProviderState>>,
    Form(form): Form<OidcTokenRequest>,
) -> Result<Json<OidcTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    use crate::services::stores::user_store::UserStoreTrait;

    // Validate client
    let client = match state.client_store.get(&form.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) | Err(_) => {
            let _ = state
                .audit_log_store
                .add_log(&AuditLog {
                    timestamp: Utc::now(),
                    event: "oidc_token".to_string(),
                    user_id: None,
                    client_id: Some(form.client_id.clone()),
                    status: "failure".to_string(),
                    detail: Some("Invalid client".to_string()),
                })
                .await;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: Some("Invalid client_id".to_string()),
                }),
            ));
        }
    };

    // Validate redirect_uri
    if !client.redirect_uris.contains(&form.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: Some("Invalid redirect_uri".to_string()),
            }),
        ));
    }

    // Exchange code for tokens
    let user_id = match state.code_store.take(&form.code, &form.client_id).await {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            let _ = state
                .audit_log_store
                .add_log(&AuditLog {
                    timestamp: Utc::now(),
                    event: "oidc_token".to_string(),
                    user_id: None,
                    client_id: Some(form.client_id.clone()),
                    status: "failure".to_string(),
                    detail: Some("Invalid or expired code".to_string()),
                })
                .await;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Invalid or expired code".to_string()),
                }),
            ));
        }
        Err(e) => {
            tracing::error!("Code store error: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: Some("Internal server error".to_string()),
                }),
            ));
        }
    };

    // Get user info
    // For user_id lookup (which is actually a username in the code store logic?),
    // wait, get_user_by_username takes a username string.
    // The variable name is `user_id` but let's check what `code_store.take` returns.
    // In oidc_authorize: `state.code_store.insert(..., user_id.clone(), ...)` where user_id comes from "auth_user_id" cookie.
    // The "auth_user_id" cookie in `oidc_login_post` is set to `user.id.to_string()`, which is a UUID string.
    // So `user_id` here is a UUID string.
    // But `get_user_by_username` expects a username.
    // We should probably use `get_user` (by ID) instead if `user_id` is a UUID.
    // However, looking at `oidc_authorize`, `user_id` is passed to `insert`.
    // Let's assume `user_id` is the user ID (UUID).

    // We need the realm_id. The client belongs to a realm.
    let realm_id = client.realm_id;

    // Try to parse as UUID first to use get_user
    let user = match uuid::Uuid::parse_str(&user_id) {
        Ok(uid) => match state.user_store.get_user(uid).await {
             Ok(Some(u)) => u,
             _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid_grant".to_string(), error_description: Some("User not found".to_string()) }))),
        },
        Err(_) => {
             // Fallback to username lookup if it's not a UUID (legacy/testing?)
             match state.user_store.get_user_by_username(&realm_id, &user_id).await {
                Ok(Some(u)) => u,
                _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid_grant".to_string(), error_description: Some("User not found".to_string()) }))),
             }
        }
    };

    // Generate ID token using Ed25519
    let id_token = generate_ed25519_id_token(
        &user_id,
        &form.client_id,
        Some(&user.email),
        Some(&user.username),
        None,
    );

    // Generate access token using Ed25519
    let access_token = generate_ed25519_id_token(
        &user_id,
        &form.client_id,
        Some(&user.email),
        Some(&user.username),
        Some("access"),
    );

    // Log successful token exchange
    let _ = state
        .audit_log_store
        .add_log(&AuditLog {
            timestamp: Utc::now(),
            event: "oidc_token".to_string(),
            user_id: Some(user_id),
            client_id: Some(form.client_id.clone()),
            status: "success".to_string(),
            detail: None,
        })
        .await;

    Ok(Json(OidcTokenResponse {
        access_token,
        id_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    }))
}

/// OIDC Userinfo endpoint
///
/// GET /oidc/userinfo
pub async fn oidc_userinfo(
    State(state): State<Arc<OidcProviderState>>,
    headers: HeaderMap,
) -> Result<Json<OidcUserinfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract Bearer token
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: Some("Missing or invalid token".to_string()),
                }),
            )
        })?;

    // Validate JWT using Ed25519
    let claims = verify_ed25519_jwt(token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: Some("Token validation failed".to_string()),
            }),
        )
    })?;

    use crate::services::stores::user_store::UserStoreTrait;

    // Get user info
    // claims.sub should be user ID (UUID)
    // We don't have client_id in the token claims explicitly to fetch realm easily here unless we look up user by ID directly (which doesn't require realm_id in UserStoreTrait::get_user).

    let user_id = uuid::Uuid::parse_str(&claims.sub).map_err(|_| {
         (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid_token".to_string(), error_description: Some("Invalid subject claim".to_string()) }))
    })?;

    let user = state
        .user_store
        .get_user(user_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: Some("Database error".to_string()),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: Some("User not found".to_string()),
                }),
            )
        })?;

    // Log successful userinfo request
    let _ = state
        .audit_log_store
        .add_log(&AuditLog {
            timestamp: Utc::now(),
            event: "oidc_userinfo".to_string(),
            user_id: Some(user.id.to_string()),
            client_id: None,
            status: "success".to_string(),
            detail: None,
        })
        .await;

    Ok(Json(OidcUserinfoResponse {
        sub: user.id.to_string(),
        email: user.email,
        name: user.username,
    }))
}

/// OIDC JWKS endpoint
///
/// GET /oidc/jwks
pub async fn oidc_jwks() -> Json<serde_json::Value> {
    // Use Ed25519 JWK instead of RSA
    let jwk = get_ed25519_jwk();
    Json(serde_json::json!({
        "keys": [jwk]
    }))
}

/// Create OIDC provider routes for the application (Ed25519-based)
pub fn create_oidc_provider_routes() -> Router<Arc<OidcProviderState>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oidc/login", get(oidc_login))
        .route("/oidc/login", post(oidc_login_post))
        .route("/oidc/authorize", get(oidc_authorize))
        .route("/oidc/token", post(oidc_token))
        .route("/oidc/userinfo", get(oidc_userinfo))
        .route("/oidc/jwks", get(oidc_jwks))
}
