//! SSO HTTP Handlers
//!
//! HTTP endpoints for Single Sign-On (SSO) operations.

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Redirect},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::app::AppState;
use crate::services::sso::service::SsoLogoutRequest;
use crate::services::sso::{SsoCallbackRequest, SsoInitiateRequest, SsoProvider};

/// SSO login initiation query parameters
#[derive(Debug, Deserialize)]
pub struct SsoLoginQuery {
    /// Provider type
    pub provider: String,
    /// Client ID
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Realm ID
    pub realm_id: String,
    /// Additional parameters (scope, state, etc.)
    #[serde(flatten)]
    pub parameters: HashMap<String, String>,
}

/// SSO callback query parameters
#[derive(Debug, Deserialize)]
pub struct SsoCallbackQuery {
    /// Authorization code
    pub code: String,
    /// State parameter
    pub state: String,
    /// Provider type
    pub provider: String,
    /// Realm ID
    pub realm_id: String,
}

/// SSO logout query parameters
#[derive(Debug, Deserialize)]
pub struct SsoLogoutQuery {
    /// Post-logout redirect URI
    pub redirect_uri: Option<String>,
}

/// SSO session info response
#[derive(Debug, Serialize)]
pub struct SsoSessionInfo {
    pub session_id: String,
    pub user_id: String,
    pub realm_id: String,
    pub provider: String,
    pub created_at: String,
    pub last_access: String,
    pub client_sessions: Vec<String>,
}

/// Create SSO router with all SSO endpoints
pub fn create_sso_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sso/login", get(initiate_sso_login))
        .route("/sso/callback", get(handle_sso_callback))
        .route("/sso/logout", post(handle_sso_logout))
        .route("/sso/session", get(get_sso_session))
        .route("/sso/sessions", get(get_user_sessions))
}

/// Initiate SSO login
///
/// GET /sso/login?provider=oidc&client_id=xxx&redirect_uri=xxx&realm_id=xxx
async fn initiate_sso_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SsoLoginQuery>,
) -> Result<Redirect, (StatusCode, Json<serde_json::Value>)> {
    // Parse provider
    let provider = match query.provider.as_str() {
        "oidc" => SsoProvider::Oidc,
        "oauth2" => SsoProvider::OAuth2,
        "saml" => SsoProvider::Saml,
        "social" => SsoProvider::Social,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid provider"})),
            ));
        }
    };

    let request = SsoInitiateRequest {
        realm_id: query.realm_id,
        provider,
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        parameters: query.parameters,
    };

    match state.sso_service.initiate_login(request).await {
        Ok(auth_url) => Ok(Redirect::temporary(&auth_url)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to initiate login: {}", e)})),
        )),
    }
}

/// Handle SSO callback
///
/// GET /sso/callback?code=xxx&state=xxx&provider=oidc&realm_id=xxx
async fn handle_sso_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SsoCallbackQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Parse provider
    let provider = match query.provider.as_str() {
        "oidc" => SsoProvider::Oidc,
        "oauth2" => SsoProvider::OAuth2,
        "saml" => SsoProvider::Saml,
        "social" => SsoProvider::Social,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid provider"})),
            ));
        }
    };

    let request = SsoCallbackRequest {
        realm_id: query.realm_id,
        provider,
        code: query.code,
        state: query.state,
        parameters: HashMap::new(),
    };

    match state.sso_service.handle_callback(request).await {
        Ok(response) => {
            // Create redirect response with Set-Cookie header
            let mut headers = HeaderMap::new();
            headers.insert(
                "Set-Cookie",
                response
                    .set_cookie_header
                    .parse()
                    .unwrap_or_else(|_| "".parse().unwrap()),
            );
            headers.insert(
                "Location",
                response
                    .redirect_uri
                    .parse()
                    .unwrap_or_else(|_| "/".parse().unwrap()),
            );

            Ok((StatusCode::FOUND, headers))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to handle callback: {}", e)})),
        )),
    }
}

/// Handle SSO logout (Single Logout)
///
/// POST /sso/logout
async fn handle_sso_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SsoLogoutQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Extract SSO cookie
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cookie_name = state.sso_cookie_manager.cookie_name();
    let cookie_value = extract_cookie_value(cookie_header, cookie_name);

    if let Some(cookie_value) = cookie_value {
        // Validate cookie and get session
        match state.sso_service.validate_session(&cookie_value).await {
            Ok(session) => {
                let logout_request = SsoLogoutRequest {
                    session_id: session.session_id,
                    redirect_uri: query.redirect_uri,
                };

                match state.sso_service.logout(logout_request).await {
                    Ok(redirect_uri) => {
                        // Generate cookie deletion header
                        let delete_cookie =
                            state.sso_cookie_manager.generate_delete_cookie_header();

                        let mut headers = HeaderMap::new();
                        headers.insert(
                            "Set-Cookie",
                            delete_cookie
                                .parse()
                                .unwrap_or_else(|_| "".parse().unwrap()),
                        );
                        headers.insert(
                            "Location",
                            redirect_uri
                                .parse()
                                .unwrap_or_else(|_| "/".parse().unwrap()),
                        );

                        Ok((StatusCode::FOUND, headers))
                    }
                    Err(e) => Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("Failed to logout: {}", e)})),
                    )),
                }
            }
            Err(_) => {
                // Invalid or expired session, still return success with cookie deletion
                let delete_cookie = state.sso_cookie_manager.generate_delete_cookie_header();
                let mut headers = HeaderMap::new();
                headers.insert(
                    "Set-Cookie",
                    delete_cookie
                        .parse()
                        .unwrap_or_else(|_| "".parse().unwrap()),
                );
                headers.insert("Location", "/".parse().unwrap());

                Ok((StatusCode::FOUND, headers))
            }
        }
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "No SSO session found"})),
        ))
    }
}

/// Get current SSO session info
///
/// GET /sso/session
async fn get_sso_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SsoSessionInfo>, (StatusCode, Json<serde_json::Value>)> {
    // Extract SSO cookie
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cookie_name = state.sso_cookie_manager.cookie_name();
    let cookie_value = extract_cookie_value(cookie_header, cookie_name);

    if let Some(cookie_value) = cookie_value {
        match state.sso_service.validate_session(&cookie_value).await {
            Ok(session) => {
                let client_sessions: Vec<String> =
                    session.client_sessions.keys().cloned().collect();

                Ok(Json(SsoSessionInfo {
                    session_id: session.session_id,
                    user_id: session.user_id,
                    realm_id: session.realm_id,
                    provider: session.provider,
                    created_at: session.created_at.to_rfc3339(),
                    last_access: session.last_access.to_rfc3339(),
                    client_sessions,
                }))
            }
            Err(e) => Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": format!("Invalid session: {}", e)})),
            )),
        }
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "No SSO session found"})),
        ))
    }
}

/// Get all active sessions for user
///
/// GET /sso/sessions
async fn get_user_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SsoSessionInfo>>, (StatusCode, Json<serde_json::Value>)> {
    // Extract SSO cookie to get current user
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cookie_name = state.sso_cookie_manager.cookie_name();
    let cookie_value = extract_cookie_value(cookie_header, cookie_name);

    if let Some(cookie_value) = cookie_value {
        match state.sso_service.validate_session(&cookie_value).await {
            Ok(session) => {
                match state
                    .sso_service
                    .get_user_sessions(&session.user_id, &session.realm_id)
                    .await
                {
                    Ok(sessions) => {
                        let session_infos: Vec<SsoSessionInfo> = sessions
                            .into_iter()
                            .map(|s| {
                                let client_sessions: Vec<String> =
                                    s.client_sessions.keys().cloned().collect();

                                SsoSessionInfo {
                                    session_id: s.session_id,
                                    user_id: s.user_id,
                                    realm_id: s.realm_id,
                                    provider: s.provider,
                                    created_at: s.created_at.to_rfc3339(),
                                    last_access: s.last_access.to_rfc3339(),
                                    client_sessions,
                                }
                            })
                            .collect();

                        Ok(Json(session_infos))
                    }
                    Err(e) => Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            serde_json::json!({"error": format!("Failed to get sessions: {}", e)}),
                        ),
                    )),
                }
            }
            Err(e) => Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": format!("Invalid session: {}", e)})),
            )),
        }
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "No SSO session found"})),
        ))
    }
}

/// Helper function to extract cookie value from Cookie header
fn extract_cookie_value<'a>(cookie_header: &'a str, cookie_name: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", cookie_name)) {
            return Some(value.to_string());
        }
    }
    None
}
