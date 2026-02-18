use crate::app::AppState;
use crate::error::{AuthencError, Result};
use authenc_services::services::webauthn::WebAuthnService;
use axum::{
    extract::{Extension, Query, State},
    response::Json,
    routing::post,
    Router,
};
use std::sync::Arc;

/// Create WebAuthn routes
pub fn create_webauthn_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register/challenge", post(register_challenge))
        .route("/register/verify", post(register_verify))
        .route("/authenticate/challenge", post(authenticate_challenge))
        .route("/authenticate/verify", post(authenticate_verify))
}

/// WebAuthn registration challenge handler
pub async fn register_challenge(
    State(state): State<Arc<AppState>>,
    Json(request): Json<crate::services::webauthn::WebAuthnRegistrationRequest>,
) -> Result<Json<serde_json::Value>> {
    let webauthn_service = WebAuthnService::new(
        state.database.clone(),
        "localhost".to_string(), // In production, use actual domain
        "Authenc Identity".to_string(),
        state.config.security.jwt_secret.clone(),
        state.config.security.webauthn_encryption_key.clone(),
    );

    match webauthn_service
        .generate_registration_challenge(request)
        .await
    {
        Ok(response) => Ok(response),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// WebAuthn registration verification handler
pub async fn register_verify(
    State(state): State<Arc<AppState>>,
    auth_user: Option<Extension<crate::middleware::auth::AuthUser>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(response): Json<crate::models::webauthn::WebauthnRegistrationResponse>,
) -> Result<Json<serde_json::Value>> {
    let username = params
        .get("username")
        .ok_or(AuthencError::validation("Bad request: Missing username"))?;

    let realm_id_str = params
        .get("realm_id")
        .ok_or(AuthencError::validation("Bad request: Missing realm_id"))?;

    let realm_id = uuid::Uuid::parse_str(realm_id_str)
        .map_err(|_| AuthencError::validation("Invalid realm_id format"))?;

    // Try to get device_id from session if authenticated
    let mut device_id = None;
    if let Some(Extension(user)) = auth_user {
        if let Some(sid_str) = &user.session_id {
            if let Ok(session_id) = uuid::Uuid::parse_str(sid_str) {
                // Lookup session to get device_id
                // We access the database directly here via operations
                use authenc_database::database::operations::sessions;
                if let Ok(Some(session_json)) = sessions::get_user_session(&state.database, session_id).await {
                    if let Some(did_str) = session_json.get("device_id").and_then(|v| v.as_str()) {
                         if let Ok(did) = uuid::Uuid::parse_str(did_str) {
                             device_id = Some(did);
                         }
                    }
                }
            }
        }
    }

    let webauthn_service = WebAuthnService::new(
        state.database.clone(),
        "localhost".to_string(),
        "Authenc Identity".to_string(),
        state.config.security.jwt_secret.clone(),
        state.config.security.webauthn_encryption_key.clone(),
    );

    match webauthn_service
        .verify_registration(&realm_id, username, response, device_id)
        .await
    {
        Ok(result) => Ok(result),
        Err(_) => Err(AuthencError::unauthorized("Unauthorized")),
    }
}

/// WebAuthn authentication challenge handler
pub async fn authenticate_challenge(
    State(state): State<Arc<AppState>>,
    Json(request): Json<crate::services::webauthn::WebAuthnAuthenticationRequest>,
) -> Result<Json<serde_json::Value>> {
    let webauthn_service = WebAuthnService::new(
        state.database.clone(),
        "localhost".to_string(),
        "Authenc Identity".to_string(),
        state.config.security.jwt_secret.clone(),
        state.config.security.webauthn_encryption_key.clone(),
    );

    match webauthn_service
        .generate_authentication_challenge(request)
        .await
    {
        Ok(response) => Ok(response),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// WebAuthn authentication verification handler
pub async fn authenticate_verify(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(response): Json<crate::models::webauthn::WebauthnAuthenticationResponse>,
) -> Result<Json<serde_json::Value>> {
    let username = params
        .get("username")
        .ok_or(AuthencError::validation("Bad request: Missing username"))?;

    let realm_id_str = params
        .get("realm_id")
        .ok_or(AuthencError::validation("Bad request: Missing realm_id"))?;

    let realm_id = uuid::Uuid::parse_str(realm_id_str)
        .map_err(|_| AuthencError::validation("Invalid realm_id format"))?;

    let webauthn_service = WebAuthnService::new(
        state.database.clone(),
        "localhost".to_string(),
        "Authenc Identity".to_string(),
        state.config.security.jwt_secret.clone(),
        state.config.security.webauthn_encryption_key.clone(),
    );

    match webauthn_service
        .verify_authentication(&realm_id, username, response)
        .await
    {
        Ok(result) => Ok(result),
        Err(_) => Err(AuthencError::unauthorized("Unauthorized")),
    }
}
