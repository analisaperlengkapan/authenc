use crate::database::Database;
use crate::app::AppState;
use crate::error::{AuthencError, Result};
use crate::services::webauthn::WebAuthnService;
use axum::{
    extract::{Query, State},
    response::Json,
    routing::post,
    Router,
};
use std::sync::Arc;
use crate::app::AppState;

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
    State(db): State<Database>,
    Json(request): Json<crate::services::webauthn::WebAuthnRegistrationRequest>,
) -> Result<Json<serde_json::Value>> {
    let webauthn_service = WebAuthnService::new(
        Arc::new(db),
        "localhost".to_string(), // In production, use actual domain
        "Authenc Identity".to_string(),
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
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(response): Json<crate::models::webauthn::WebauthnRegistrationResponse>,
) -> Result<Json<serde_json::Value>> {
    let username = params
        .get("username")
        .ok_or(AuthencError::validation("Bad request"))?;

    let webauthn_service =
        WebAuthnService::new(Arc::new(db), "localhost".to_string(), "Authenc Identity".to_string());

    match webauthn_service
        .verify_registration(username, response)
        .await
    {
        Ok(result) => Ok(result),
        Err(_) => Err(AuthencError::unauthorized("Unauthorized")),
    }
}

/// WebAuthn authentication challenge handler
pub async fn authenticate_challenge(
    State(db): State<Database>,
    Json(request): Json<crate::services::webauthn::WebAuthnAuthenticationRequest>,
) -> Result<Json<serde_json::Value>> {
    let webauthn_service =
        WebAuthnService::new(Arc::new(db), "localhost".to_string(), "Authenc Identity".to_string());

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
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(response): Json<crate::models::webauthn::WebauthnAuthenticationResponse>,
) -> Result<Json<serde_json::Value>> {
    let username = params
        .get("username")
        .ok_or(AuthencError::validation("Bad request"))?;

    let webauthn_service =
        WebAuthnService::new(Arc::new(db), "localhost".to_string(), "Authenc Identity".to_string());

    match webauthn_service
        .verify_authentication(username, response)
        .await
    {
        Ok(result) => Ok(result),
        Err(_) => Err(AuthencError::unauthorized("Unauthorized")),
    }
}
