use axum::{
    Router,
    extract::State,
    response::Json,
    routing::post,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AuthencError;
use crate::services::webauthn::{
    WebAuthnAuthenticationRequest, WebAuthnRegistrationRequest,
};
use crate::models::webauthn::{
    WebauthnAuthenticationResponse, WebauthnRegistrationResponse,
};

/// Create WebAuthn routes
pub fn create_webauthn_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/webauthn/register/challenge", post(generate_registration_challenge))
        .route("/auth/webauthn/register/verify", post(verify_registration))
        .route("/auth/webauthn/login/challenge", post(generate_authentication_challenge))
        .route("/auth/webauthn/login/verify", post(verify_authentication))
}

/// Generate registration challenge
pub async fn generate_registration_challenge(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebAuthnRegistrationRequest>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    state.webauthn_service.generate_registration_challenge(payload).await
}

/// Wrapper for verification request to include context
#[derive(serde::Deserialize)]
pub struct RegistrationVerificationRequest {
    pub realm_id: Uuid,
    pub username: String,
    #[serde(flatten)]
    pub response: WebauthnRegistrationResponse,
    pub device_id: Option<Uuid>,
}

/// Verify registration response
pub async fn verify_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegistrationVerificationRequest>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    state.webauthn_service.verify_registration(
        &req.realm_id,
        &req.username,
        req.response,
        req.device_id
    ).await
}

/// Generate authentication challenge
pub async fn generate_authentication_challenge(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebAuthnAuthenticationRequest>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    state.webauthn_service.generate_authentication_challenge(payload).await
}

/// Wrapper for authentication verification to include context
#[derive(serde::Deserialize)]
pub struct AuthenticationVerificationRequest {
    pub realm_id: Uuid,
    pub username: String,
    #[serde(flatten)]
    pub response: WebauthnAuthenticationResponse,
}

/// Verify authentication response
pub async fn verify_authentication(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticationVerificationRequest>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    state.webauthn_service.verify_authentication(
        &req.realm_id,
        &req.username,
        req.response
    ).await
}
