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
use authenc_services::services::protocols::webauthn::{
    WebAuthnAuthenticationRequest, WebAuthnRegistrationRequest,
};
use authenc_models::models::webauthn::{
    WebauthnAuthenticationResponse, WebauthnRegistrationResponse,
};

/// Create WebAuthn routes
pub fn create_webauthn_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/webauthn/register/challenge", post(generate_registration_challenge))
        .route("/webauthn/register/verify", post(verify_registration))
        .route("/webauthn/login/challenge", post(generate_authentication_challenge))
        .route("/webauthn/login/verify", post(verify_authentication))
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
    pub realm_id: String,
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
    let parsed_realm = if req.realm_id == "master" {
        Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
    } else {
        Uuid::parse_str(&req.realm_id).map_err(|_| AuthencError::validation("Invalid realm_id"))?
    };

    state.webauthn_service.verify_registration(
        &parsed_realm,
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
    pub realm_id: String,
    pub username: String,
    #[serde(flatten)]
    pub response: WebauthnAuthenticationResponse,
}

/// Verify authentication response
pub async fn verify_authentication(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticationVerificationRequest>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    let parsed_realm = if req.realm_id == "master" {
        Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
    } else {
        Uuid::parse_str(&req.realm_id).map_err(|_| AuthencError::validation("Invalid realm_id"))?
    };

    // Verify via service
    state.webauthn_service.verify_authentication(
        &parsed_realm,
        &req.username,
        req.response
    ).await?;

    // Look up user to generate token
    let user = state.user_store.get_user_by_username(&parsed_realm, &req.username).await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found after passkey auth"))?;

    let token = authenc_crypto::utils::crypto::jwt::generate_jwt(&user.id.to_string())
        .map_err(|_| AuthencError::internal("Token generation failed"))?;

    Ok(Json(serde_json::json!({
        "status": "authenticated",
        "access_token": token
    })))
}
