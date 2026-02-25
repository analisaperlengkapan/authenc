use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;

/// Request payload for email verification
#[derive(Debug, Deserialize)]
pub struct RequestVerificationRequest {
    /// The email address of the user
    pub email: String,
    /// The ID of the realm the user belongs to (optional, defaults to master)
    pub realm_id: Option<Uuid>,
}

/// Request payload for completing verification
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    /// The verification token received via email
    pub token: String,
}

/// Handler for requesting email verification
pub async fn request_verification(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RequestVerificationRequest>,
) -> impl IntoResponse {
    // Rate limit check
    let ip = addr.ip().to_string();
    let rate_limit_key = format!("email_verify_req:{}", ip);

    // Reuse password reset protector for simplicity
    match state.password_reset_protector.register_attempt(&rate_limit_key) {
        Ok(true) => {
            tracing::warn!("Rate limit exceeded for verification request from IP: {}", ip);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "Too many requests. Please try again later." })),
            );
        }
        Err(e) => {
            tracing::error!("Rate limiter error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            );
        }
        _ => {}
    }

    let realm_id = if let Some(id) = payload.realm_id {
        id
    } else {
        match state.realm_store.get_by_name("master") {
            Some(realm) => realm.id,
            None => Uuid::nil()
        }
    };

    match state
        .email_verification_service
        .request_verification(&payload.email, &realm_id)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "message": "If the email exists and is not verified, a verification link has been sent"
            })),
        ),
        Err(e) => {
            tracing::error!("Failed to request verification: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
        }
    }
}

/// Handler for verifying email
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyEmailRequest>,
) -> impl IntoResponse {
    match state
        .email_verification_service
        .verify_email(&payload.token)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Email verified successfully" })),
        ),
        Err(e) => {
            tracing::warn!("Verification failed: {}", e);
            let (status, message) = if e.to_string().contains("Invalid") || e.to_string().contains("expired") {
                (StatusCode::BAD_REQUEST, "Invalid or expired verification token".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            };

            (status, Json(json!({ "error": message })))
        }
    }
}
