use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;

/// Request payload for password reset
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    pub realm_id: Option<Uuid>,
}

/// Request payload for completing password reset
#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// Handler for requesting a password reset
pub async fn request_password_reset(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> impl IntoResponse {
    let realm_id = payload.realm_id.unwrap_or_else(Uuid::nil); // Default realm if not provided

    match state
        .password_reset_service
        .request_reset(&payload.email, &realm_id)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "message": "If the email exists, a password reset link has been sent"
            })),
        ),
        Err(e) => {
            tracing::error!("Failed to request password reset: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
        }
    }
}

/// Handler for resetting the password
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    // Basic password validation
    if payload.new_password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Password must be at least 8 characters long" })),
        );
    }

    match state
        .password_reset_service
        .reset_password(&payload.token, &payload.new_password)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Password reset successfully" })),
        ),
        Err(e) => {
            // Log specific error but return generic error to client unless it's a validation error
            tracing::warn!("Password reset failed: {}", e);
            let (status, message) = if e.to_string().contains("Invalid") || e.to_string().contains("expired") {
                (StatusCode::BAD_REQUEST, "Invalid or expired reset token".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            };

            (status, Json(json!({ "error": message })))
        }
    }
}
