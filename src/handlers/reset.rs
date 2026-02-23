use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> impl IntoResponse {
    // Rate limit check using brute force protector (limits requests by IP)
    let ip = addr.ip().to_string();
    // Use a specific key prefix for password reset requests to separate from login attempts
    let rate_limit_key = format!("pwd_reset_req:{}", ip);

    // Check if blocked
    match state.brute_force_protector.register_attempt(&rate_limit_key) {
        Ok(true) => {
            tracing::warn!("Rate limit exceeded for password reset request from IP: {}", ip);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "Too many requests. Please try again later." })),
            );
        }
        Err(e) => {
            tracing::error!("Rate limiter error: {}", e);
            // Continue securely on error, or fail closed? Failing closed is safer for denial of service prevention on backend resources
        }
        _ => {}
    }

    let realm_id = if let Some(id) = payload.realm_id {
        id
    } else {
        // Default to "master" realm if not provided
        match state.realm_store.get_by_name("master") {
            Some(realm) => realm.id,
            None => {
                tracing::error!("Default 'master' realm not found for password reset");
                // If master realm doesn't exist, use nil UUID which will effectively match no users (fail safe)
                Uuid::nil()
            }
        }
    };

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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    // Rate limit check
    let ip = addr.ip().to_string();
    let rate_limit_key = format!("pwd_reset_sub:{}", ip);

    match state.brute_force_protector.register_attempt(&rate_limit_key) {
        Ok(true) => {
            tracing::warn!("Rate limit exceeded for password reset submission from IP: {}", ip);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "Too many requests. Please try again later." })),
            );
        }
        Err(e) => {
            tracing::error!("Rate limiter error: {}", e);
        }
        _ => {}
    }

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
                (StatusCode::BAD_REQUEST, e.to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            };

            (status, Json(json!({ "error": message })))
        }
    }
}
