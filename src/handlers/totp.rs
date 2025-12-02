//! TOTP (Time-based One-Time Password) handlers for Axum
//!
//! This module provides endpoints for enabling and disabling TOTP
//! two-factor authentication for users.

use crate::services::totp_store::TotpStore;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request payload for enabling TOTP
#[derive(Debug, Deserialize)]
pub struct EnableTotpRequest {
    /// The TOTP secret in base32 format
    pub secret: String,
}

/// Response for TOTP operations
#[derive(Debug, Serialize)]
pub struct TotpResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Optional message describing the result
    pub message: String,
}

/// Enable TOTP for a user
///
/// POST /users/{user_id}/totp
pub async fn enable_totp(
    State(totp_store): State<Arc<TotpStore>>,
    Path(user_id): Path<String>,
    Json(req): Json<EnableTotpRequest>,
) -> impl IntoResponse {
    match totp_store.set_secret(&user_id, &req.secret) {
        Ok(_) => {
            tracing::info!("TOTP enabled for user: {}", user_id);
            (
                StatusCode::OK,
                Json(TotpResponse {
                    success: true,
                    message: "TOTP enabled".to_string(),
                }),
            )
        }
        Err(e) => {
            tracing::warn!("Failed to set TOTP secret for user {}: {}", user_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TotpResponse {
                    success: false,
                    message: format!("Failed to enable TOTP: {}", e),
                }),
            )
        }
    }
}

/// Disable TOTP for a user
///
/// DELETE /users/{user_id}/totp
pub async fn disable_totp(
    State(totp_store): State<Arc<TotpStore>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    match totp_store.remove_secret(&user_id) {
        Ok(_) => {
            tracing::info!("TOTP disabled for user: {}", user_id);
            (
                StatusCode::OK,
                Json(TotpResponse {
                    success: true,
                    message: "TOTP disabled".to_string(),
                }),
            )
        }
        Err(e) => {
            tracing::warn!("Failed to remove TOTP secret for user {}: {}", user_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TotpResponse {
                    success: false,
                    message: format!("Failed to disable TOTP: {}", e),
                }),
            )
        }
    }
}

/// Create TOTP routes for the application
pub fn create_totp_routes() -> Router<Arc<TotpStore>> {
    Router::new()
        .route("/users/{user_id}/totp", post(enable_totp))
        .route("/users/{user_id}/totp", delete(disable_totp))
}
