//! TOTP verification handlers for Axum
//!
//! This module provides endpoints for verifying TOTP codes
//! during two-factor authentication.

use crate::services::totp_store::TotpStore;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};

/// Request payload for TOTP verification
#[derive(Debug, Deserialize)]
pub struct VerifyTotpRequest {
    /// The TOTP code to verify
    pub code: String,
}

/// Response for TOTP verification
#[derive(Debug, Serialize)]
pub struct VerifyTotpResponse {
    /// Whether the TOTP code is valid
    pub valid: bool,
    /// Optional message describing the result
    pub message: String,
}

/// Verify a TOTP code for a user
///
/// POST /users/{user_id}/totp/verify
pub async fn verify_totp(
    State(totp_store): State<Arc<TotpStore>>,
    Path(user_id): Path<String>,
    Json(req): Json<VerifyTotpRequest>,
) -> impl IntoResponse {
    match totp_store.get_secret(&user_id) {
        Ok(Some(secret)) => {
            // Create TOTP instance with standard parameters
            // SHA1, 6 digits, 1 step skew, 30 second period
            match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.as_bytes().to_vec()) {
                Ok(totp) => {
                    if totp.check_current(&req.code).unwrap_or(false) {
                        tracing::debug!("TOTP verification successful for user: {}", user_id);
                        (
                            StatusCode::OK,
                            Json(VerifyTotpResponse {
                                valid: true,
                                message: "TOTP valid".to_string(),
                            }),
                        )
                    } else {
                        tracing::debug!("TOTP verification failed for user: {}", user_id);
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(VerifyTotpResponse {
                                valid: false,
                                message: "Invalid TOTP code".to_string(),
                            }),
                        )
                    }
                }
                Err(e) => {
                    tracing::error!("TOTP creation error for user {}: {:?}", user_id, e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(VerifyTotpResponse {
                            valid: false,
                            message: "TOTP error".to_string(),
                        }),
                    )
                }
            }
        }
        Ok(None) => {
            tracing::warn!("TOTP not enabled for user: {}", user_id);
            (
                StatusCode::BAD_REQUEST,
                Json(VerifyTotpResponse {
                    valid: false,
                    message: "TOTP not enabled for user".to_string(),
                }),
            )
        }
        Err(e) => {
            tracing::error!("TOTP store error for user {}: {}", user_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(VerifyTotpResponse {
                    valid: false,
                    message: format!("TOTP store error: {}", e),
                }),
            )
        }
    }
}

/// Create TOTP verification routes for the application
pub fn create_totp_verify_routes() -> Router<Arc<TotpStore>> {
    Router::new().route("/users/{user_id}/totp/verify", post(verify_totp))
}
