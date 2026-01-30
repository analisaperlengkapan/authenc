//! Session management handlers for Axum
//!
//! This module provides endpoints for listing user sessions
//! and handling logout operations.

use crate::services::stores::session_store::SessionStoreTrait;
use crate::utils::crypto::jwt::Claims;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::Serialize;
use std::sync::Arc;

/// Session state for the router
pub struct SessionState {
    /// Session store for managing user sessions
    pub session_store: Arc<dyn SessionStoreTrait>,
    /// JWT secret for token validation
    pub jwt_secret: String,
}

/// Response for session listing
#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    /// List of session tokens
    pub sessions: Vec<String>,
}

/// Response for logout operation
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    /// Whether logout was successful
    pub success: bool,
    /// Message describing the result
    pub message: String,
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

/// Extract Bearer token from Authorization header
fn extract_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// List all sessions for the authenticated user
///
/// GET /sessions
pub async fn list_sessions(
    State(state): State<Arc<SessionState>>,
    headers: HeaderMap,
) -> Result<Json<SessionListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let token = match extract_token(&headers) {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing token".to_string(),
                }),
            ));
        }
    };

    let decoded = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    );

    let user_id = match decoded {
        Ok(data) => data.claims.sub,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid token".to_string(),
                }),
            ));
        }
    };

    let sessions = state.session_store.all_for_user(&user_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Session store error: {}", e),
            }),
        )
    })?;
    Ok(Json(SessionListResponse { sessions }))
}

/// Logout the current session
///
/// POST /logout
pub async fn logout(
    State(state): State<Arc<SessionState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(LogoutResponse {
                    success: false,
                    message: "Missing token".to_string(),
                }),
            );
        }
    };

    match state.session_store.remove(&token) {
        Ok(_) => {
            tracing::info!("Session removed successfully");
            (
                StatusCode::OK,
                Json(LogoutResponse {
                    success: true,
                    message: "Logged out".to_string(),
                }),
            )
        }
        Err(e) => {
            tracing::warn!("Failed to remove session: {}", e);
            (
                StatusCode::OK,
                Json(LogoutResponse {
                    success: true,
                    message: "Logged out (session may have already expired)".to_string(),
                }),
            )
        }
    }
}

/// Create session management routes for the application
pub fn create_session_routes() -> Router<Arc<SessionState>> {
    Router::new()
        .route("/sessions", get(list_sessions))
        .route("/logout", post(logout))
}

/// Helper function to create SessionState from components
impl SessionState {
    /// Create a new SessionState
    pub fn new(session_store: Arc<dyn SessionStoreTrait>, jwt_secret: String) -> Self {
        Self {
            session_store,
            jwt_secret,
        }
    }
}
