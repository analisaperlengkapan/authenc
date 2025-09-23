use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, put, delete},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::models::user::{UpdateUserRequest, UserResponse};
use crate::models::session::SessionResponse;
use crate::services::stores::user_store::UserStoreTrait;
use crate::services::session_store::SessionStore;
use crate::services::stores::user_store::UserStore;

/// Create account management routes for user self-service
pub fn create_account_routes() -> Router<(
    Arc<UserStore>,
    Arc<SessionStore>,
)> {
    Router::new()
        .route("/account", get(get_account_profile))
        .route("/account", put(update_account_profile))
        .route("/account/sessions", get(get_account_sessions))
        .route("/account/sessions/{session_id}", delete(revoke_account_session))
}

/// Get current user's account profile
pub async fn get_account_profile(
    State((user_store, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
    )>,
) -> Result<Json<UserResponse>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    let user = user_store
        .get_user(current_user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    Ok(Json(user.into()))
}

/// Update current user's account profile
pub async fn update_account_profile(
    State((user_store, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
    )>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<StatusCode, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    user_store
        .update_user(current_user_id, request)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get current user's active sessions
pub async fn get_account_sessions(
    State((_, session_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
    )>,
) -> Result<Json<Vec<SessionResponse>>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    let sessions = session_store
        .get_user_sessions(current_user_id)
        .await?;

    let response = sessions
        .into_iter()
        .map(|s| s.into())
        .collect();

    Ok(Json(response))
}

/// Revoke a specific session
pub async fn revoke_account_session(
    State((_, session_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
    )>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    // Verify the session belongs to the current user
    let session = session_store
        .get_session(session_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Session not found"))?;

    if session.user_id != current_user_id {
        return Err(AuthencError::forbidden("Cannot revoke session belonging to another user"));
    }

    session_store
        .delete_session(session_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
