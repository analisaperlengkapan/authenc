use crate::error::AuthencError;
use crate::services::user_store::UserStore;
use crate::handlers::api::auth_bearer::AuthBearer;
use crate::models::user::User;
use crate::services::stores::user_store::UserStoreTrait;
use crate::utils::crypto::password;
use crate::utils::jwt;
use crate::app::AppState;
use axum::{
    extract::State,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create authentication routes
pub fn create_auth_routes() -> Router<Arc<crate::app::AppState>> {
    Router::new().route("/login", post(login))
}

#[derive(Deserialize)]
/// Request payload for user login
pub struct LoginRequest {
    /// The username for authentication
    pub username: String,
    /// The password for authentication
    pub password: String,
    /// The realm the user belongs to
    pub realm: String,
}

#[derive(Serialize)]
/// Response payload for successful login
pub struct LoginResponse {
    /// JWT access token for authenticated requests
    pub access_token: String,
    /// Success message
    pub message: String,
}

/// Authenticate a user with username and password
pub async fn login(
    State(state): State<Arc<crate::app::AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthencError> {
    // Get user by username from database
    let user = state.user_store
        .get_user_by_username(&req.username)
        .await?
        .ok_or_else(|| AuthencError::unauthorized("Invalid credentials"))?;

    // Check if user belongs to the requested realm
    if user.realm_id.map(|rid| rid.to_string()) != Some(req.realm.clone()) {
        return Err(AuthencError::unauthorized("Invalid credentials"));
    }

    // Verify password
    if let Some(ref password_hash) = user.password_hash {
        if password::verify_password(password_hash, &req.password).unwrap_or(false) {
            let token = jwt::generate_jwt(&user.id.to_string())
                .map_err(|_| AuthencError::internal("Token generation failed"))?;
            let message = format!("Login successful for user {}", user.username);

            // Fire successful login event
            let event = crate::services::events::EventBuilder::new(
                crate::models::events::EventType::Login,
                req.realm.clone(),
            )
            .user_id(user.id.to_string())
            .client_id("api".to_string()) // API login
            .detail("method", "password")
            .build();

            if let Err(e) = state.event_manager.write().await.fire_event(event).await {
                tracing::error!("Failed to fire login event: {}", e);
            }

            return Ok(Json(LoginResponse {
                access_token: token,
                message,
            }));
        }
    }

    // Fire login error event
    let event = crate::services::events::EventBuilder::new(
        crate::models::events::EventType::LoginError,
        req.realm.clone(),
    )
    .user_id(user.id.to_string())
    .client_id("api".to_string())
    .detail("method", "password")
    .detail("reason", "invalid_credentials")
    .build();

    if let Err(e) = state.event_manager.write().await.fire_event(event).await {
        tracing::error!("Failed to fire login error event: {}", e);
    }

    Err(AuthencError::unauthorized("Invalid credentials"))
}
