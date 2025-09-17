use crate::error::AuthencError;
use crate::services::user_store::UserStore;
use crate::utils::crypto::password;
use crate::utils::jwt;
use axum::{
    extract::State,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create authentication routes
pub fn create_auth_routes() -> Router<Arc<UserStore>> {
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
    State(user_store): State<Arc<UserStore>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthencError> {
    let users = user_store.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| {
        u.username == req.username
            && u.realm_id.map(|rid| rid.to_string()) == Some(req.realm.clone())
    }) {
        if let Some(ref password_hash) = user.password_hash {
            if password::verify_password(password_hash, &req.password).unwrap_or(false) {
                let token = jwt::generate_jwt(&user.id.to_string())
                    .map_err(|_| AuthencError::internal("Token generation failed"))?;
                let message = format!("Login successful for user {}", user.username);
                return Ok(Json(LoginResponse {
                    access_token: token,
                    message,
                }));
            }
        }
    }

    Err(AuthencError::unauthorized("Invalid credentials"))
}
