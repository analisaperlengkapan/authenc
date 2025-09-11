use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use crate::error::AuthencError;
use serde::{Deserialize, Serialize};
use crate::models::user::User;
use crate::utils::crypto::password;
use crate::utils::jwt;
use crate::services::user_store::UserStore;
use std::sync::Arc;

pub fn create_auth_routes() -> Router<Arc<UserStore>> {
    Router::new()
        .route("/login", post(login))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub realm: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub message: String,
}

pub async fn login(
    State(user_store): State<Arc<UserStore>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthencError> {
    let users = user_store.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.username == req.username && u.realm_id.map(|rid| rid.to_string()) == Some(req.realm.clone())) {
        if let Some(ref password_hash) = user.password_hash {
            if password::verify_password(password_hash, &req.password).unwrap_or(false) {
                let token = jwt::generate_jwt(&user.id.to_string()).map_err(|_| AuthencError::internal("Token generation failed"))?;
                let message = format!("Login successful for user {}", user.username);
                return Ok(Json(LoginResponse { access_token: token, message }));
            }
        }
    }

    Err(AuthencError::unauthorized("Invalid credentials"))
}
