use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete, patch},
    Router,
};
use crate::services::user_store::UserStore;
use crate::models::user::User;
use crate::handlers::api::auth_bearer::AuthBearer;
use crate::utils::crypto::password;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub fn create_user_routes() -> Router<Arc<UserStore>> {
    Router::new()
        .route("/realms/{realm}/users", get(get_users))
        .route("/realms/{realm}/users", post(create_user))
        .route("/realms/{realm}/users/{id}", get(get_user_by_id))
        .route("/realms/{realm}/users/{id}", put(update_user))
        .route("/realms/{realm}/users/{id}", delete(delete_user))
        .route("/realms/{realm}/users/{id}/password", patch(update_password))
}

pub async fn get_users(
    State(store): State<Arc<UserStore>>,
    _auth: AuthBearer,
    Path(realm): Path<String>,
) -> Result<Json<Vec<User>>, StatusCode> {
    let users = store.get_all();
    let filtered: Vec<User> = users.into_iter().filter(|u| u.realm_id.map(|id| id.to_string()) == Some(realm.clone())).collect();
    Ok(Json(filtered))
}

pub async fn get_user_by_id(
    State(store): State<Arc<UserStore>>,
    _auth: AuthBearer,
    Path((realm, id)): Path<(String, String)>,
) -> Result<Json<User>, StatusCode> {
    let users = store.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.id.to_string() == id && u.realm_id.map(|rid| rid.to_string()) == Some(realm.clone())) {
        Ok(Json(user.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub realm_id: Option<Uuid>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub enabled: Option<bool>,
    pub require_password_change: Option<bool>,
}pub async fn create_user(
    State(user_store): State<Arc<UserStore>>,
    AuthBearer(_auth): AuthBearer,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<User>, StatusCode> {
    // Hash the password
    let password_hash = password::hash_password(&request.password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create new user
    let user = User {
        id: Uuid::new_v4(),
        username: request.username,
        email: request.email,
        email_verified: false,
        first_name: request.first_name,
        last_name: request.last_name,
        phone_number: request.phone_number,
        phone_verified: false,
        password_hash: Some(password_hash),
        totp_secret: None,
        totp_backup_codes: None,
        webauthn_enabled: false,
        account_locked: false,
        account_locked_until: None,
        failed_login_attempts: 0,
        last_login_at: None,
        last_failed_login_at: None,
        password_changed_at: Some(Utc::now()),
        password_expires_at: None,
        require_password_change: request.require_password_change.unwrap_or(false),
        realm_id: request.realm_id,
        organization_id: None,
        attributes: None,
        enabled: request.enabled.unwrap_or(true),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        deleted_at: None,
    };

    // Store the user
    user_store.add_user(user.clone());

    Ok(Json(user))
}#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
}

pub async fn update_user(
    State(store): State<Arc<UserStore>>,
    _auth: AuthBearer,
    Path((realm, id)): Path<(String, String)>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut users = store.users.lock().unwrap();
    let realm_uuid = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(user) = users.iter_mut().find(|u| u.id.to_string() == id && u.realm_id == Some(realm_uuid)) {
        if let Some(username) = &req.username {
            user.username = username.clone();
        }
        if let Some(email) = &req.email {
            user.email = email.clone();
        }
        user.updated_at = Utc::now();
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn delete_user(
    State(store): State<Arc<UserStore>>,
    auth: AuthBearer,
    Path((realm, id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    let realm_uuid = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // TODO: Implement proper admin role checking
    // For now, allow deletion if user is authenticated
    let users = store.users.lock().unwrap();
    let user_exists = users.iter().any(|u| u.id.to_string() == auth.0.sub && u.realm_id == Some(realm_uuid));
    
    if !user_exists {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let mut users = store.users.lock().unwrap();
    let len_before = users.len();
    users.retain(|u| !(u.id.to_string() == id && u.realm_id == Some(realm_uuid)));
    if users.len() < len_before {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

pub async fn update_password(
    State(store): State<Arc<UserStore>>,
    _auth: AuthBearer,
    Path((realm, id)): Path<(String, String)>,
    Json(req): Json<UpdatePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    let realm_uuid = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let mut users = store.users.lock().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.id.to_string() == id && u.realm_id == Some(realm_uuid)) {
        // Handle Option<String> for password_hash
        if let Some(ref password_hash) = user.password_hash {
            if password::verify_password(password_hash, &req.old_password).unwrap_or(false) {
                match password::hash_password(&req.new_password) {
                    Ok(new_hash) => {
                        user.password_hash = Some(new_hash);
                        user.password_changed_at = Some(Utc::now());
                        user.updated_at = Utc::now();
                        Ok(StatusCode::OK)
                    },
                    Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                }
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        } else {
            Err(StatusCode::BAD_REQUEST)
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}