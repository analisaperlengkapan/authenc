use crate::app::AppState;
use crate::handlers::api::auth_bearer::AuthBearer;
use authenc_api::models::user::{self, User};
use authenc_services::services::stores::user_store::UserStoreTrait;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, patch, post, put},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Create user management routes for a realm
pub fn create_user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/realms/{realm}/users", get(get_users))
        .route("/realms/{realm}/users", post(create_user))
        .route("/realms/{realm}/users/{id}", get(get_user_by_id))
        .route("/realms/{realm}/users/{id}", put(update_user))
        .route("/realms/{realm}/users/{id}", delete(delete_user))
        .route(
            "/realms/{realm}/users/{id}/password",
            patch(update_password),
        )
}

/// Get all users in the specified realm
pub async fn get_users(
    State(state): State<Arc<AppState>>,
    _auth: AuthBearer,
    Path(realm): Path<String>,
) -> Result<Json<Vec<User>>, StatusCode> {
    let realm_id = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;
    let users = state
        .user_store
        .get_users_by_realm(realm_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(users))
}

/// Get a specific user by ID in the specified realm
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    _auth: AuthBearer,
    Path((_realm, id)): Path<(String, String)>,
) -> Result<Json<User>, StatusCode> {
    let user_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let user = state
        .user_store
        .get_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    user.ok_or(StatusCode::NOT_FOUND).map(Json)
}
#[derive(Deserialize)]
/// Request payload for creating a new user account
pub struct CreateUserRequest {
    /// The unique username for the user account
    pub username: String,
    /// The email address associated with the user account
    pub email: String,
    /// The initial password for the user account (will be hashed)
    pub password: String,
    /// Optional UUID of the realm this user belongs to
    pub realm_id: Option<Uuid>,
    /// Optional first name of the user
    pub first_name: Option<String>,
    /// Optional last name of the user
    pub last_name: Option<String>,
    /// Optional phone number for the user
    pub phone_number: Option<String>,
    /// Whether the user account should be enabled upon creation
    pub enabled: Option<bool>,
    /// Whether the user must change their password on first login
    pub require_password_change: Option<bool>,
}
/// Create a new user in the specified realm
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<User>, StatusCode> {
    // Convert handler request to model request
    let model_request = user::CreateUserRequest {
        username: request.username,
        email: request.email,
        password: Some(request.password),
        first_name: request.first_name,
        last_name: request.last_name,
        phone_number: None,
        realm_id: request.realm_id,
        organization_id: None,
        attributes: None,
    };

    // Store the user
    let created_user = state
        .user_store
        .add_user(model_request)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let realm_id = request.realm_id.ok_or(StatusCode::BAD_REQUEST)?;

    // Fire admin event for user creation
    let auth_details = authenc_api::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let admin_event = authenc_services::services::events::AdminEventBuilder::new(
        realm_id.to_string(),
        auth_details,
        authenc_api::models::events::ResourceType::User,
        authenc_api::models::events::OperationType::Create,
        format!("/realms/{}/users/{}", realm_id, created_user.id),
    )
    .representation(serde_json::to_string(&created_user).unwrap_or_default())
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!("Failed to fire user creation admin event: {}", e);
    }

    Ok(Json(created_user))
}
#[derive(Deserialize)]
/// Request payload for updating user information
pub struct UpdateUserRequest {
    /// Optional new username for the user
    pub username: Option<String>,
    /// Optional new email address for the user
    pub email: Option<String>,
}

/// Update an existing user's information in the specified realm
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, id)): Path<(String, String)>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let user_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Create update request for the model
    let update_request = authenc_api::models::user::UpdateUserRequest {
        username: req.username,
        email: req.email,
        first_name: None,
        last_name: None,
        phone_number: None,
        enabled: None,
        email_verified: None,
        phone_verified: None,
        require_password_change: None,
        attributes: None,
    };

    // Update user in database
    state
        .user_store
        .update_user(user_id, update_request)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for user update
    let auth_details = authenc_api::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = authenc_services::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        authenc_api::models::events::ResourceType::User,
        authenc_api::models::events::OperationType::Update,
        format!("/realms/{}/users/{}", realm, user_id),
    )
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, false)
        .await
    {
        tracing::error!("Failed to fire user update admin event: {}", e);
    }

    Ok(StatusCode::OK)
}

/// Delete a user from the specified realm
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    let user_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let realm_id = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check if user exists and belongs to the realm
    let user = state
        .user_store
        .get_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if user.realm_id != Some(realm_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Delete the user
    state
        .user_store
        .delete_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for user deletion
    let auth_details = authenc_api::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = authenc_services::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        authenc_api::models::events::ResourceType::User,
        authenc_api::models::events::OperationType::Delete,
        format!("/realms/{}/users/{}", realm, user_id),
    )
    .representation(serde_json::to_string(&user).unwrap_or_default())
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!("Failed to fire user deletion admin event: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
/// Request payload for updating a user's password
pub struct UpdatePasswordRequest {
    /// The current password for verification
    pub old_password: String,
    /// The new password to set for the user account
    pub new_password: String,
}

/// Update a user's password in the specified realm
pub async fn update_password(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, id)): Path<(String, String)>,
    Json(req): Json<UpdatePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    let user_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let realm_id = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get the user
    let user = state
        .user_store
        .get_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Check if user belongs to the realm
    if user.realm_id != Some(realm_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Verify old password if user has a password hash
    if let Some(password_hash) = &user.password_hash {
        let is_valid = authenc_core::utils::crypto::verify_password(password_hash, &req.old_password)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !is_valid {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        // User doesn't have a password set, which shouldn't happen for regular users
        return Err(StatusCode::BAD_REQUEST);
    }

    // Hash the new password
    let new_password_hash = authenc_core::utils::crypto::hash_password(&req.new_password)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update password in database
    state
        .user_store
        .update_password(user_id, new_password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for password change
    let auth_details = authenc_api::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = authenc_services::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        authenc_api::models::events::ResourceType::User,
        authenc_api::models::events::OperationType::Update,
        format!("/realms/{}/users/{}/password", realm, user_id),
    )
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, false)
        .await
    {
        tracing::error!("Failed to fire password change admin event: {}", e);
    }

    Ok(StatusCode::OK)
}
