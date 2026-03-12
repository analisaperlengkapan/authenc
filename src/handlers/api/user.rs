use crate::app::AppState;
use crate::handlers::api::auth_bearer::AuthBearer;
use authenc_models::models::user::{self, User, UserResponse};
use authenc_services::services::stores::user_store::UserStoreTrait;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, patch, post, put},
};
use serde::Deserialize;
use authenc_models::models::social_account::{CreateSocialAccountRequest, SocialAccountResponse};
use authenc_services::services::social::SocialProvider;
use authenc_services::services::stores::social_account_store::SocialAccountStoreTrait;
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
        .route("/realms/{realm}/users/{id}/social", get(get_user_social_accounts).post(link_user_social_account))
        .route(
            "/realms/{realm}/users/{id}/social/{provider}",
            delete(unlink_user_social_account),
        )
}

/// Get all users in the specified realm
pub async fn get_users(
    State(state): State<Arc<AppState>>,
    _auth: AuthBearer,
    Path(realm): Path<String>,
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    let realm_id = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;
    let users = state
        .user_store
        .get_users_by_realm(realm_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response_users = users.into_iter().map(UserResponse::from).collect();
    Ok(Json(response_users))
}

/// Get a specific user by ID in the specified realm
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    _auth: AuthBearer,
    Path((realm, id)): Path<(String, String)>,
) -> Result<Json<UserResponse>, StatusCode> {
    let user_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let realm_id = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;

    let user = state
        .user_store
        .get_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if user.realm_id != Some(realm_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(UserResponse::from(user)))
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
    /// Whether the email address has been verified
    pub email_verified: Option<bool>,
    /// Whether the user must change their password on first login
    pub require_password_change: Option<bool>,
}
/// Create a new user in the specified realm
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path(realm): Path<String>,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    let realm_id = Uuid::parse_str(&realm).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate that request body realm_id matches path realm_id if present
    if let Some(req_realm_id) = request.realm_id {
        if req_realm_id != realm_id {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Convert handler request to model request
    let model_request = user::CreateUserRequest {
        username: request.username,
        email: request.email,
        password: Some(request.password),
        first_name: request.first_name,
        last_name: request.last_name,
        phone_number: request.phone_number,
        email_verified: request.email_verified,
        enabled: request.enabled,
        require_password_change: request.require_password_change,
        realm_id: Some(realm_id),
        organization_id: None,
        attributes: None,
    };

    // Store the user
    let created_user = state
        .user_store
        .add_user(model_request)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for user creation
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let admin_event = crate::services::events::AdminEventBuilder::new(
        realm_id.to_string(),
        auth_details,
        crate::models::events::ResourceType::User,
        crate::models::events::OperationType::Create,
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

    Ok(Json(UserResponse::from(created_user)))
}
#[derive(Deserialize)]
/// Request payload for updating user information
pub struct UpdateUserRequest {
    /// Optional new username for the user
    pub username: Option<String>,
    /// Optional new email address for the user
    pub email: Option<String>,
    /// Optional new first name for the user
    pub first_name: Option<String>,
    /// Optional new last name for the user
    pub last_name: Option<String>,
    /// Optional new phone number for the user
    pub phone_number: Option<String>,
    /// Whether the user account is enabled
    pub enabled: Option<bool>,
    /// Whether the email address has been verified
    pub email_verified: Option<bool>,
    /// Whether the user must change their password on next login
    pub require_password_change: Option<bool>,
}

/// Update an existing user's information in the specified realm
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, id)): Path<(String, String)>,
    Json(req): Json<UpdateUserRequest>,
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
        return Err(StatusCode::NOT_FOUND);
    }

    // Prevent self-disabling
    if req.enabled == Some(false) && (auth.sub == id || Uuid::parse_str(&auth.sub).ok() == Some(user_id)) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Create update request for the model
    let update_request = crate::models::user::UpdateUserRequest {
        username: req.username,
        email: req.email,
        first_name: req.first_name,
        last_name: req.last_name,
        phone_number: req.phone_number,
        enabled: req.enabled,
        email_verified: req.email_verified,
        phone_verified: None,
        require_password_change: req.require_password_change,
        attributes: None,
    };

    // Update user in database
    state
        .user_store
        .update_user(user_id, update_request)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for user update
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = crate::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        crate::models::events::ResourceType::User,
        crate::models::events::OperationType::Update,
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
        return Err(StatusCode::NOT_FOUND);
    }

    // Prevent self-deletion
    // Compare as strings and, if possible, as UUIDs to ensure format mismatches don't bypass the check
    if auth.sub == id || Uuid::parse_str(&auth.sub).ok() == Some(user_id) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Delete the user
    state
        .user_store
        .delete_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for user deletion
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = crate::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        crate::models::events::ResourceType::User,
        crate::models::events::OperationType::Delete,
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
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify old password if user has a password hash
    if let Some(password_hash) = &user.password_hash {
        let is_valid = authenc_crypto::utils::crypto::verify_password(password_hash, &req.old_password)
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
    let new_password_hash = authenc_crypto::utils::crypto::hash_password(&req.new_password)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update password in database
    state
        .user_store
        .update_password(user_id, new_password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event for password change
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = crate::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        crate::models::events::ResourceType::User,
        crate::models::events::OperationType::Update,
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

/// Link a social account for a specific user
pub async fn link_user_social_account(
    State(state): State<Arc<AppState>>,
    Path((realm, user_id)): Path<(String, Uuid)>,
    AuthBearer(auth): AuthBearer,
    Json(request): Json<CreateSocialAccountRequest>,
) -> Result<Json<SocialAccountResponse>, crate::error::AuthencError> {
    // Get user to verify they exist and belong to the realm
    let user = state
        .user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| crate::error::AuthencError::resource_not_found("User not found"))?;

    // Validate realm consistently with other handlers
    let realm_uuid = Uuid::parse_str(&realm).map_err(|_| crate::error::AuthencError::validation("Invalid realm ID"))?;

    if user.realm_id != Some(realm_uuid) {
        return Err(crate::error::AuthencError::resource_not_found("User not found in realm"));
    }

    let account = state
        .social_account_store
        .add_social_account(user_id, request)
        .await?;

    // Fire admin event for linking social account
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = crate::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        crate::models::events::ResourceType::User,
        crate::models::events::OperationType::Update,
        format!("/realms/{}/users/{}/social", realm, user_id),
    )
    .representation(serde_json::to_string(&account).unwrap_or_default())
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, false)
        .await
    {
        tracing::error!("Failed to fire link social account admin event: {}", e);
    }

    Ok(Json(account.into()))
}

/// Get linked social accounts for a specific user
pub async fn get_user_social_accounts(
    State(state): State<Arc<AppState>>,
    Path((realm, user_id)): Path<(String, Uuid)>,
    _auth: AuthBearer,
) -> Result<Json<Vec<SocialAccountResponse>>, crate::error::AuthencError> {
    // Get user to verify they exist and belong to the realm
    let user = state
        .user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| crate::error::AuthencError::resource_not_found("User not found"))?;

    // Validate realm consistently with other handlers
    let realm_uuid = Uuid::parse_str(&realm).map_err(|_| crate::error::AuthencError::validation("Invalid realm ID"))?;

    if user.realm_id != Some(realm_uuid) {
        return Err(crate::error::AuthencError::resource_not_found("User not found in realm"));
    }

    // Get social accounts for the user
    let social_accounts = state
        .social_account_store
        .get_user_social_accounts(user_id)
        .await?;

    // Convert to response format
    let responses: Vec<SocialAccountResponse> = social_accounts
        .into_iter()
        .map(|account| account.into())
        .collect();

    Ok(Json(responses))
}

/// Unlink a social account for a specific user
pub async fn unlink_user_social_account(
    State(state): State<Arc<AppState>>,
    Path((realm, user_id, provider_str)): Path<(String, Uuid, String)>,
    AuthBearer(auth): AuthBearer,
) -> Result<StatusCode, crate::error::AuthencError> {
    // Admin validation: Check if user exists and belongs to the realm
    let user = state
        .user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| crate::error::AuthencError::resource_not_found("User not found"))?;

    // Validate realm consistently with other handlers
    let realm_uuid = Uuid::parse_str(&realm).map_err(|_| crate::error::AuthencError::validation("Invalid realm ID"))?;

    if user.realm_id != Some(realm_uuid) {
        return Err(crate::error::AuthencError::resource_not_found("User not found in realm"));
    }

    // Parse provider
    let provider = std::str::FromStr::from_str(&provider_str)
        .unwrap_or_else(|_| SocialProvider::Custom(provider_str.clone()));

    // Remove the social account link
    state
        .social_account_store
        .remove_social_account_by_provider(user_id, &provider)
        .await?;

    // Fire admin event for unlinking social account
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let admin_event = crate::services::events::AdminEventBuilder::new(
        realm.clone(),
        auth_details,
        crate::models::events::ResourceType::User,
        crate::models::events::OperationType::Delete,
        format!("/realms/{}/users/{}/social/{}", realm, user_id, provider_str),
    )
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, false)
        .await
    {
        tracing::error!("Failed to fire unlink social account admin event: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}
