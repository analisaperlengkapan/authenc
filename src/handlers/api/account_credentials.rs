use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, put, delete, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::models::user::UserResponse;
use crate::services::stores::user_store::{UserStore, UserStoreTrait};

/// Create account credentials management routes
pub fn create_account_credentials_routes() -> Router<Arc<UserStore>> {
    Router::new()
        .route("/account/credentials", get(get_account_credentials))
        .route("/account/credentials/password", put(update_account_password))
        .route("/account/credentials/{credential_id}", delete(remove_account_credential))
}

/// Get current user's credentials
pub async fn get_account_credentials(
    State(user_store): State<Arc<UserStore>>,
) -> Result<Json<Vec<CredentialResponse>>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    let user = user_store
        .get_user(current_user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    // TODO: Get actual credentials from user model
    // For now, return empty list
    let credentials = Vec::new();

    Ok(Json(credentials))
}

/// Update current user's password
#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn update_account_password(
    State(user_store): State<Arc<UserStore>>,
    Json(request): Json<UpdatePasswordRequest>,
) -> Result<StatusCode, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    // TODO: Verify current password
    // TODO: Validate new password against password policy
    // TODO: Hash new password
    // TODO: Update user password

    Ok(StatusCode::NO_CONTENT)
}

/// Remove a credential from current user's account
pub async fn remove_account_credential(
    State(user_store): State<Arc<UserStore>>,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = Uuid::new_v4(); // Placeholder

    // TODO: Verify credential belongs to current user
    // TODO: Remove credential based on type (TOTP, WebAuthn, etc.)

    Ok(StatusCode::NO_CONTENT)
}

/// Credential response structure
#[derive(serde::Serialize)]
pub struct CredentialResponse {
    /// Unique identifier for the credential
    pub id: String,
    /// Type of credential
    pub credential_type: CredentialType,
    /// User-friendly name for the credential
    pub user_label: Option<String>,
    /// When the credential was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the credential was last used
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Types of credentials
#[derive(serde::Serialize)]
pub enum CredentialType {
    /// Password credential
    Password,
    /// TOTP credential
    Totp,
    /// WebAuthn credential
    WebAuthn,
    /// Backup codes
    BackupCode,
}
