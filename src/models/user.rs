use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// User entity representing an authenticated user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub realm_id: Uuid,
    pub enabled: bool,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User creation request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub realm_id: Uuid,
}

/// User update request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub enabled: Option<bool>,
}

/// User response (without sensitive data)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub realm_id: Uuid,
    pub enabled: bool,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            realm_id: user.realm_id,
            enabled: user.enabled,
            email_verified: user.email_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl User {
    /// Create a new user with default values
    pub fn new(username: String, email: String, password_hash: String, realm_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            realm_id,
            enabled: true,
            email_verified: false,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }
    
    /// Check if user is active (enabled and not deleted)
    pub fn is_active(&self) -> bool {
        self.enabled && self.deleted_at.is_none()
    }
    
    /// Soft delete the user
    pub fn delete(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }
    
    /// Update user fields
    pub fn update(&mut self, request: UpdateUserRequest) {
        if let Some(username) = request.username {
            self.username = username;
        }
        if let Some(email) = request.email {
            self.email = email;
        }
        if let Some(enabled) = request.enabled {
            self.enabled = enabled;
        }
        self.updated_at = Utc::now();
    }
}
