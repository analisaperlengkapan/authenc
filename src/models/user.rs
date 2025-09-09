use crate::error::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT Claims for user authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    pub sub: String, // Subject (user ID)
    pub username: String,
    pub email: String,
    pub realm_id: String,
    pub roles: Vec<String>,
    pub exp: usize,  // Expiration time
    pub iat: usize,  // Issued at
    pub iss: String, // Issuer
}

/// User entity representing an authenticated user (enhanced for enterprise features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: bool,
    pub password_hash: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_backup_codes: Option<Vec<String>>,
    pub webauthn_enabled: bool,
    pub account_locked: bool,
    pub account_locked_until: Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_failed_login_at: Option<DateTime<Utc>>,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub require_password_change: bool,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub attributes: Option<serde_json::Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_type: CredentialType,
    pub credential_data: serde_json::Value,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Credential type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    Password,
    Totp,
    Webauthn,
    RecoveryCode,
    MagicLink,
    Social,
}

/// User session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_id: String,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub started_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub termination_reason: Option<String>,
    pub refresh_token_id: Option<Uuid>,
    pub attributes: Option<serde_json::Value>,
}

/// User role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub assigned_by: Uuid,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub attributes: Option<serde_json::Value>,
}

/// Role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub realm_id: Option<Uuid>,
    pub composite: bool,
    pub client_role: bool,
    pub client_id: Option<String>,
    pub attributes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub action: String,
    pub realm_id: Option<Uuid>,
    pub attributes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role permission mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermission {
    pub id: Uuid,
    pub role_id: Uuid,
    pub permission_id: Uuid,
    pub assigned_at: DateTime<Utc>,
}

/// User group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    pub id: Uuid,
    pub user_id: Uuid,
    pub group_id: Uuid,
    pub assigned_by: Uuid,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub path: String,
    pub parent_id: Option<Uuid>,
    pub realm_id: Option<Uuid>,
    pub attributes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Group role mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRole {
    pub id: Uuid,
    pub group_id: Uuid,
    pub role_id: Uuid,
    pub assigned_at: DateTime<Utc>,
}

/// User profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub theme: Option<String>,
    pub preferences: Option<serde_json::Value>,
    pub updated_at: DateTime<Utc>,
}

/// Authentication flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFlow {
    pub id: Uuid,
    pub alias: String,
    pub description: Option<String>,
    pub realm_id: Option<Uuid>,
    pub provider_id: String,
    pub top_level: bool,
    pub built_in: bool,
    pub attributes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Authentication execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExecution {
    pub id: Uuid,
    pub flow_id: Uuid,
    pub alias: String,
    pub description: Option<String>,
    pub provider_id: String,
    pub requirement: ExecutionRequirement,
    pub priority: i32,
    pub parent_flow: Option<Uuid>,
    pub authenticator_config: Option<String>,
    pub attributes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Execution requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionRequirement {
    Required,
    Alternative,
    Disabled,
    Conditional,
}

/// Authenticator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorConfig {
    pub id: Uuid,
    pub alias: String,
    pub description: Option<String>,
    pub realm_id: Option<Uuid>,
    pub provider_id: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Identity provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: Uuid,
    pub alias: String,
    pub display_name: Option<String>,
    pub provider_id: String,
    pub enabled: bool,
    pub trust_email: bool,
    pub store_token: bool,
    pub add_read_token_role_on_create: bool,
    pub authenticate_by_default: bool,
    pub link_only: bool,
    pub first_broker_login_flow_id: Option<Uuid>,
    pub post_broker_login_flow_id: Option<Uuid>,
    pub config: serde_json::Value,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Identity provider mapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderMapper {
    pub id: Uuid,
    pub name: String,
    pub identity_provider_alias: String,
    pub identity_provider_mapper: String,
    pub config: serde_json::Value,
    pub realm_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User identity provider link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentityProviderLink {
    pub id: Uuid,
    pub user_id: Uuid,
    pub identity_provider_id: Uuid,
    pub external_id: String,
    pub external_username: Option<String>,
    pub token: Option<String>,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Required action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredAction {
    pub id: Uuid,
    pub alias: String,
    pub name: String,
    pub description: Option<String>,
    pub provider_id: String,
    pub enabled: bool,
    pub default_action: bool,
    pub priority: i32,
    pub config: Option<serde_json::Value>,
    pub realm_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User required action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRequiredAction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub required_action_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// User creation request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub attributes: Option<serde_json::Value>,
}

/// User update request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub enabled: Option<bool>,
    pub email_verified: Option<bool>,
    pub phone_verified: Option<bool>,
    pub require_password_change: Option<bool>,
    pub attributes: Option<serde_json::Value>,
}

/// User response (without sensitive data)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: bool,
    pub webauthn_enabled: bool,
    pub account_locked: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user with default values
    pub fn new(
        username: String,
        email: String,
        password_hash: Option<String>,
        realm_id: Option<Uuid>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            email_verified: false,
            first_name: None,
            last_name: None,
            phone_number: None,
            phone_verified: false,
            password_hash,
            totp_secret: None,
            totp_backup_codes: None,
            webauthn_enabled: false,
            account_locked: false,
            account_locked_until: None,
            failed_login_attempts: 0,
            last_login_at: None,
            last_failed_login_at: None,
            password_changed_at: None,
            password_expires_at: None,
            require_password_change: false,
            realm_id,
            organization_id: None,
            attributes: None,
            enabled: true,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Check if user is active (enabled and not deleted)
    pub fn is_active(&self) -> bool {
        self.enabled && self.deleted_at.is_none() && !self.account_locked
    }

    /// Check if user account is locked
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.account_locked_until {
            self.account_locked && Utc::now() < locked_until
        } else {
            self.account_locked
        }
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
        if let Some(first_name) = request.first_name {
            self.first_name = Some(first_name);
        }
        if let Some(last_name) = request.last_name {
            self.last_name = Some(last_name);
        }
        if let Some(phone_number) = request.phone_number {
            self.phone_number = Some(phone_number);
        }
        if let Some(enabled) = request.enabled {
            self.enabled = enabled;
        }
        if let Some(email_verified) = request.email_verified {
            self.email_verified = email_verified;
        }
        if let Some(phone_verified) = request.phone_verified {
            self.phone_verified = phone_verified;
        }
        if let Some(require_password_change) = request.require_password_change {
            self.require_password_change = require_password_change;
        }
        if let Some(attributes) = request.attributes {
            self.attributes = Some(attributes);
        }
        self.updated_at = Utc::now();
    }

    /// Record a successful login
    pub fn record_login(&mut self) {
        self.last_login_at = Some(Utc::now());
        self.failed_login_attempts = 0;
        self.account_locked = false;
        self.account_locked_until = None;
        self.updated_at = Utc::now();
    }

    /// Record a failed login attempt
    pub fn record_failed_login(&mut self) {
        self.failed_login_attempts += 1;
        self.last_failed_login_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Lock the user account
    pub fn lock_account(&mut self, until: Option<DateTime<Utc>>) {
        self.account_locked = true;
        self.account_locked_until = until;
        self.updated_at = Utc::now();
    }

    /// Unlock the user account
    pub fn unlock_account(&mut self) {
        self.account_locked = false;
        self.account_locked_until = None;
        self.failed_login_attempts = 0;
        self.updated_at = Utc::now();
    }

    /// Update password
    pub fn update_password(&mut self, new_hash: String) {
        self.password_hash = Some(new_hash);
        self.password_changed_at = Some(Utc::now());
        self.require_password_change = false;
        self.updated_at = Utc::now();
    }

    /// Enable WebAuthn
    pub fn enable_webauthn(&mut self) {
        self.webauthn_enabled = true;
        self.updated_at = Utc::now();
    }

    /// Disable WebAuthn
    pub fn disable_webauthn(&mut self) {
        self.webauthn_enabled = false;
        self.updated_at = Utc::now();
    }

    /// Get full name
    pub fn full_name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => format!("{} {}", first, last),
            (Some(first), None) => first.clone(),
            (None, Some(last)) => last.clone(),
            (None, None) => self.username.clone(),
        }
    }
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
            first_name: user.first_name,
            last_name: user.last_name,
            phone_number: user.phone_number,
            phone_verified: user.phone_verified,
            webauthn_enabled: user.webauthn_enabled,
            account_locked: user.account_locked,
            last_login_at: user.last_login_at,
            realm_id: user.realm_id,
            organization_id: user.organization_id,
            enabled: user.enabled,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl TryFrom<tokio_postgres::Row> for User {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(User {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            email: row.try_get("email")?,
            email_verified: row.try_get("email_verified")?,
            first_name: row.try_get("first_name")?,
            last_name: row.try_get("last_name")?,
            phone_number: row.try_get("phone_number")?,
            phone_verified: row.try_get("phone_verified")?,
            password_hash: row.try_get("password_hash")?,
            totp_secret: row.try_get("totp_secret")?,
            totp_backup_codes: row.try_get("totp_backup_codes")?,
            webauthn_enabled: row.try_get("webauthn_enabled")?,
            account_locked: row.try_get("account_locked")?,
            account_locked_until: row.try_get("account_locked_until")?,
            failed_login_attempts: row.try_get("failed_login_attempts")?,
            last_login_at: row.try_get("last_login_at")?,
            last_failed_login_at: row.try_get("last_failed_login_at")?,
            password_changed_at: row.try_get("password_changed_at")?,
            password_expires_at: row.try_get("password_expires_at")?,
            require_password_change: row.try_get("require_password_change")?,
            realm_id: row.try_get("realm_id")?,
            organization_id: row.try_get("organization_id")?,
            attributes: {
                let json_str: Option<String> = row.try_get("attributes")?;
                json_str.and_then(|s| serde_json::from_str(&s).ok())
            },
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}
