use crate::error::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT Claims for user authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    /// Subject identifier (user ID)
    pub sub: String,
    /// Username of the authenticated user
    pub username: String,
    /// Email address of the user
    pub email: String,
    /// Realm identifier the user belongs to
    pub realm_id: String,
    /// List of roles assigned to the user
    pub roles: Vec<String>,
    /// Token expiration timestamp
    pub exp: usize,
    /// Token issued at timestamp
    pub iat: usize,
    /// Token issuer identifier
    pub iss: String,
}

/// User entity representing an authenticated user (enhanced for enterprise features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user
    pub id: Uuid,
    /// Username for authentication
    pub username: String,
    /// Email address of the user
    pub email: String,
    /// Whether the email address has been verified
    pub email_verified: bool,
    /// User's first name
    pub first_name: Option<String>,
    /// User's last name
    pub last_name: Option<String>,
    /// User's phone number
    pub phone_number: Option<String>,
    /// Whether the phone number has been verified
    pub phone_verified: bool,
    /// Hashed password for authentication
    pub password_hash: Option<String>,
    /// TOTP secret for two-factor authentication
    pub totp_secret: Option<String>,
    /// Backup codes for TOTP recovery
    pub totp_backup_codes: Option<Vec<String>>,
    /// Whether WebAuthn is enabled for this user
    pub webauthn_enabled: bool,
    /// Whether the account is currently locked
    pub account_locked: bool,
    /// Timestamp until which the account is locked
    pub account_locked_until: Option<DateTime<Utc>>,
    /// Number of consecutive failed login attempts
    pub failed_login_attempts: i32,
    /// Timestamp of the last successful login
    pub last_login_at: Option<DateTime<Utc>>,
    /// Timestamp of the last failed login attempt
    pub last_failed_login_at: Option<DateTime<Utc>>,
    /// Timestamp when the password was last changed
    pub password_changed_at: Option<DateTime<Utc>>,
    /// Timestamp when the password expires
    pub password_expires_at: Option<DateTime<Utc>>,
    /// Whether the user must change their password on next login
    pub require_password_change: bool,
    /// ID of the realm this user belongs to
    pub realm_id: Option<Uuid>,
    /// ID of the organization this user belongs to
    pub organization_id: Option<Uuid>,
    /// Additional user attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Whether the user account is enabled
    pub enabled: bool,
    /// Whether this user was created via identity provider federation
    pub federated: bool,
    /// Timestamp when the user was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the user was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the user was soft deleted
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCredential {
    /// Unique identifier for the credential
    pub id: Uuid,
    /// ID of the user this credential belongs to
    pub user_id: Uuid,
    /// Type of credential (password, TOTP, WebAuthn, etc.)
    pub credential_type: CredentialType,
    /// Credential data stored as JSON
    pub credential_data: serde_json::Value,
    /// Priority order for credential usage
    pub priority: i32,
    /// Whether this credential is enabled
    pub enabled: bool,
    /// Timestamp when the credential was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the credential was last used
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Credential type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    /// Password-based authentication
    Password,
    /// Time-based One-Time Password (TOTP)
    Totp,
    /// WebAuthn/FIDO2 authentication
    Webauthn,
    /// Recovery codes for account recovery
    RecoveryCode,
    /// Magic link authentication
    MagicLink,
    /// Social login authentication
    Social,
}

/// User session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    /// Unique identifier for the session
    pub id: Uuid,
    /// ID of the user this session belongs to
    pub user_id: Uuid,
    /// Session identifier string
    pub session_id: String,
    /// Client ID associated with the session
    pub client_id: Option<String>,
    /// IP address of the client
    pub ip_address: Option<String>,
    /// User agent string from the client
    pub user_agent: Option<String>,
    /// Timestamp when the session started
    pub started_at: DateTime<Utc>,
    /// Timestamp when the session expires
    pub expires_at: DateTime<Utc>,
    /// Timestamp of the last activity in this session
    pub last_activity_at: DateTime<Utc>,
    /// Timestamp when the session was terminated
    pub terminated_at: Option<DateTime<Utc>>,
    /// Reason for session termination
    pub termination_reason: Option<String>,
    /// ID of the refresh token associated with this session
    pub refresh_token_id: Option<Uuid>,
    /// Additional session attributes as JSON
    pub attributes: Option<serde_json::Value>,
}

/// User role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    /// Unique identifier for the user-role assignment
    pub id: Uuid,
    /// ID of the user
    pub user_id: Uuid,
    /// ID of the role
    pub role_id: Uuid,
    /// ID of the user who assigned this role
    pub assigned_by: Uuid,
    /// Timestamp when the role was assigned
    pub assigned_at: DateTime<Utc>,
    /// Timestamp when the role assignment expires
    pub expires_at: Option<DateTime<Utc>>,
    /// Additional attributes for the role assignment
    pub attributes: Option<serde_json::Value>,
}

/// Role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier for the role
    pub id: Uuid,
    /// Name of the role
    pub name: String,
    /// Description of the role
    pub description: Option<String>,
    /// ID of the realm this role belongs to
    pub realm_id: Option<Uuid>,
    /// Whether this is a composite role (contains other roles)
    pub composite: bool,
    /// Whether this is a client-specific role
    pub client_role: bool,
    /// Client identifier if this is a client role
    pub client_id: Option<String>,
    /// Additional role attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Timestamp when the role was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the role was last updated
    pub updated_at: DateTime<Utc>,
}

/// Permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Unique identifier for the permission
    pub id: Uuid,
    /// Name of the permission
    pub name: String,
    /// Description of the permission
    pub description: Option<String>,
    /// Type of resource this permission applies to
    pub resource_type: String,
    /// Specific resource identifier
    pub resource_id: Option<String>,
    /// Action allowed on the resource (read, write, delete, etc.)
    pub action: String,
    /// ID of the realm this permission belongs to
    pub realm_id: Option<Uuid>,
    /// Additional permission attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Timestamp when the permission was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the permission was last updated
    pub updated_at: DateTime<Utc>,
}

/// Role permission mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermission {
    /// Unique identifier for the role-permission assignment
    pub id: Uuid,
    /// ID of the role
    pub role_id: Uuid,
    /// ID of the permission
    pub permission_id: Uuid,
    /// Timestamp when the permission was assigned to the role
    pub assigned_at: DateTime<Utc>,
}

/// User group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    /// Unique identifier for the user-group assignment
    pub id: Uuid,
    /// ID of the user
    pub user_id: Uuid,
    /// ID of the group
    pub group_id: Uuid,
    /// ID of the user who assigned this group membership
    pub assigned_by: Uuid,
    /// Timestamp when the user was assigned to the group
    pub assigned_at: DateTime<Utc>,
    /// Timestamp when the group membership expires
    pub expires_at: Option<DateTime<Utc>>,
}

/// Group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier for the group
    pub id: Uuid,
    /// Name of the group
    pub name: String,
    /// Description of the group
    pub description: Option<String>,
    /// Path of the group in the hierarchy
    pub path: String,
    /// ID of the parent group
    pub parent_id: Option<Uuid>,
    /// ID of the realm this group belongs to
    pub realm_id: Option<Uuid>,
    /// Additional group attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Timestamp when the group was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the group was last updated
    pub updated_at: DateTime<Utc>,
}

/// Group role mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRole {
    /// Unique identifier for the group-role assignment
    pub id: Uuid,
    /// ID of the group
    pub group_id: Uuid,
    /// ID of the role
    pub role_id: Uuid,
    /// Timestamp when the role was assigned to the group
    pub assigned_at: DateTime<Utc>,
}

/// User profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// ID of the user this profile belongs to
    pub user_id: Uuid,
    /// URL to the user's avatar image
    pub avatar_url: Option<String>,
    /// User's biography or description
    pub bio: Option<String>,
    /// User's website URL
    pub website: Option<String>,
    /// User's location
    pub location: Option<String>,
    /// User's timezone
    pub timezone: Option<String>,
    /// User's preferred locale
    pub locale: Option<String>,
    /// User's preferred theme
    pub theme: Option<String>,
    /// Additional user preferences as JSON
    pub preferences: Option<serde_json::Value>,
    /// Timestamp when the profile was last updated
    pub updated_at: DateTime<Utc>,
}

/// Authentication flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFlow {
    /// Unique identifier for the authentication flow
    pub id: Uuid,
    /// Alias name for the flow
    pub alias: String,
    /// Description of the authentication flow
    pub description: Option<String>,
    /// ID of the realm this flow belongs to
    pub realm_id: Option<Uuid>,
    /// Provider identifier for the flow
    pub provider_id: String,
    /// Whether this is a top-level flow
    pub top_level: bool,
    /// Whether this is a built-in flow
    pub built_in: bool,
    /// Additional flow attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Timestamp when the flow was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the flow was last updated
    pub updated_at: DateTime<Utc>,
}

/// Authentication execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExecution {
    /// Unique identifier for the execution
    pub id: Uuid,
    /// ID of the flow this execution belongs to
    pub flow_id: Uuid,
    /// Alias name for the execution
    pub alias: String,
    /// Description of the execution
    pub description: Option<String>,
    /// Provider identifier for the execution
    pub provider_id: String,
    /// Requirement level for this execution
    pub requirement: ExecutionRequirement,
    /// Priority order of the execution
    pub priority: i32,
    /// ID of the parent flow
    pub parent_flow: Option<Uuid>,
    /// Authenticator configuration identifier
    pub authenticator_config: Option<String>,
    /// Additional execution attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Timestamp when the execution was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the execution was last updated
    pub updated_at: DateTime<Utc>,
}

/// Execution requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionRequirement {
    /// Execution is required
    Required,
    /// Execution is an alternative option
    Alternative,
    /// Execution is disabled
    Disabled,
    /// Execution is conditional
    Conditional,
}

/// Authenticator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorConfig {
    /// Unique identifier for the configuration
    pub id: Uuid,
    /// Alias name for the configuration
    pub alias: String,
    /// Description of the configuration
    pub description: Option<String>,
    /// ID of the realm this configuration belongs to
    pub realm_id: Option<Uuid>,
    /// Provider identifier for the authenticator
    pub provider_id: String,
    /// Configuration data as JSON
    pub config: serde_json::Value,
    /// Timestamp when the configuration was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the configuration was last updated
    pub updated_at: DateTime<Utc>,
}

/// Identity provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    /// Unique identifier for the identity provider
    pub id: Uuid,
    /// Alias name for the provider
    pub alias: String,
    /// Display name for the provider
    pub display_name: Option<String>,
    /// Provider identifier
    pub provider_id: String,
    /// Whether the provider is enabled
    pub enabled: bool,
    /// Whether to trust email from this provider
    pub trust_email: bool,
    /// Whether to store tokens from this provider
    pub store_token: bool,
    /// Whether to add read token role on user creation
    pub add_read_token_role_on_create: bool,
    /// Whether to authenticate by default with this provider
    pub authenticate_by_default: bool,
    /// Whether this provider is for linking only
    pub link_only: bool,
    /// ID of the flow for first broker login
    pub first_broker_login_flow_id: Option<Uuid>,
    /// ID of the flow for post broker login
    pub post_broker_login_flow_id: Option<Uuid>,
    /// Provider configuration as JSON
    pub config: serde_json::Value,
    /// ID of the realm this provider belongs to
    pub realm_id: Option<Uuid>,
    /// ID of the organization this provider belongs to
    pub organization_id: Option<Uuid>,
    /// Timestamp when the provider was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the provider was last updated
    pub updated_at: DateTime<Utc>,
}

/// Identity provider mapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderMapper {
    /// Unique identifier for the mapper
    pub id: Uuid,
    /// Name of the mapper
    pub name: String,
    /// Alias of the identity provider
    pub identity_provider_alias: String,
    /// Mapper provider identifier
    pub identity_provider_mapper: String,
    /// Mapper configuration as JSON
    pub config: serde_json::Value,
    /// ID of the realm this mapper belongs to
    pub realm_id: Option<Uuid>,
    /// Timestamp when the mapper was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the mapper was last updated
    pub updated_at: DateTime<Utc>,
}

/// User identity provider link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentityProviderLink {
    /// Unique identifier for the link
    pub id: Uuid,
    /// ID of the user
    pub user_id: Uuid,
    /// ID of the identity provider
    pub identity_provider_id: Uuid,
    /// External identifier from the provider
    pub external_id: String,
    /// External username from the provider
    pub external_username: Option<String>,
    /// Token from the provider
    pub token: Option<String>,
    /// Timestamp when the link was created
    pub linked_at: DateTime<Utc>,
    /// Timestamp of the last login via this provider
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Required action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredAction {
    /// Unique identifier for the required action
    pub id: Uuid,
    /// Alias name for the action
    pub alias: String,
    /// Display name for the action
    pub name: String,
    /// Description of the required action
    pub description: Option<String>,
    /// Provider identifier for the action
    pub provider_id: String,
    /// Whether the action is enabled
    pub enabled: bool,
    /// Whether this is the default action
    pub default_action: bool,
    /// Priority order of the action
    pub priority: i32,
    /// Action configuration as JSON
    pub config: Option<serde_json::Value>,
    /// ID of the realm this action belongs to
    pub realm_id: Option<Uuid>,
    /// Timestamp when the action was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the action was last updated
    pub updated_at: DateTime<Utc>,
}

/// User required action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRequiredAction {
    /// Unique identifier for the user-action assignment
    pub id: Uuid,
    /// ID of the user
    pub user_id: Uuid,
    /// ID of the required action
    pub required_action_id: Uuid,
    /// Timestamp when the action was assigned
    pub created_at: DateTime<Utc>,
    /// Timestamp when the action expires
    pub expires_at: Option<DateTime<Utc>>,
}

/// User creation request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    /// Username for the new user
    pub username: String,
    /// Email address for the new user
    pub email: String,
    /// Password for the new user (optional, can be set later)
    pub password: Option<String>,
    /// First name of the user
    pub first_name: Option<String>,
    /// Last name of the user
    pub last_name: Option<String>,
    /// Phone number of the user
    pub phone_number: Option<String>,
    /// ID of the realm to create the user in
    pub realm_id: Option<Uuid>,
    /// ID of the organization to assign the user to
    pub organization_id: Option<Uuid>,
    /// Additional user attributes as JSON
    pub attributes: Option<serde_json::Value>,
}

/// User update request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    /// New username for the user
    pub username: Option<String>,
    /// New email address for the user
    pub email: Option<String>,
    /// New first name for the user
    pub first_name: Option<String>,
    /// New last name for the user
    pub last_name: Option<String>,
    /// New phone number for the user
    pub phone_number: Option<String>,
    /// Whether the user account is enabled
    pub enabled: Option<bool>,
    /// Whether the email address has been verified
    pub email_verified: Option<bool>,
    /// Whether the phone number has been verified
    pub phone_verified: Option<bool>,
    /// Whether the user must change their password on next login
    pub require_password_change: Option<bool>,
    /// Additional user attributes as JSON
    pub attributes: Option<serde_json::Value>,
}

/// User response (without sensitive data)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    /// Unique identifier for the user
    pub id: Uuid,
    /// Username of the user
    pub username: String,
    /// Email address of the user
    pub email: String,
    /// Whether the email address has been verified
    pub email_verified: bool,
    /// First name of the user
    pub first_name: Option<String>,
    /// Last name of the user
    pub last_name: Option<String>,
    /// Phone number of the user
    pub phone_number: Option<String>,
    /// Whether the phone number has been verified
    pub phone_verified: bool,
    /// Whether WebAuthn is enabled for this user
    pub webauthn_enabled: bool,
    /// Whether the account is currently locked
    pub account_locked: bool,
    /// Timestamp of the last successful login
    pub last_login_at: Option<DateTime<Utc>>,
    /// ID of the realm this user belongs to
    pub realm_id: Option<Uuid>,
    /// ID of the organization this user belongs to
    pub organization_id: Option<Uuid>,
    /// Whether the user account is enabled
    pub enabled: bool,
    /// Timestamp when the user was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the user was last updated
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
            federated: false,
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
            federated: row.try_get("federated")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

/// Federated identity linking a user to an external identity provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentity {
    /// Unique identifier for the federated identity link
    pub id: Uuid,
    /// ID of the user in Authenc
    pub user_id: Uuid,
    /// ID of the identity provider
    pub identity_provider_id: Uuid,
    /// External user ID from the identity provider
    pub external_id: String,
    /// External username from the identity provider
    pub external_username: Option<String>,
    /// External email from the identity provider
    pub external_email: Option<String>,
    /// Additional attributes from the identity provider
    pub external_attributes: Option<serde_json::Value>,
    /// Timestamp of the last login via this identity provider
    pub last_login_at: Option<DateTime<Utc>>,
    /// Timestamp when this link was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when this link was last updated
    pub updated_at: DateTime<Utc>,
}

/// Request to create a federated identity link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFederatedIdentityRequest {
    /// ID of the user in Authenc
    pub user_id: Uuid,
    /// ID of the identity provider
    pub identity_provider_id: Uuid,
    /// External user ID from the identity provider
    pub external_id: String,
    /// External username from the identity provider
    pub external_username: Option<String>,
    /// External email from the identity provider
    pub external_email: Option<String>,
    /// Additional attributes from the identity provider
    pub external_attributes: Option<serde_json::Value>,
}

/// JIT user provisioning request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JITUserProvisioningRequest {
    /// ID of the identity provider
    pub identity_provider_id: Uuid,
    /// External user ID from the identity provider
    pub external_id: String,
    /// External username from the identity provider
    pub external_username: Option<String>,
    /// External email from the identity provider
    pub external_email: Option<String>,
    /// User's first name from the identity provider
    pub first_name: Option<String>,
    /// User's last name from the identity provider
    pub last_name: Option<String>,
    /// Additional attributes from the identity provider
    pub external_attributes: Option<serde_json::Value>,
    /// ID of the realm where the user should be created
    pub realm_id: Uuid,
}

/// JIT user provisioning response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JITUserProvisioningResponse {
    /// The created or existing user
    pub user: User,
    /// Whether a new user was created (true) or existing user was found (false)
    pub created: bool,
    /// The federated identity link
    pub federated_identity: FederatedIdentity,
}
