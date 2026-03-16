//! Store trait definitions for SPI
//!
//! These traits define the interfaces for data stores used by SPI providers.
//! Concrete implementations live in authenc-services.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

use authenc_core::error::AuthencError;
use authenc_models::models::group::Group;
use authenc_models::models::oidc_client::OidcClient;
use authenc_models::models::role::Role;
use authenc_models::models::session::Session;
use authenc_models::models::user::{CreateUserRequest, UpdateUserRequest, User};

// ============================================================
// User Store Trait
// ============================================================

/// Trait for user store operations
#[async_trait]
pub trait UserStoreTrait: Send + Sync {
    /// Get user by ID
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AuthencError>;

    /// Get user by username
    async fn get_user_by_username(
        &self,
        realm_id: &Uuid,
        username: &str,
    ) -> Result<Option<User>, AuthencError>;

    /// Get user by email
    async fn get_user_by_email(
        &self,
        realm_id: &Uuid,
        email: &str,
    ) -> Result<Option<User>, AuthencError>;

    /// Create a new user
    async fn add_user(&self, request: CreateUserRequest) -> Result<User, AuthencError>;

    /// Update user
    async fn update_user(
        &self,
        user_id: Uuid,
        request: UpdateUserRequest,
    ) -> Result<User, AuthencError>;

    /// Delete user (soft delete)
    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthencError>;

    /// Get all users
    async fn get_all(&self) -> Result<Vec<User>, AuthencError>;

    /// Get users by realm
    async fn get_users_by_realm(&self, realm_id: Uuid) -> Result<Vec<User>, AuthencError>;

    /// Update user password
    async fn update_password(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthencError>;

    /// Record successful login
    async fn record_login(&self, user_id: Uuid) -> Result<(), AuthencError>;

    /// Record failed login attempt and return new count
    async fn record_failed_login(&self, user_id: Uuid) -> Result<i32, AuthencError>;

    /// Lock user account
    async fn lock_account(
        &self,
        user_id: Uuid,
        until: Option<DateTime<Utc>>,
    ) -> Result<(), AuthencError>;

    /// Unlock user account
    async fn unlock_account(&self, user_id: Uuid) -> Result<(), AuthencError>;

    /// Set password reset token for a user
    async fn set_reset_token(
        &self,
        _user_id: Uuid,
        _token_hash: Option<String>,
        _expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), AuthencError> {
        Err(AuthencError::not_implemented("Method not implemented"))
    }

    /// Get user by password reset token
    async fn get_user_by_reset_token(
        &self,
        _token_hash: &str,
    ) -> Result<Option<User>, AuthencError> {
        Err(AuthencError::not_implemented("Method not implemented"))
    }

    /// Reset password and clear reset token atomically
    async fn reset_password_transaction(
        &self,
        _user_id: Uuid,
        _password_hash: String,
        _token_hash: String,
    ) -> Result<(), AuthencError> {
        Err(AuthencError::not_implemented("Method not implemented"))
    }

    /// Set verification token for a user
    async fn set_verification_token(
        &self,
        _user_id: Uuid,
        _token_hash: Option<String>,
        _expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), AuthencError> {
        Err(AuthencError::not_implemented("Method not implemented"))
    }

    /// Get user by verification token
    async fn get_user_by_verification_token(
        &self,
        _token_hash: &str,
    ) -> Result<Option<User>, AuthencError> {
        Err(AuthencError::not_implemented("Method not implemented"))
    }

    /// Verify email transaction (clear token, set verified=true)
    async fn verify_email_transaction(
        &self,
        _user_id: Uuid,
        _token_hash: String,
    ) -> Result<(), AuthencError> {
        Err(AuthencError::not_implemented("Method not implemented"))
    }
}

// ============================================================
// Session Store Trait
// ============================================================

/// Parameters for creating a session
pub struct CreateSessionParams<'a> {
    /// User ID
    pub user_id: Uuid,
    /// Realm ID
    pub realm_id: Uuid,
    /// Client ID
    pub client_id: Option<Uuid>,
    /// Access token
    pub token: &'a str,
    /// Refresh token
    pub refresh_token: Option<&'a str>,
    /// Expiration time in seconds
    pub expires_in: i64,
    /// Client IP address
    pub ip_address: Option<&'a str>,
    /// User agent string
    pub user_agent: Option<&'a str>,
    /// Authentication method
    pub auth_method: Option<&'a str>,
    /// Protocol used (e.g., openid-connect)
    pub protocol: Option<&'a str>,
}

/// Parameters for creating an offline token
pub struct CreateOfflineTokenParams<'a> {
    /// User ID
    pub user_id: Uuid,
    /// Realm ID
    pub realm_id: Uuid,
    /// Client ID
    pub client_id: Uuid,
    /// Offline token string
    pub token: &'a str,
    /// Scopes granted
    pub scope: Option<&'a str>,
    /// Expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Additional metadata
    pub data: Option<serde_json::Value>,
}

/// Trait for session store operations
#[async_trait]
pub trait SessionStoreTrait: Send + Sync {
    /// Add session token for user
    fn add(&self, token: &str, user_id: &str) -> Result<(), String>;

    /// Remove session token
    fn remove(&self, token: &str) -> Result<(), String>;

    /// Get user ID for session token
    fn get_user_id(&self, token: &str) -> Result<Option<String>, String>;

    /// Get all session tokens for user
    fn all_for_user(&self, user_id: &str) -> Result<Vec<String>, String>;

    /// Get all sessions for a user
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AuthencError>;

    /// Get a specific session by ID
    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, AuthencError>;

    /// Delete a specific session
    async fn delete_session(&self, session_id: Uuid) -> Result<(), AuthencError>;

    /// Delete all sessions for a user
    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthencError>;

    /// Store a full session object
    async fn store_session(&self, session: Session) -> Result<(), AuthencError>;

    /// Create a new user session with persistence
    async fn create_session(
        &self,
        params: CreateSessionParams<'_>,
    ) -> Result<Uuid, AuthencError>;

    /// Get session by token
    async fn get_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError>;

    /// Touch session to update last accessed time
    async fn touch_session_db(&self, session_id: Uuid) -> Result<(), AuthencError>;

    /// Rotate refresh token
    async fn rotate_refresh_token(
        &self,
        session_id: Uuid,
        old_refresh_token: &str,
        new_refresh_token: &str,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<bool, AuthencError>;

    /// Revoke a specific session
    async fn revoke_session_db(
        &self,
        session_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(), AuthencError>;

    /// Create offline token
    async fn create_offline_token(
        &self,
        params: CreateOfflineTokenParams<'_>,
    ) -> Result<Uuid, AuthencError>;

    /// Get offline token
    async fn get_offline_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError>;

    /// Touch offline token to update last used time
    async fn touch_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError>;

    /// Revoke offline token
    async fn revoke_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError>;

    /// Cleanup expired sessions
    async fn cleanup_expired(&self) -> Result<i64, AuthencError>;
}

// ============================================================
// OIDC Client Store Trait
// ============================================================

/// Trait for OIDC client store operations
#[async_trait]
pub trait OidcClientStoreTrait: Send + Sync {
    /// Get client by client ID
    async fn get(&self, client_id: &str) -> Result<Option<OidcClient>, AuthencError>;

    /// Get all clients
    async fn all(&self) -> Result<Vec<OidcClient>, AuthencError>;

    /// Add a new client
    async fn add(&self, client: OidcClient) -> Result<(), AuthencError>;

    /// Update a client
    async fn update(&self, client: OidcClient) -> Result<(), AuthencError>;

    /// Delete a client by client ID
    async fn delete(&self, client_id: &str) -> Result<bool, AuthencError>;
}

// ============================================================
// Role Store Trait
// ============================================================

/// Trait for role store operations
pub trait RoleStoreTrait: Send + Sync {
    /// Get role by name
    fn get_by_name(&self, name: &str) -> Option<Role>;

    /// Get all roles
    fn get_all(&self) -> Arc<Vec<Role>>;

    /// Add a role
    fn add_role(&self, role: Role);

    /// Update an existing role
    fn update_role(&self, role: Role) -> Result<(), String>;

    /// Delete a role by name within a realm
    fn delete_by_name(&self, name: &str, realm_id: &str) -> Result<(), String>;

    /// Get all roles for a specific realm
    fn get_by_realm(&self, realm_id: &str) -> Vec<Role>;
}

// ============================================================
// Group Store Trait
// ============================================================

/// Trait for group store operations
pub trait GroupStoreTrait: Send + Sync {
    /// Get group by ID
    fn get(&self, id: &Uuid) -> Option<Group>;

    /// Get all groups
    fn all(&self) -> Vec<Group>;

    /// Create a new group
    fn create(
        &self,
        realm_id: Uuid,
        name: &str,
        description: Option<String>,
    ) -> Option<Group>;

    /// Delete a group by ID
    fn delete(&self, id: &Uuid) -> bool;
}

// ============================================================
// Event Persistence Trait
// ============================================================

use crate::spi::events::{AdminEventQuery, EventQuery};

/// Trait for persisting events to storage
///
/// This trait abstracts the event persistence layer so that the SPI
/// events module does not need to depend directly on the database crate.
#[async_trait]
pub trait EventPersistenceProvider: Send + Sync {
    /// Store a user event
    async fn store_event(
        &self,
        event: &authenc_models::models::events::Event,
    ) -> Result<(), AuthencError>;

    /// Store an admin event
    async fn store_admin_event(
        &self,
        event: &authenc_models::models::events::AdminEvent,
    ) -> Result<(), AuthencError>;

    /// Query user events
    async fn query_events(
        &self,
        query: &EventQuery,
    ) -> Result<Vec<authenc_models::models::events::Event>, AuthencError>;

    /// Query admin events
    async fn query_admin_events(
        &self,
        query: &AdminEventQuery,
    ) -> Result<Vec<authenc_models::models::events::AdminEvent>, AuthencError>;
}
