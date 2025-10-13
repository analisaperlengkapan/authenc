//! Authentication Manager
//!
//! Provides authentication session management, flow processing,
//! and authentication state coordination.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{AuthencError as Error, Result};
use crate::spi::authenticator::{AuthenticationResult, AuthenticatorProvider, AuthenticatorType};

/// Authentication session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSessionState {
    /// Unique session identifier
    pub session_id: String,
    /// Realm identifier
    pub realm_id: String,
    /// Client identifier
    pub client_id: String,
    /// User identifier if authenticated
    pub user_id: Option<String>,
    /// Authentication flow type
    pub flow_type: String,
    /// Authentication flow identifier
    pub flow_id: String,
    /// Execution states for flow steps
    pub execution_states: HashMap<String, ExecutionState>,
    /// Authentication notes
    pub auth_note: HashMap<String, String>,
    /// Client-specific notes
    pub client_note: HashMap<String, String>,
    /// User session notes
    pub user_session_note: HashMap<String, String>,
    /// Required actions for user
    pub required_actions: Vec<String>,
    /// Session creation timestamp
    pub timestamp: i64,
}

/// State of an authentication execution step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionState {
    /// Execution identifier
    pub execution_id: String,
    /// Execution requirement type
    pub requirement: String,
    /// Execution status
    pub status: String,
}

/// Authentication manager for coordinating authentication flows
#[async_trait]
pub trait AuthenticationManager: Send + Sync {
    /// Create a new authentication session
    async fn create_authentication_session(
        &self,
        realm_id: &str,
        client_id: &str,
        flow_type: &str,
        flow_id: &str,
    ) -> Result<String>;

    /// Get authentication session by ID
    async fn get_authentication_session(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthenticationSessionState>>;

    /// Update authentication session
    async fn update_authentication_session(
        &self,
        session: AuthenticationSessionState,
    ) -> Result<()>;

    /// Remove authentication session
    async fn remove_authentication_session(&self, session_id: &str) -> Result<()>;

    /// Authenticate user with credentials
    async fn authenticate_user(
        &self,
        realm_id: &str,
        username: &str,
        password: &str,
        client_id: &str,
    ) -> Result<AuthenticationResult>;

    /// Process authentication flow
    async fn process_flow(
        &self,
        session_id: &str,
        authenticator_provider: &dyn AuthenticatorProvider,
    ) -> Result<AuthenticationResult>;

    /// Create user session after successful authentication
    async fn create_user_session(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        auth_result: &AuthenticationResult,
    ) -> Result<String>;

    /// Validate authentication session
    async fn validate_session(&self, session_id: &str) -> Result<bool>;
}

/// Default authentication manager implementation
pub struct DefaultAuthenticationManager {
    sessions: Arc<tokio::sync::RwLock<HashMap<String, AuthenticationSessionState>>>,
    database: Arc<crate::database::Database>,
}

impl DefaultAuthenticationManager {
    /// Create a new default authentication manager
    pub fn new(database: Arc<crate::database::Database>) -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            database,
        }
    }
}

#[async_trait]
impl AuthenticationManager for DefaultAuthenticationManager {
    async fn create_authentication_session(
        &self,
        realm_id: &str,
        client_id: &str,
        flow_type: &str,
        flow_id: &str,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = AuthenticationSessionState {
            session_id: session_id.clone(),
            realm_id: realm_id.to_string(),
            client_id: client_id.to_string(),
            user_id: None,
            flow_type: flow_type.to_string(),
            flow_id: flow_id.to_string(),
            execution_states: HashMap::new(),
            auth_note: HashMap::new(),
            client_note: HashMap::new(),
            user_session_note: HashMap::new(),
            required_actions: vec![],
            timestamp: chrono::Utc::now().timestamp(),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    async fn get_authentication_session(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthenticationSessionState>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn update_authentication_session(
        &self,
        session: AuthenticationSessionState,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    async fn remove_authentication_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn authenticate_user(
        &self,
        realm_id: &str,
        username: &str,
        password: &str,
        client_id: &str,
    ) -> Result<AuthenticationResult> {
        // Create authentication session
        let session_id = self
            .create_authentication_session(realm_id, client_id, "browser", "browser")
            .await?;

        // Load user from database
        let user_opt =
            crate::database::operations::users::get_user_by_username(&self.database, username)
                .await?;

        // Check if user exists and password is valid
        let (success, error_message) = if let Some(ref u) = user_opt {
            if !u.enabled {
                (false, Some("User is disabled".to_string()))
            } else if let Some(ref hash) = u.password_hash {
                // Validate password hash against stored hash
                match crate::utils::crypto::password::verify_password(hash, password) {
                    Ok(true) => (true, None),
                    Ok(false) => (false, Some("Invalid username or password".to_string())),
                    Err(_) => (false, Some("Password verification failed".to_string())),
                }
            } else {
                // No password hash stored (federated user or passwordless)
                (
                    false,
                    Some("Password authentication not available for this user".to_string()),
                )
            }
        } else {
            (false, Some("Invalid username or password".to_string()))
        };

        // Wrap user in Arc if present
        let user = user_opt.map(Arc::new);

        let result = AuthenticationResult {
            success,
            user,
            authenticator_type: AuthenticatorType::UsernamePassword,
            auth_data: HashMap::new(),
            error_message,
        };

        Ok(result)
    }

    async fn process_flow(
        &self,
        session_id: &str,
        _authenticator_provider: &dyn AuthenticatorProvider,
    ) -> Result<AuthenticationResult> {
        let session = self
            .get_authentication_session(session_id)
            .await?
            .ok_or_else(|| Error::unauthorized("Authentication session not found"))?;

        // Load user if we have a user_id in the session
        let user_opt = if let Some(ref user_id_str) = session.user_id {
            // Parse user_id as UUID
            if let Ok(user_id) = uuid::Uuid::parse_str(user_id_str) {
                crate::database::operations::users::get_user_by_id(&self.database, user_id).await?
            } else {
                None
            }
        } else {
            None
        };

        // Wrap user in Arc if present
        let user = user_opt.map(Arc::new);

        // For now, return success
        // In a real implementation, this would process the authentication flow
        let result = AuthenticationResult {
            success: true,
            user,
            authenticator_type: AuthenticatorType::UsernamePassword,
            auth_data: session.auth_note.clone(),
            error_message: None,
        };

        Ok(result)
    }

    async fn create_user_session(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _client_id: &str,
        _auth_result: &AuthenticationResult,
    ) -> Result<String> {
        // In a real implementation, this would create a user session
        // For now, return a mock session ID
        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn validate_session(&self, session_id: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        Ok(sessions.contains_key(session_id))
    }
}

// Default implementation removed - requires database parameter
// Use DefaultAuthenticationManager::new(database) instead
