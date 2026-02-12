//! User Session Manager
//!
//! Manages user sessions, session lifecycle, and cross-DC session management.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use authenc_core::error::{AuthencError as Error, Result};

/// User session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionState {
    /// Unique session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: String,
    /// Realm identifier
    pub realm_id: String,
    /// Session creation timestamp
    pub created_at: i64,
    /// Last access timestamp
    pub last_access: i64,
    /// Session expiration timestamp
    pub expires_at: i64,
    /// Client sessions associated with this user session
    pub client_sessions: HashMap<String, ClientSessionState>,
    /// Session notes
    pub notes: HashMap<String, String>,
    /// Whether this is an offline session
    pub is_offline: bool,
}

/// State of a client session within a user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSessionState {
    /// Client identifier
    pub client_id: String,
    /// Session identifier
    pub session_id: String,
    /// Client session creation timestamp
    pub created_at: i64,
    /// Last access timestamp for this client session
    pub last_access: i64,
    /// Client session expiration timestamp
    pub expires_at: i64,
    /// Client session notes
    pub notes: HashMap<String, String>,
}

/// User session manager for managing user sessions
#[async_trait]
pub trait UserSessionManager: Send + Sync {
    /// Create a new user session
    async fn create_user_session(
        &self,
        user_id: &str,
        realm_id: &str,
        is_offline: bool,
    ) -> Result<String>;

    /// Get user session by ID
    async fn get_user_session(&self, session_id: &str) -> Result<Option<UserSessionState>>;

    /// Update user session last access time
    async fn update_session_access(&self, session_id: &str) -> Result<()>;

    /// Remove user session
    async fn remove_user_session(&self, session_id: &str) -> Result<()>;

    /// Get user sessions for a user
    async fn get_user_sessions(
        &self,
        user_id: &str,
        realm_id: &str,
    ) -> Result<Vec<UserSessionState>>;

    /// Create client session for user session
    async fn create_client_session(&self, user_session_id: &str, client_id: &str)
    -> Result<String>;

    /// Get client session
    async fn get_client_session(
        &self,
        user_session_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientSessionState>>;

    /// Remove client session
    async fn remove_client_session(&self, user_session_id: &str, client_id: &str) -> Result<()>;

    /// Check if session is expired
    async fn is_session_expired(&self, session_id: &str) -> Result<bool>;

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) -> Result<i32>;
}

/// Default user session manager implementation
pub struct DefaultUserSessionManager {
    sessions: Arc<tokio::sync::RwLock<HashMap<String, UserSessionState>>>,
    session_timeout: Duration,
    offline_session_timeout: Duration,
}

impl DefaultUserSessionManager {
    /// Create a new default user session manager with default timeouts
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            session_timeout: Duration::from_secs(3600), // 1 hour
            offline_session_timeout: Duration::from_secs(30 * 24 * 3600), // 30 days
        }
    }

    /// Create a new default user session manager with custom timeouts
    pub fn with_timeouts(session_timeout: Duration, offline_session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            session_timeout,
            offline_session_timeout,
        }
    }

    fn calculate_expiry(&self, is_offline: bool) -> i64 {
        let timeout = if is_offline {
            self.offline_session_timeout
        } else {
            self.session_timeout
        };

        (chrono::Utc::now() + chrono::Duration::from_std(timeout).unwrap()).timestamp()
    }
}

#[async_trait]
impl UserSessionManager for DefaultUserSessionManager {
    async fn create_user_session(
        &self,
        user_id: &str,
        realm_id: &str,
        is_offline: bool,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        let session = UserSessionState {
            session_id: session_id.clone(),
            user_id: user_id.to_string(),
            realm_id: realm_id.to_string(),
            created_at: now,
            last_access: now,
            expires_at: self.calculate_expiry(is_offline),
            client_sessions: HashMap::new(),
            notes: HashMap::new(),
            is_offline,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    async fn get_user_session(&self, session_id: &str) -> Result<Option<UserSessionState>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn update_session_access(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_access = chrono::Utc::now().timestamp();
            session.expires_at = self.calculate_expiry(session.is_offline);
        }
        Ok(())
    }

    async fn remove_user_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn get_user_sessions(
        &self,
        user_id: &str,
        realm_id: &str,
    ) -> Result<Vec<UserSessionState>> {
        let sessions = self.sessions.read().await;
        let user_sessions = sessions
            .values()
            .filter(|s| s.user_id == user_id && s.realm_id == realm_id)
            .cloned()
            .collect();
        Ok(user_sessions)
    }

    async fn create_client_session(
        &self,
        user_session_id: &str,
        client_id: &str,
    ) -> Result<String> {
        let client_session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        let client_session = ClientSessionState {
            client_id: client_id.to_string(),
            session_id: client_session_id.clone(),
            created_at: now,
            last_access: now,
            expires_at: self.calculate_expiry(false), // Client sessions use regular timeout
            notes: HashMap::new(),
        };

        let mut sessions = self.sessions.write().await;
        if let Some(user_session) = sessions.get_mut(user_session_id) {
            user_session
                .client_sessions
                .insert(client_id.to_string(), client_session);
        } else {
            return Err(Error::resource_not_found("User session not found"));
        }

        Ok(client_session_id)
    }

    async fn get_client_session(
        &self,
        user_session_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientSessionState>> {
        let sessions = self.sessions.read().await;
        if let Some(user_session) = sessions.get(user_session_id) {
            Ok(user_session.client_sessions.get(client_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn remove_client_session(&self, user_session_id: &str, client_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(user_session) = sessions.get_mut(user_session_id) {
            user_session.client_sessions.remove(client_id);
        }
        Ok(())
    }

    async fn is_session_expired(&self, session_id: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            let now = chrono::Utc::now().timestamp();
            Ok(session.expires_at < now)
        } else {
            Ok(true) // Non-existent session is considered expired
        }
    }

    async fn cleanup_expired_sessions(&self) -> Result<i32> {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now().timestamp();
        let initial_count = sessions.len();

        sessions.retain(|_, session| session.expires_at >= now);

        let removed_count = (initial_count - sessions.len()) as i32;
        Ok(removed_count)
    }
}

impl Default for DefaultUserSessionManager {
    fn default() -> Self {
        Self::new()
    }
}
