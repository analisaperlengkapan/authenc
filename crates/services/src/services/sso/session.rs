//! SSO Session Management
//!
//! Manages unified SSO sessions across multiple authentication protocols.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use authenc_api::error::Result;

/// SSO Session representing a unified authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    /// Unique SSO session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: String,
    /// Realm identifier
    pub realm_id: String,
    /// Authentication provider that initiated this SSO session
    pub provider: String,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    pub last_access: DateTime<Utc>,
    /// Session idle timeout (seconds)
    pub idle_timeout: i32,
    /// Session maximum lifespan (seconds)
    pub max_lifespan: i32,
    /// Whether remember me is enabled
    pub remember_me: bool,
    /// Client sessions associated with this SSO session
    pub client_sessions: HashMap<String, ClientSession>,
    /// Session attributes
    pub attributes: HashMap<String, String>,
    /// IP address from which session was created
    pub ip_address: Option<String>,
    /// User agent from which session was created
    pub user_agent: Option<String>,
}

/// Client session within an SSO session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSession {
    /// Client identifier
    pub client_id: String,
    /// Protocol used (oidc, oauth2, saml, social)
    pub protocol: String,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    pub last_access: DateTime<Utc>,
    /// Client-specific session data
    pub data: HashMap<String, String>,
}

/// SSO Session Manager trait
#[async_trait]
pub trait SsoSessionManager: Send + Sync {
    /// Create a new SSO session
    async fn create_session(
        &self,
        user_id: &str,
        realm_id: &str,
        provider: &str,
        idle_timeout: i32,
        max_lifespan: i32,
        remember_me: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SsoSession>;

    /// Get SSO session by session ID
    async fn get_session(&self, session_id: &str) -> Result<Option<SsoSession>>;

    /// Update session last access time
    async fn update_access(&self, session_id: &str) -> Result<()>;

    /// Add client session to SSO session
    async fn add_client_session(
        &self,
        session_id: &str,
        client_id: &str,
        protocol: &str,
        data: HashMap<String, String>,
    ) -> Result<()>;

    /// Remove client session from SSO session
    async fn remove_client_session(&self, session_id: &str, client_id: &str) -> Result<()>;

    /// Check if session is expired
    async fn is_expired(&self, session_id: &str) -> Result<bool>;

    /// Invalidate SSO session (logout)
    async fn invalidate_session(&self, session_id: &str) -> Result<()>;

    /// Get all sessions for a user
    async fn get_user_sessions(&self, user_id: &str, realm_id: &str) -> Result<Vec<SsoSession>>;

    /// Cleanup expired sessions
    async fn cleanup_expired(&self) -> Result<u32>;

    /// Set session attribute
    async fn set_attribute(&self, session_id: &str, key: &str, value: &str) -> Result<()>;

    /// Get session attribute
    async fn get_attribute(&self, session_id: &str, key: &str) -> Result<Option<String>>;
}

/// Default in-memory SSO session manager
pub struct DefaultSsoSessionManager {
    sessions: Arc<RwLock<HashMap<String, SsoSession>>>,
}

impl DefaultSsoSessionManager {
    /// Create a new default SSO session manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for DefaultSsoSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SsoSessionManager for DefaultSsoSessionManager {
    async fn create_session(
        &self,
        user_id: &str,
        realm_id: &str,
        provider: &str,
        idle_timeout: i32,
        max_lifespan: i32,
        remember_me: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SsoSession> {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = SsoSession {
            session_id: session_id.clone(),
            user_id: user_id.to_string(),
            realm_id: realm_id.to_string(),
            provider: provider.to_string(),
            created_at: now,
            last_access: now,
            idle_timeout,
            max_lifespan,
            remember_me,
            client_sessions: HashMap::new(),
            attributes: HashMap::new(),
            ip_address,
            user_agent,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session.clone());

        Ok(session)
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SsoSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn update_access(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_access = Utc::now();
        }
        Ok(())
    }

    async fn add_client_session(
        &self,
        session_id: &str,
        client_id: &str,
        protocol: &str,
        data: HashMap<String, String>,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            let now = Utc::now();
            session.client_sessions.insert(
                client_id.to_string(),
                ClientSession {
                    client_id: client_id.to_string(),
                    protocol: protocol.to_string(),
                    created_at: now,
                    last_access: now,
                    data,
                },
            );
        }
        Ok(())
    }

    async fn remove_client_session(&self, session_id: &str, client_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.client_sessions.remove(client_id);
        }
        Ok(())
    }

    async fn is_expired(&self, session_id: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            let now = Utc::now();
            let created_duration = (now - session.created_at).num_seconds();
            let idle_duration = (now - session.last_access).num_seconds();

            // Check max lifespan
            if created_duration > session.max_lifespan as i64 {
                return Ok(true);
            }

            // Check idle timeout
            if idle_duration > session.idle_timeout as i64 {
                return Ok(true);
            }

            Ok(false)
        } else {
            Ok(true) // Session not found = expired
        }
    }

    async fn invalidate_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &str, realm_id: &str) -> Result<Vec<SsoSession>> {
        let sessions = self.sessions.read().await;
        let user_sessions: Vec<SsoSession> = sessions
            .values()
            .filter(|s| s.user_id == user_id && s.realm_id == realm_id)
            .cloned()
            .collect();
        Ok(user_sessions)
    }

    async fn cleanup_expired(&self) -> Result<u32> {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        let initial_count = sessions.len();

        sessions.retain(|_, session| {
            let created_duration = (now - session.created_at).num_seconds();
            let idle_duration = (now - session.last_access).num_seconds();

            // Keep session if not expired
            created_duration <= session.max_lifespan as i64
                && idle_duration <= session.idle_timeout as i64
        });

        let removed = (initial_count - sessions.len()) as u32;
        Ok(removed)
    }

    async fn set_attribute(&self, session_id: &str, key: &str, value: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session
                .attributes
                .insert(key.to_string(), value.to_string());
        }
        Ok(())
    }

    async fn get_attribute(&self, session_id: &str, key: &str) -> Result<Option<String>> {
        let sessions = self.sessions.read().await;
        Ok(sessions
            .get(session_id)
            .and_then(|s| s.attributes.get(key))
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_get_session() {
        let manager = DefaultSsoSessionManager::new();
        let session = manager
            .create_session(
                "user123",
                "realm456",
                "oidc",
                1800,
                36000,
                false,
                Some("192.168.1.1".to_string()),
                Some("Mozilla/5.0".to_string()),
            )
            .await
            .unwrap();

        let retrieved = manager.get_session(&session.session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
    }

    #[tokio::test]
    async fn test_session_expiration() {
        let manager = DefaultSsoSessionManager::new();
        let session = manager
            .create_session(
                "user123", "realm456", "oidc", -1, // Expired immediately
                36000, false, None, None,
            )
            .await
            .unwrap();

        let is_expired = manager.is_expired(&session.session_id).await.unwrap();
        assert!(is_expired);
    }

    #[tokio::test]
    async fn test_client_session_management() {
        let manager = DefaultSsoSessionManager::new();
        let session = manager
            .create_session(
                "user123", "realm456", "oidc", 1800, 36000, false, None, None,
            )
            .await
            .unwrap();

        let mut data = HashMap::new();
        data.insert("scope".to_string(), "openid profile".to_string());

        manager
            .add_client_session(&session.session_id, "client1", "oidc", data)
            .await
            .unwrap();

        let updated = manager.get_session(&session.session_id).await.unwrap();
        assert!(updated.is_some());
        assert_eq!(updated.unwrap().client_sessions.len(), 1);
    }
}
