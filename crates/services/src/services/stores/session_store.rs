use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use authenc_db::database::Database;
use authenc_db::database::operations as db_ops;
use authenc_api::error::AuthencError;
use authenc_api::models::session::Session;

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
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
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

/// Session store for managing user authentication sessions
pub struct SessionStore {
    /// Database connection
    db: Arc<Database>,
    /// token -> user_id mapping (for backward compatibility with in-memory)
    sessions: Arc<RwLock<HashMap<String, String>>>,
    /// session_id -> Session mapping (for backward compatibility with in-memory)
    full_sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
}

impl SessionStore {
    /// Create new session store for managing authentication sessions
    pub fn new(db: Arc<Database>) -> Self {
        SessionStore {
            db,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            full_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SessionStoreTrait for SessionStore {
    fn add(&self, token: &str, user_id: &str) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        sessions.insert(token.to_string(), user_id.to_string());
        Ok(())
    }

    fn remove(&self, token: &str) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        sessions.remove(token);
        Ok(())
    }

    fn get_user_id(&self, token: &str) -> Result<Option<String>, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(sessions.get(token).cloned())
    }

    fn all_for_user(&self, user_id: &str) -> Result<Vec<String>, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(sessions
            .iter()
            .filter_map(|(token, uid)| {
                if uid == user_id {
                    Some(token.clone())
                } else {
                    None
                }
            })
            .collect())
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AuthencError> {
        let full_sessions = self
            .full_sessions
            .read()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        let user_sessions = full_sessions
            .values()
            .filter(|session| session.user_id == user_id && !session.revoked)
            .cloned()
            .collect();

        Ok(user_sessions)
    }

    async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, AuthencError> {
        let full_sessions = self
            .full_sessions
            .read()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        Ok(full_sessions.get(&session_id).cloned())
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), AuthencError> {
        let mut full_sessions = self
            .full_sessions
            .write()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        full_sessions.remove(&session_id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthencError> {
        let mut full_sessions = self
            .full_sessions
            .write()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        // Remove all sessions for this user
        full_sessions.retain(|_, session| session.user_id != user_id);

        // Also clean up the old token-based sessions
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        sessions.retain(|_, uid| uid != &user_id.to_string());

        Ok(())
    }

    async fn store_session(&self, session: Session) -> Result<(), AuthencError> {
        // Store in memory for fast access
        {
            let mut full_sessions = self
                .full_sessions
                .write()
                .map_err(|_| AuthencError::internal("Lock poisoned"))?;

            full_sessions.insert(session.id, session.clone());
        } // Drop lock explicitly before async operation

        // Also persist to database for durability
        db_ops::sessions::store_session(&self.db, &session).await?;

        Ok(())
    }

    async fn create_session(
        &self,
        params: CreateSessionParams<'_>,
    ) -> Result<Uuid, AuthencError> {
        let result = db_ops::sessions::create_user_session(
            &self.db,
            params.user_id,
            params.realm_id,
            params.client_id,
            params.token,
            params.refresh_token,
            params.expires_in,
            params.ip_address,
            params.user_agent,
            params.auth_method,
            params.protocol,
        )
        .await?;

        let session_id = result["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AuthencError::internal("Invalid session ID returned"))?;

        Ok(session_id)
    }

    async fn get_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError> {
        db_ops::sessions::get_session_by_token(&self.db, token).await
    }

    async fn touch_session_db(&self, session_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::touch_session(&self.db, session_id).await
    }

    async fn rotate_refresh_token(
        &self,
        session_id: Uuid,
        old_refresh_token: &str,
        new_refresh_token: &str,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<bool, AuthencError> {
        db_ops::sessions::rotate_refresh_token(
            &self.db,
            session_id,
            old_refresh_token,
            new_refresh_token,
            client_ip,
            user_agent,
        )
        .await
    }

    async fn revoke_session_db(
        &self,
        session_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(), AuthencError> {
        db_ops::sessions::revoke_session(&self.db, session_id, reason).await
    }

    async fn create_offline_token(
        &self,
        params: CreateOfflineTokenParams<'_>,
    ) -> Result<Uuid, AuthencError> {
        let result = db_ops::sessions::create_offline_token(
            &self.db,
            params.user_id,
            params.realm_id,
            params.client_id,
            params.token,
            params.scope,
            params.expires_at,
            params.data,
        )
        .await?;

        let token_id = result["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AuthencError::internal("Invalid offline token ID returned"))?;

        Ok(token_id)
    }

    async fn get_offline_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError> {
        db_ops::sessions::get_offline_token(&self.db, token).await
    }

    async fn touch_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::touch_offline_token(&self.db, token_id).await
    }

    async fn revoke_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::revoke_offline_token(&self.db, token_id).await
    }

    async fn cleanup_expired(&self) -> Result<i64, AuthencError> {
        db_ops::sessions::cleanup_expired_sessions(&self.db).await
    }
}
