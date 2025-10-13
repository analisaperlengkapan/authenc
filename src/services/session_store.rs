use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::database::Database;
use crate::database::operations as db_ops;
use crate::error::AuthencError;
use crate::models::session::Session;

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

    /// Add session token for user
    ///
    /// # Arguments
    /// * `token` - The session token to store
    /// * `user_id` - The user ID associated with the token
    ///
    /// # Returns
    /// * `Ok(())` on successful storage
    /// * `Err(String)` if there's a lock poisoning error
    pub fn add(&self, token: &str, user_id: &str) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        sessions.insert(token.to_string(), user_id.to_string());
        Ok(())
    }

    /// Remove session token
    ///
    /// # Arguments
    /// * `token` - The session token to remove
    ///
    /// # Returns
    /// * `Ok(())` on successful removal
    /// * `Err(String)` if there's a lock poisoning error
    pub fn remove(&self, token: &str) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        sessions.remove(token);
        Ok(())
    }

    /// Get user ID for session token
    ///
    /// # Arguments
    /// * `token` - The session token to look up
    ///
    /// # Returns
    /// * `Ok(Some(String))` containing the user ID if token exists
    /// * `Ok(None)` if token doesn't exist
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_user_id(&self, token: &str) -> Result<Option<String>, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(sessions.get(token).cloned())
    }

    /// Get all session tokens for user
    ///
    /// # Arguments
    /// * `user_id` - The user ID to find sessions for
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` containing all session tokens for the user
    /// * `Err(String)` if there's a lock poisoning error
    pub fn all_for_user(&self, user_id: &str) -> Result<Vec<String>, String> {
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

    /// Get all sessions for a user
    ///
    /// # Arguments
    /// * `user_id` - The user ID to find sessions for
    ///
    /// # Returns
    /// * `Result<Vec<Session>, AuthencError>` containing all sessions for the user
    pub async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AuthencError> {
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

    /// Get a specific session by ID
    ///
    /// # Arguments
    /// * `session_id` - The session ID to retrieve
    ///
    /// # Returns
    /// * `Result<Option<Session>, AuthencError>` containing the session if found
    pub async fn get_session(&self, session_id: Uuid) -> Result<Option<Session>, AuthencError> {
        let full_sessions = self
            .full_sessions
            .read()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        Ok(full_sessions.get(&session_id).cloned())
    }

    /// Delete a specific session
    ///
    /// # Arguments
    /// * `session_id` - The session ID to delete
    ///
    /// # Returns
    /// * `Result<(), AuthencError>` indicating success or failure
    pub async fn delete_session(&self, session_id: Uuid) -> Result<(), AuthencError> {
        let mut full_sessions = self
            .full_sessions
            .write()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        full_sessions.remove(&session_id);
        Ok(())
    }

    /// Delete all sessions for a user
    ///
    /// # Arguments
    /// * `user_id` - The user ID to delete sessions for
    ///
    /// # Returns
    /// * `Result<(), AuthencError>` indicating success or failure
    pub async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthencError> {
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

    /// Store a full session object
    ///
    /// # Arguments
    /// * `session` - The session to store
    ///
    /// # Returns
    /// * `Result<(), AuthencError>` indicating success or failure
    pub async fn store_session(&self, session: Session) -> Result<(), AuthencError> {
        // Store in memory for fast access
        let mut full_sessions = self
            .full_sessions
            .write()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        full_sessions.insert(session.id, session.clone());

        // Also persist to database for durability
        // Note: This assumes the session has a realm_id field that needs to be added to the Session model
        // For now, we'll use a default realm_id or make it optional
        // This is a placeholder - actual implementation needs to handle realm_id properly
        drop(full_sessions); // Release lock before async operation

        Ok(())
    }

    /// Create a new user session with persistence
    ///
    /// # Arguments
    /// * `user_id` - The user ID for the session
    /// * `realm_id` - The realm ID for the session
    /// * `client_id` - Optional client ID
    /// * `token` - The access token
    /// * `refresh_token` - Optional refresh token
    /// * `expires_in` - Session expiration in seconds
    /// * `ip_address` - Optional client IP address
    /// * `user_agent` - Optional user agent string
    /// * `auth_method` - Optional authentication method
    /// * `protocol` - Optional protocol (openid-connect, saml, etc.)
    ///
    /// # Returns
    /// * `Result<Uuid, AuthencError>` with the session ID
    pub async fn create_session(
        &self,
        user_id: Uuid,
        realm_id: Uuid,
        client_id: Option<Uuid>,
        token: &str,
        refresh_token: Option<&str>,
        expires_in: i64,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        auth_method: Option<&str>,
        protocol: Option<&str>,
    ) -> Result<Uuid, AuthencError> {
        let result = db_ops::sessions::create_user_session(
            &self.db,
            user_id,
            realm_id,
            client_id,
            token,
            refresh_token,
            expires_in,
            ip_address,
            user_agent,
            auth_method,
            protocol,
        )
        .await?;

        let session_id = result["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AuthencError::internal("Invalid session ID returned"))?;

        Ok(session_id)
    }

    /// Get session by token
    ///
    /// # Arguments
    /// * `token` - The access token
    ///
    /// # Returns
    /// * `Result<Option<serde_json::Value>, AuthencError>` with session data
    pub async fn get_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError> {
        db_ops::sessions::get_session_by_token(&self.db, token).await
    }

    /// Touch session to update last accessed time
    ///
    /// # Arguments
    /// * `session_id` - The session ID
    ///
    /// # Returns
    /// * `Result<(), AuthencError>`
    pub async fn touch_session_db(&self, session_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::touch_session(&self.db, session_id).await
    }

    /// Rotate refresh token
    ///
    /// # Arguments
    /// * `session_id` - The session ID
    /// * `old_refresh_token` - The old refresh token
    /// * `new_refresh_token` - The new refresh token
    /// * `client_ip` - Optional client IP
    /// * `user_agent` - Optional user agent
    ///
    /// # Returns
    /// * `Result<bool, AuthencError>` - true if rotation succeeded
    pub async fn rotate_refresh_token(
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

    /// Revoke a specific session
    ///
    /// # Arguments
    /// * `session_id` - The session ID to revoke
    /// * `reason` - Optional reason for revocation
    ///
    /// # Returns
    /// * `Result<(), AuthencError>`
    pub async fn revoke_session_db(
        &self,
        session_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(), AuthencError> {
        db_ops::sessions::revoke_session(&self.db, session_id, reason).await
    }

    /// Create offline token
    ///
    /// # Arguments
    /// * `user_id` - The user ID
    /// * `realm_id` - The realm ID
    /// * `client_id` - The client ID
    /// * `token` - The offline token
    /// * `scope` - Optional scope
    /// * `expires_at` - Optional expiration (None = never expires)
    /// * `data` - Optional metadata
    ///
    /// # Returns
    /// * `Result<Uuid, AuthencError>` with the offline token ID
    pub async fn create_offline_token(
        &self,
        user_id: Uuid,
        realm_id: Uuid,
        client_id: Uuid,
        token: &str,
        scope: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        data: Option<serde_json::Value>,
    ) -> Result<Uuid, AuthencError> {
        let result = db_ops::sessions::create_offline_token(
            &self.db, user_id, realm_id, client_id, token, scope, expires_at, data,
        )
        .await?;

        let token_id = result["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AuthencError::internal("Invalid offline token ID returned"))?;

        Ok(token_id)
    }

    /// Get offline token
    ///
    /// # Arguments
    /// * `token` - The offline token
    ///
    /// # Returns
    /// * `Result<Option<serde_json::Value>, AuthencError>` with token data
    pub async fn get_offline_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError> {
        db_ops::sessions::get_offline_token(&self.db, token).await
    }

    /// Touch offline token to update last used time
    ///
    /// # Arguments
    /// * `token_id` - The offline token ID
    ///
    /// # Returns
    /// * `Result<(), AuthencError>`
    pub async fn touch_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::touch_offline_token(&self.db, token_id).await
    }

    /// Revoke offline token
    ///
    /// # Arguments
    /// * `token_id` - The offline token ID
    ///
    /// # Returns
    /// * `Result<(), AuthencError>`
    pub async fn revoke_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::revoke_offline_token(&self.db, token_id).await
    }

    /// Cleanup expired sessions
    ///
    /// # Returns
    /// * `Result<i64, AuthencError>` with count of deleted sessions
    pub async fn cleanup_expired(&self) -> Result<i64, AuthencError> {
        db_ops::sessions::cleanup_expired_sessions(&self.db).await
    }
}
