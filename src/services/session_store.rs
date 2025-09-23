use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::models::session::Session;
use crate::error::AuthencError;

/// Session store for managing user authentication sessions
pub struct SessionStore {
    /// token -> user_id mapping (for backward compatibility)
    sessions: Arc<RwLock<HashMap<String, String>>>,
    /// session_id -> Session mapping
    full_sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    /// Create new session store for managing authentication sessions
    pub fn new() -> Self {
        SessionStore {
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

    /// Store a full session object
    ///
    /// # Arguments
    /// * `session` - The session to store
    ///
    /// # Returns
    /// * `Result<(), AuthencError>` indicating success or failure
    pub async fn store_session(&self, session: Session) -> Result<(), AuthencError> {
        let mut full_sessions = self
            .full_sessions
            .write()
            .map_err(|_| AuthencError::internal("Lock poisoned"))?;

        full_sessions.insert(session.id, session);
        Ok(())
    }
}
