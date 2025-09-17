use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Session store for managing user authentication sessions
pub struct SessionStore {
    /// token -> user_id mapping
    sessions: Arc<RwLock<HashMap<String, String>>>,
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
}
