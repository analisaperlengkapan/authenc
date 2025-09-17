impl Default for TotpStore {
    fn default() -> Self {
        Self::new()
    }
}
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// TOTP (Time-based One-Time Password) store for managing user TOTP secrets
pub struct TotpStore {
    /// user_id -> base32 secret mapping
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

impl TotpStore {
    /// Create new TOTP store for managing Time-based One-Time Password secrets
    pub fn new() -> Self {
        TotpStore {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set TOTP secret for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    /// * `secret` - The base32-encoded TOTP secret
    ///
    /// # Returns
    /// * `Ok(())` on successful storage
    /// * `Err(String)` if there's a lock poisoning error
    pub fn set_secret(&self, user_id: &str, secret: &str) -> Result<(), String> {
        let mut secrets = self
            .secrets
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        secrets.insert(user_id.to_string(), secret.to_string());
        Ok(())
    }

    /// Get TOTP secret for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(Some(String))` containing the base32-encoded secret if it exists
    /// * `Ok(None)` if no secret is found for the user
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_secret(&self, user_id: &str) -> Result<Option<String>, String> {
        let secrets = self
            .secrets
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(secrets.get(user_id).cloned())
    }

    /// Remove TOTP secret for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(())` on successful removal
    /// * `Err(String)` if there's a lock poisoning error
    pub fn remove_secret(&self, user_id: &str) -> Result<(), String> {
        let mut secrets = self
            .secrets
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        secrets.remove(user_id);
        Ok(())
    }
}
