impl Default for TotpStore {
    fn default() -> Self {
        Self::new()
    }
}
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// TOTP (Time-based One-Time Password) store for managing user TOTP secrets
pub struct TotpStore {
    /// user_id -> base32 secret mapping
    secrets: Arc<RwLock<HashMap<String, String>>>,
    /// user_id -> hashed backup codes mapping
    backup_codes: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// user_id -> configured timestamp mapping
    configured_at: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl TotpStore {
    /// Create new TOTP store for managing Time-based One-Time Password secrets
    pub fn new() -> Self {
        TotpStore {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            backup_codes: Arc::new(RwLock::new(HashMap::new())),
            configured_at: Arc::new(RwLock::new(HashMap::new())),
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

        // Also set the configured timestamp
        let mut configured_at = self
            .configured_at
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        configured_at.insert(user_id.to_string(), Utc::now());

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

        // Also remove configured timestamp
        let mut configured_at = self
            .configured_at
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        configured_at.remove(user_id);

        Ok(())
    }

    /// Set backup codes for user (hashed)
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    /// * `codes` - Vector of hashed backup codes
    ///
    /// # Returns
    /// * `Ok(())` on successful storage
    /// * `Err(String)` if there's a lock poisoning error
    pub fn set_backup_codes(&self, user_id: &str, codes: Vec<String>) -> Result<(), String> {
        let mut backup_codes = self
            .backup_codes
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        backup_codes.insert(user_id.to_string(), codes);
        Ok(())
    }

    /// Get backup codes for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(Some(Vec<String>))` containing the hashed backup codes if they exist
    /// * `Ok(None)` if no backup codes are found for the user
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_backup_codes(&self, user_id: &str) -> Result<Option<Vec<String>>, String> {
        let backup_codes = self
            .backup_codes
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(backup_codes.get(user_id).cloned())
    }

    /// Remove backup codes for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(())` on successful removal
    /// * `Err(String)` if there's a lock poisoning error
    pub fn remove_backup_codes(&self, user_id: &str) -> Result<(), String> {
        let mut backup_codes = self
            .backup_codes
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        backup_codes.remove(user_id);
        Ok(())
    }

    /// Get TOTP configured timestamp for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(Some(DateTime<Utc>))` containing the configured timestamp if it exists
    /// * `Ok(None)` if no timestamp is found for the user
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_configured_at(&self, user_id: &str) -> Result<Option<DateTime<Utc>>, String> {
        let configured_at = self
            .configured_at
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(configured_at.get(user_id).cloned())
    }

    /// Verify and consume a backup code
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    /// * `code` - The backup code to verify (plain text)
    ///
    /// # Returns
    /// * `Ok(true)` if the code was valid and consumed
    /// * `Ok(false)` if the code was invalid
    /// * `Err(String)` if there's a lock poisoning error
    pub fn verify_backup_code(&self, user_id: &str, code: &str) -> Result<bool, String> {
        let mut backup_codes = self
            .backup_codes
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;

        if let Some(codes) = backup_codes.get_mut(user_id) {
            // Hash the input code for comparison (simple hash for demo)
            use sha2::{Digest, Sha256};
            let hashed_input = format!("{:x}", Sha256::digest(code.as_bytes()));

            // Find and remove the matching code
            if let Some(pos) = codes.iter().position(|c| c == &hashed_input) {
                codes.remove(pos);
                return Ok(true);
            }
        }
        Ok(false)
    }
}
