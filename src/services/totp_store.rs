use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Internal struct to hold TOTP data
#[derive(Clone)]
struct TotpEntry {
    secret: String,
    created_at: DateTime<Utc>,
}

/// TOTP (Time-based One-Time Password) store for managing user TOTP secrets
pub struct TotpStore {
    /// user_id -> TOTP entry mapping
    entries: Arc<RwLock<HashMap<String, TotpEntry>>>,
    /// user_id -> hashed backup codes mapping
    backup_codes: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl Default for TotpStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpStore {
    /// Create new TOTP store for managing Time-based One-Time Password secrets
    pub fn new() -> Self {
        TotpStore {
            entries: Arc::new(RwLock::new(HashMap::new())),
            backup_codes: Arc::new(RwLock::new(HashMap::new())),
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
        let mut entries = self
            .entries
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;

        entries.insert(user_id.to_string(), TotpEntry {
            secret: secret.to_string(),
            created_at: Utc::now(),
        });

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
        let entries = self
            .entries
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(entries.get(user_id).map(|e| e.secret.clone()))
    }

    /// Remove TOTP secret for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(bool)` true if secret was removed, false if it didn't exist
    /// * `Err(String)` if there's a lock poisoning error
    pub fn remove_secret(&self, user_id: &str) -> Result<bool, String> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(entries.remove(user_id).is_some())
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
        let entries = self
            .entries
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(entries.get(user_id).map(|e| e.created_at))
    }

    /// Get both secret and configuration time atomically
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(Some((String, DateTime<Utc>)))` containing the secret and timestamp if it exists
    /// * `Ok(None)` if no entry is found for the user
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_totp_info(&self, user_id: &str) -> Result<Option<(String, DateTime<Utc>)>, String> {
        let entries = self
            .entries
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(entries.get(user_id).map(|e| (e.secret.clone(), e.created_at)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_totp_store_creation_time() {
        let store = TotpStore::new();
        let user_id = "user1";
        let secret = "secret1";

        // Set secret
        store.set_secret(user_id, secret).unwrap();

        // Get creation time
        let created_at = store.get_configured_at(user_id).unwrap().unwrap();

        // It should be close to now
        let now = Utc::now();
        assert!(now.signed_duration_since(created_at).num_seconds() < 5);

        // Update secret (re-setup)
        thread::sleep(Duration::from_millis(10));
        store.set_secret(user_id, "secret2").unwrap();
        let created_at_2 = store.get_configured_at(user_id).unwrap().unwrap();

        assert!(created_at_2 > created_at);

        // Test atomic retrieval
        let info = store.get_totp_info(user_id).unwrap().unwrap();
        assert_eq!(info.0, "secret2");
        assert_eq!(info.1, created_at_2);
    }
}
