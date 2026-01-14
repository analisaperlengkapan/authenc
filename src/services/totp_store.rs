use chrono::{DateTime, Duration, Utc};
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
    /// user_id -> TOTP entry mapping (temporary)
    temporary_entries: Arc<RwLock<HashMap<String, TotpEntry>>>,
    /// user_id -> hashed backup codes mapping
    backup_codes: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// user_id -> last used timestamp mapping
    last_used_at: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl Default for TotpStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpStore {
    /// TTL for temporary secrets (10 minutes)
    const TEMPORARY_SECRET_TTL_MINUTES: i64 = 10;

    /// Create new TOTP store for managing Time-based One-Time Password secrets
    pub fn new() -> Self {
        TotpStore {
            entries: Arc::new(RwLock::new(HashMap::new())),
            temporary_entries: Arc::new(RwLock::new(HashMap::new())),
            backup_codes: Arc::new(RwLock::new(HashMap::new())),
            last_used_at: Arc::new(RwLock::new(HashMap::new())),
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

        entries.insert(
            user_id.to_string(),
            TotpEntry {
                secret: secret.to_string(),
                created_at: Utc::now(),
            },
        );

        Ok(())
    }

    /// Set temporary TOTP secret for user during setup
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    /// * `secret` - The base32-encoded TOTP secret
    ///
    /// # Returns
    /// * `Ok(())` on successful storage
    /// * `Err(String)` if there's a lock poisoning error
    pub fn set_temporary_secret(&self, user_id: &str, secret: &str) -> Result<(), String> {
        let mut entries = self
            .temporary_entries
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;

        entries.insert(
            user_id.to_string(),
            TotpEntry {
                secret: secret.to_string(),
                created_at: Utc::now(),
            },
        );

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

    /// Get temporary TOTP secret for user, respecting TTL
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(Some(String))` containing the base32-encoded secret if it exists and is valid
    /// * `Ok(None)` if no secret is found for the user or if it has expired
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_temporary_secret(&self, user_id: &str) -> Result<Option<String>, String> {
        let mut entries = self
            .temporary_entries
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;

        if let Some(entry) = entries.get(user_id) {
            let expiration_time = entry.created_at + Duration::minutes(Self::TEMPORARY_SECRET_TTL_MINUTES);
            if Utc::now() > expiration_time {
                // Expired, remove it
                entries.remove(user_id);
                return Ok(None);
            }
            return Ok(Some(entry.secret.clone()));
        }

        Ok(None)
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
        let removed = entries.remove(user_id).is_some();

        // Also remove last used timestamp
        let mut last_used_at = self
            .last_used_at
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        last_used_at.remove(user_id);

        Ok(removed)
    }

    /// Remove temporary TOTP secret for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(bool)` true if secret was removed, false if it didn't exist
    /// * `Err(String)` if there's a lock poisoning error
    pub fn remove_temporary_secret(&self, user_id: &str) -> Result<bool, String> {
        let mut entries = self
            .temporary_entries
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        let removed = entries.remove(user_id).is_some();

        Ok(removed)
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
        Ok(entries
            .get(user_id)
            .map(|e| (e.secret.clone(), e.created_at)))
    }

    /// Record TOTP usage timestamp for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(())` on successful storage
    /// * `Err(String)` if there's a lock poisoning error
    pub fn record_usage(&self, user_id: &str) -> Result<(), String> {
        let mut last_used_at = self
            .last_used_at
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        last_used_at.insert(user_id.to_string(), Utc::now());
        Ok(())
    }

    /// Get TOTP last used timestamp for user
    ///
    /// # Arguments
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    /// * `Ok(Some(DateTime<Utc>))` containing the last used timestamp if it exists
    /// * `Ok(None)` if no timestamp is found for the user
    /// * `Err(String)` if there's a lock poisoning error
    pub fn get_last_used_at(&self, user_id: &str) -> Result<Option<DateTime<Utc>>, String> {
        let last_used_at = self
            .last_used_at
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(last_used_at.get(user_id).cloned())
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

    #[test]
    fn test_record_usage() {
        let store = TotpStore::new();
        let user_id = "user123";

        // Initially no last used time
        assert!(store.get_last_used_at(user_id).unwrap().is_none());

        // Record usage
        store.record_usage(user_id).unwrap();

        // Check it was recorded
        let last_used = store.get_last_used_at(user_id).unwrap();
        assert!(last_used.is_some());
    }

    #[test]
    fn test_remove_secret_clears_usage() {
        let store = TotpStore::new();
        let user_id = "user123";

        store.set_secret(user_id, "secret").unwrap();
        store.record_usage(user_id).unwrap();

        assert!(store.get_last_used_at(user_id).unwrap().is_some());

        store.remove_secret(user_id).unwrap();

        assert!(store.get_last_used_at(user_id).unwrap().is_none());
        assert!(store.get_secret(user_id).unwrap().is_none());
    }

    #[test]
    fn test_temporary_secret_flow() {
        let store = TotpStore::new();
        let user_id = "user_temp";
        let secret = "temp_secret";

        // Should be empty initially
        assert!(store.get_temporary_secret(user_id).unwrap().is_none());
        assert!(store.get_secret(user_id).unwrap().is_none());

        // Set temporary secret
        store.set_temporary_secret(user_id, secret).unwrap();

        // Should be in temporary store but not permanent
        assert_eq!(store.get_temporary_secret(user_id).unwrap().unwrap(), secret);
        assert!(store.get_secret(user_id).unwrap().is_none());

        // Remove temporary secret
        store.remove_temporary_secret(user_id).unwrap();

        // Should be gone
        assert!(store.get_temporary_secret(user_id).unwrap().is_none());
    }

    #[test]
    fn test_temporary_secret_expiration() {
        let store = TotpStore::new();
        let user_id = "user_expired";
        let secret = "expired_secret";

        // Set manually with an old timestamp
        {
            let mut entries = store.temporary_entries.write().unwrap();
            entries.insert(
                user_id.to_string(),
                TotpEntry {
                    secret: secret.to_string(),
                    created_at: Utc::now() - chrono::Duration::minutes(15), // 15 minutes old > 10 min TTL
                },
            );
        }

        // Should be expired and removed
        assert!(store.get_temporary_secret(user_id).unwrap().is_none());

        // Verify it was actually removed from the map
        {
            let entries = store.temporary_entries.read().unwrap();
            assert!(entries.get(user_id).is_none());
        }
    }
}
