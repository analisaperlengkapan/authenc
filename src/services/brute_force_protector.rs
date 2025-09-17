use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Brute force protection service to prevent credential stuffing and dictionary attacks
pub struct BruteForceProtector {
    /// Map of keys (username/IP) to timestamps of failed attempts
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    /// Maximum number of failed attempts allowed within the time window
    pub max_attempts: usize,
    /// Time window for counting failed attempts
    pub window: Duration,
}

impl BruteForceProtector {
    /// Create a new brute force protector with specified limits
    ///
    /// # Arguments
    /// * `max_attempts` - Maximum number of failed attempts allowed within the time window
    /// * `window_secs` - Time window in seconds for counting failed attempts
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Register a failed authentication attempt for a given key
    ///
    /// # Arguments
    /// * `key` - The key to track (typically username or IP address)
    ///
    /// # Returns
    /// * `Ok(true)` if the attempt should be blocked due to exceeding max attempts
    /// * `Ok(false)` if the attempt is allowed
    /// * `Err(String)` if there's a lock poisoning error
    pub fn register_attempt(&self, key: &str) -> Result<bool, String> {
        let mut map = self
            .attempts
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_default();
        entry.push(now);
        // Remove old attempts
        entry.retain(|&t| now.duration_since(t) < self.window);
        Ok(entry.len() > self.max_attempts)
    }

    /// Clear all failed attempts for a given key (typically after successful authentication)
    ///
    /// # Arguments
    /// * `key` - The key to clear attempts for
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(String)` if there's a lock poisoning error
    pub fn clear(&self, key: &str) -> Result<(), String> {
        let mut map = self
            .attempts
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        map.remove(key);
        Ok(())
    }
}
