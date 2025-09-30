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
        if self.window.as_secs() > 0 {
            entry.retain(|&t| now.duration_since(t) < self.window);
        } else {
            // For zero window, expire all attempts immediately
            entry.clear();
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_brute_force_protector_creation() {
        let protector = BruteForceProtector::new(5, 300); // 5 attempts per 5 minutes
        assert_eq!(protector.max_attempts, 5);
        assert_eq!(protector.window, Duration::from_secs(300));
        assert!(protector.attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn test_register_attempt_under_limit() {
        let protector = BruteForceProtector::new(3, 60);

        // Register attempts under the limit
        for i in 0..3 {
            let result = protector.register_attempt("user1").unwrap();
            assert!(!result, "Attempt {} should not be blocked", i + 1);
        }

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 3);
    }

    #[test]
    fn test_register_attempt_at_limit() {
        let protector = BruteForceProtector::new(3, 60);

        // Register exactly max_attempts
        for i in 0..3 {
            let result = protector.register_attempt("user1").unwrap();
            assert!(!result, "Attempt {} should not be blocked", i + 1);
        }

        // Next attempt should be blocked
        let result = protector.register_attempt("user1").unwrap();
        assert!(result, "4th attempt should be blocked");

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 4);
    }

    #[test]
    fn test_register_attempt_over_limit() {
        let protector = BruteForceProtector::new(2, 60);

        // Register more than max_attempts
        for i in 0..5 {
            let result = protector.register_attempt("user1").unwrap();
            if i < 2 {
                assert!(!result, "Attempt {} should not be blocked", i + 1);
            } else {
                assert!(result, "Attempt {} should be blocked", i + 1);
            }
        }

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 5);
    }

    #[test]
    fn test_register_attempt_different_keys() {
        let protector = BruteForceProtector::new(2, 60);

        // Different keys should be tracked separately
        let result1 = protector.register_attempt("user1").unwrap();
        assert!(!result1);

        let result2 = protector.register_attempt("user2").unwrap();
        assert!(!result2);

        let result3 = protector.register_attempt("user1").unwrap();
        assert!(!result3); // user1 still under limit

        let result4 = protector.register_attempt("user2").unwrap();
        assert!(!result4); // user2 still under limit

        let result5 = protector.register_attempt("user1").unwrap();
        assert!(result5); // user1 now blocked

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 3);
        assert_eq!(attempts["user2"].len(), 2);
    }

    #[test]
    fn test_clear_attempts() {
        let protector = BruteForceProtector::new(3, 60);

        // Register some attempts
        protector.register_attempt("user1").unwrap();
        protector.register_attempt("user1").unwrap();

        // Verify attempts are recorded
        {
            let attempts = protector.attempts.lock().unwrap();
            assert_eq!(attempts["user1"].len(), 2);
        }

        // Clear attempts
        protector.clear("user1").unwrap();

        // Verify attempts are cleared
        let attempts = protector.attempts.lock().unwrap();
        assert!(!attempts.contains_key("user1"));
    }

    #[test]
    fn test_clear_nonexistent_key() {
        let protector = BruteForceProtector::new(3, 60);

        // Clear non-existent key should not error
        protector.clear("nonexistent").unwrap();

        let attempts = protector.attempts.lock().unwrap();
        assert!(!attempts.contains_key("nonexistent"));
    }

    #[test]
    fn test_time_window_expiration() {
        let protector = BruteForceProtector::new(2, 1); // 1 second window

        // Register attempts
        protector.register_attempt("user1").unwrap();
        protector.register_attempt("user1").unwrap();

        // Verify both attempts are within window
        let result = protector.register_attempt("user1").unwrap();
        assert!(result); // Should be blocked

        // Wait for window to expire
        thread::sleep(Duration::from_secs(2));

        // Register new attempt - old attempts should be cleared
        let result = protector.register_attempt("user1").unwrap();
        assert!(!result); // Should not be blocked

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 1); // Only the new attempt
    }

    #[test]
    fn test_mixed_old_and_new_attempts() {
        let protector = BruteForceProtector::new(2, 1); // 1 second window

        // Register first attempt
        protector.register_attempt("user1").unwrap();

        // Wait 1 second
        thread::sleep(Duration::from_secs(1));

        // Register second attempt
        protector.register_attempt("user1").unwrap();

        // Register third attempt - first attempt should be expired now
        let result = protector.register_attempt("user1").unwrap();
        assert!(!result); // Should not be blocked (only 2 attempts after expiration)

        // Wait another 1.5 seconds (total 2.5s > 1s window)
        thread::sleep(Duration::from_millis(1500));

        // Register new attempt - all previous attempts should be expired
        let result = protector.register_attempt("user1").unwrap();
        assert!(!result); // Should not be blocked (only 1 attempt)

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 1);
    }

    #[test]
    fn test_empty_key() {
        let protector = BruteForceProtector::new(2, 60);

        let result = protector.register_attempt("").unwrap();
        assert!(!result);

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts[""].len(), 1);
    }

    #[test]
    fn test_special_characters_in_key() {
        let protector = BruteForceProtector::new(2, 60);

        let result = protector.register_attempt("user@domain.com").unwrap();
        assert!(!result);

        let result = protector.register_attempt("192.168.1.1:8080").unwrap();
        assert!(!result);

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user@domain.com"].len(), 1);
        assert_eq!(attempts["192.168.1.1:8080"].len(), 1);
    }

    #[test]
    fn test_clear_after_blocking() {
        let protector = BruteForceProtector::new(2, 60);

        // Register attempts to trigger blocking
        protector.register_attempt("user1").unwrap();
        protector.register_attempt("user1").unwrap();
        let result = protector.register_attempt("user1").unwrap();
        assert!(result); // Should be blocked

        // Clear attempts
        protector.clear("user1").unwrap();

        // Should be able to attempt again
        let result = protector.register_attempt("user1").unwrap();
        assert!(!result); // Should not be blocked

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 1);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let protector = Arc::new(BruteForceProtector::new(5, 60));
        let mut handles = vec![];

        // Spawn multiple threads registering attempts
        for _ in 0..10 {
            let protector_clone = Arc::clone(&protector);
            let handle = thread::spawn(move || {
                for _ in 0..3 {
                    let _ = protector_clone.register_attempt("shared_user");
                    thread::sleep(Duration::from_millis(1));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state
        let attempts = protector.attempts.lock().unwrap();
        assert!(attempts["shared_user"].len() >= 5); // At least max_attempts
    }

    #[test]
    fn test_zero_max_attempts() {
        let protector = BruteForceProtector::new(0, 60);

        // Any attempt should be blocked
        let result = protector.register_attempt("user1").unwrap();
        assert!(result);

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 1);
    }

    #[test]
    fn test_zero_window() {
        let protector = BruteForceProtector::new(3, 0);

        // With zero window, all attempts should be considered expired immediately
        protector.register_attempt("user1").unwrap();
        protector.register_attempt("user1").unwrap();
        protector.register_attempt("user1").unwrap();

        // All attempts should be expired, so new attempt should not be blocked
        let result = protector.register_attempt("user1").unwrap();
        assert!(!result);

        let attempts = protector.attempts.lock().unwrap();
        assert_eq!(attempts["user1"].len(), 0); // No attempts retained with zero window
    }
}
