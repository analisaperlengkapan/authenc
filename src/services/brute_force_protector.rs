use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct BruteForceProtector {
    // (username/ip) -> Vec<Instant>
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    pub max_attempts: usize,
    pub window: Duration,
}

impl BruteForceProtector {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn register_attempt(&self, key: &str) -> Result<bool, String> {
        let mut map = self.attempts.lock().map_err(|e| format!("Lock poisoned: {e}"))?;
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_default();
        entry.push(now);
        // Remove old attempts
        entry.retain(|&t| now.duration_since(t) < self.window);
        Ok(entry.len() > self.max_attempts)
    }

    pub fn clear(&self, key: &str) -> Result<(), String> {
        let mut map = self.attempts.lock().map_err(|e| format!("Lock poisoned: {e}"))?;
        map.remove(key);
        Ok(())
    }
}
