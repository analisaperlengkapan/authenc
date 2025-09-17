use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for anomaly detection functionality
pub trait AnomalyDetectorTrait: Send + Sync {
    /// Check if an IP address is new for a given user
    fn is_new_ip(&self, user_id: &str, ip: &str) -> Result<bool, String>;
}

/// Anomaly detector for tracking user IP addresses and detecting suspicious activity
pub struct AnomalyDetector {
    /// Map of user IDs to their known IP addresses for anomaly detection
    known_ips: Mutex<HashMap<String, Vec<String>>>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    /// Create a new anomaly detector instance
    pub fn new() -> Self {
        Self {
            known_ips: Mutex::new(HashMap::new()),
        }
    }
}

impl AnomalyDetectorTrait for AnomalyDetector {
    /// Check if an IP address is new for a given user (implementation)
    fn is_new_ip(&self, user_id: &str, ip: &str) -> Result<bool, String> {
        let mut map = self
            .known_ips
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        let ips = map.entry(user_id.to_string()).or_default();
        if !ips.contains(&ip.to_string()) {
            ips.push(ip.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
