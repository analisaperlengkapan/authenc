use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for anomaly detection
pub trait AnomalyDetectorTrait: Send + Sync {
    fn is_new_ip(&self, user_id: &str, ip: &str) -> Result<bool, String>;
}

pub struct AnomalyDetector {
    // user_id -> set of known IPs
    known_ips: Mutex<HashMap<String, Vec<String>>>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            known_ips: Mutex::new(HashMap::new()),
        }
    }
}

impl AnomalyDetectorTrait for AnomalyDetector {
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
