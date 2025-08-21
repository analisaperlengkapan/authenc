use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct AnomalyDetector {
    // user_id -> set of known IPs
    known_ips: Mutex<HashMap<String, Vec<String>>>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            known_ips: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_new_ip(&self, user_id: &str, ip: &str) -> bool {
        let mut map = self.known_ips.lock().unwrap();
        let ips = map.entry(user_id.to_string()).or_insert_with(Vec::new);
        if !ips.contains(&ip.to_string()) {
            ips.push(ip.to_string());
            true
        } else {
            false
        }
    }
}
