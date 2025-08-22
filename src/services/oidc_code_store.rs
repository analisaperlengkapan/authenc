use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct OidcCodeStore {
    codes: Mutex<HashMap<String, (String, String, Instant)>>, // code -> (client_id, user_id, issued_at)
    pub ttl: Duration,
}

impl OidcCodeStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            codes: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }
    pub fn insert(&self, code: String, client_id: String, user_id: String) -> Result<(), String> {
        let mut map = self.codes.lock().map_err(|e| format!("Lock poisoned: {e}"))?;
        map.insert(code, (client_id, user_id, Instant::now()));
        Ok(())
    }
    pub fn take(&self, code: &str, client_id: &str) -> Result<Option<String>, String> {
        let mut map = self.codes.lock().map_err(|e| format!("Lock poisoned: {e}"))?;
        if let Some((cid, uid, issued)) = map.get(code) {
            if cid == client_id && issued.elapsed() < self.ttl {
                let uid = uid.clone();
                map.remove(code);
                return Ok(Some(uid));
            }
        }
        Ok(None)
    }
}
