use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct TotpStore {
    // user_id -> base32 secret
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

impl TotpStore {
    pub fn new() -> Self {
        TotpStore {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_secret(&self, user_id: &str, secret: &str) {
        let mut secrets = self.secrets.write().unwrap();
        secrets.insert(user_id.to_string(), secret.to_string());
    }

    pub fn get_secret(&self, user_id: &str) -> Option<String> {
        let secrets = self.secrets.read().unwrap();
        secrets.get(user_id).cloned()
    }

    pub fn remove_secret(&self, user_id: &str) {
        let mut secrets = self.secrets.write().unwrap();
        secrets.remove(user_id);
    }
}
