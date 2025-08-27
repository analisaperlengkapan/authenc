impl Default for TotpStore {
    fn default() -> Self {
        Self::new()
    }
}
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

    pub fn set_secret(&self, user_id: &str, secret: &str) -> Result<(), String> {
        let mut secrets = self
            .secrets
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        secrets.insert(user_id.to_string(), secret.to_string());
        Ok(())
    }

    pub fn get_secret(&self, user_id: &str) -> Result<Option<String>, String> {
        let secrets = self
            .secrets
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(secrets.get(user_id).cloned())
    }

    pub fn remove_secret(&self, user_id: &str) -> Result<(), String> {
        let mut secrets = self
            .secrets
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        secrets.remove(user_id);
        Ok(())
    }
}
