impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct SessionStore {
    // token -> user_id
    sessions: Arc<RwLock<HashMap<String, String>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add(&self, token: &str, user_id: &str) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        sessions.insert(token.to_string(), user_id.to_string());
        Ok(())
    }

    pub fn remove(&self, token: &str) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        sessions.remove(token);
        Ok(())
    }

    pub fn get_user_id(&self, token: &str) -> Result<Option<String>, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(sessions.get(token).cloned())
    }

    pub fn all_for_user(&self, user_id: &str) -> Result<Vec<String>, String> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        Ok(sessions
            .iter()
            .filter_map(|(token, uid)| {
                if uid == user_id {
                    Some(token.clone())
                } else {
                    None
                }
            })
            .collect())
    }
}
