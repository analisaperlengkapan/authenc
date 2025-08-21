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

    pub fn add(&self, token: &str, user_id: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(token.to_string(), user_id.to_string());
    }

    pub fn remove(&self, token: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(token);
    }

    pub fn get_user_id(&self, token: &str) -> Option<String> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(token).cloned()
    }

    pub fn all_for_user(&self, user_id: &str) -> Vec<String> {
        let sessions = self.sessions.read().unwrap();
        sessions.iter().filter_map(|(token, uid)| if uid == user_id { Some(token.clone()) } else { None }).collect()
    }
}
