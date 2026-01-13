use crate::models::realm::Realm;
use std::sync::{Mutex, MutexGuard};

/// In-memory store for managing realms
pub struct RealmStore {
    /// Thread-safe storage of realms
    pub realms: Mutex<Vec<Realm>>,
}

impl Default for RealmStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RealmStore {
    /// Create new realm store
    pub fn new() -> Self {
        Self {
            realms: Mutex::new(vec![]),
        }
    }

    /// Add realm to store
    pub fn add_realm(&self, realm: Realm) {
        self.realms.lock().unwrap().push(realm);
    }

    /// Get all realms for read-only access
    pub fn get_realms(&self) -> MutexGuard<Vec<Realm>> {
        self.realms.lock().unwrap()
    }

    /// Get realm by name
    pub fn get_by_name(&self, name: &str) -> Option<Realm> {
        self.realms
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }
}
