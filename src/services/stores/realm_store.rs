use crate::models::realm::Realm;
use std::sync::{Arc, RwLock};

/// In-memory store for managing realms
pub struct RealmStore {
    /// Thread-safe storage of realms
    pub realms: RwLock<Arc<Vec<Realm>>>,
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
            realms: RwLock::new(Arc::new(vec![])),
        }
    }

    /// Add realm to store
    pub fn add_realm(&self, realm: Realm) {
        let mut realms = self.realms.write().unwrap();
        Arc::make_mut(&mut realms).push(realm);
    }

    /// Get all realms
    pub fn get_all(&self) -> Arc<Vec<Realm>> {
        self.realms.read().unwrap().clone()
    }

    /// Get realm by name
    pub fn get_by_name(&self, name: &str) -> Option<Realm> {
        self.realms
            .read()
            .unwrap()
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }
}
