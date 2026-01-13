use crate::models::realm::Realm;
use std::sync::{Arc, RwLock};

/// In-memory store for managing realms
///
/// Optimized for read-heavy workloads using Copy-On-Write (CoW) semantics.
/// The inner `Arc<Vec<Realm>>` allows `get_all` to return a cheap clone of the Arc,
/// providing O(1) snapshotting without blocking writers for long periods or copying the entire vector.
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
    ///
    /// Uses `Arc::make_mut` to implement Copy-On-Write.
    /// If there are other references to the inner vector (held by readers),
    /// the vector is cloned before modification.
    pub fn add_realm(&self, realm: Realm) {
        let mut realms = self.realms.write().unwrap();
        Arc::make_mut(&mut realms).push(realm);
    }

    /// Get all realms
    ///
    /// Returns an `Arc<Vec<Realm>>` which is an O(1) operation.
    /// Callers can hold this Arc as long as needed without blocking other operations.
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
