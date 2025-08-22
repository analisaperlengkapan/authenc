use std::sync::Mutex;
use crate::models::realm::Realm;

pub struct RealmStore {
    pub realms: Mutex<Vec<Realm>>,
}

impl RealmStore {
    pub fn new() -> Self {
        Self {
            realms: Mutex::new(vec![]),
        }
    }

    pub fn add_realm(&self, realm: Realm) {
        self.realms.lock().unwrap().push(realm);
    }

    pub fn get_all(&self) -> Vec<Realm> {
        self.realms.lock().unwrap().clone()
    }

    pub fn get_by_name(&self, name: &str) -> Option<Realm> {
        self.realms.lock().unwrap().iter().find(|r| r.name == name).cloned()
    }
}
