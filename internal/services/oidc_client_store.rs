use crate::model::oidc_client::OidcClient;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct OidcClientStore {
    clients: Arc<RwLock<HashMap<String, OidcClient>>>, // client_id -> OidcClient
}

impl OidcClientStore {
    pub fn new() -> Self {
        OidcClientStore {
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    pub fn add(&self, client: OidcClient) {
        self.clients.write().unwrap().insert(client.client_id.clone(), client);
    }
    pub fn get(&self, client_id: &str) -> Option<OidcClient> {
        self.clients.read().unwrap().get(client_id).cloned()
    }
    pub fn all(&self) -> Vec<OidcClient> {
        self.clients.read().unwrap().values().cloned().collect()
    }
    pub fn delete(&self, client_id: &str) -> bool {
        self.clients.write().unwrap().remove(client_id).is_some()
    }
}
