impl Default for OidcClientStore {
    fn default() -> Self {
        Self::new()
    }
}
use crate::models::oidc_client::OidcClient;
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
    pub fn add(&self, client: OidcClient) -> Result<(), String> {
        self.clients
            .write()
            .map_err(|e| format!("Lock poisoned: {e}"))?
            .insert(client.client_id.clone(), client);
        Ok(())
    }
    pub fn get(&self, client_id: &str) -> Result<Option<OidcClient>, String> {
        Ok(self.clients.read().map_err(|e| format!("Lock poisoned: {e}"))?.get(client_id).cloned())
    }
    pub fn all(&self) -> Result<Vec<OidcClient>, String> {
        Ok(self.clients.read().map_err(|e| format!("Lock poisoned: {e}"))?.values().cloned().collect())
    }
    pub fn delete(&self, client_id: &str) -> Result<bool, String> {
        Ok(self.clients.write().map_err(|e| format!("Lock poisoned: {e}"))?.remove(client_id).is_some())
    }
}
