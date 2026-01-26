use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use crate::error::Result;
use super::state_store::{SocialStateStore, SocialLoginState};

/// In-memory implementation of SocialStateStore
pub struct InMemorySocialStateStore {
    states: RwLock<HashMap<String, SocialLoginState>>,
}

impl Default for InMemorySocialStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySocialStateStore {
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SocialStateStore for InMemorySocialStateStore {
    async fn create_state(
        &self,
        state: &str,
        provider: &str,
        redirect_uri: &str,
        realm_id: Option<&str>,
        expires_in: i64,
    ) -> Result<()> {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);
        let login_state = SocialLoginState {
            state: state.to_string(),
            provider: provider.to_string(),
            redirect_uri: redirect_uri.to_string(),
            realm_id: realm_id.map(String::from),
            expires_at,
        };

        let mut states = self.states.write().map_err(|_| crate::error::AuthencError::internal("Lock poisoned"))?;
        states.insert(state.to_string(), login_state);
        Ok(())
    }

    async fn validate_and_consume_state(&self, state: &str) -> Result<Option<SocialLoginState>> {
        let mut states = self.states.write().map_err(|_| crate::error::AuthencError::internal("Lock poisoned"))?;

        if let Some(login_state) = states.remove(state) {
            if login_state.expires_at > chrono::Utc::now() {
                return Ok(Some(login_state));
            }
        }
        Ok(None)
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = chrono::Utc::now();
        let mut states = self.states.write().map_err(|_| crate::error::AuthencError::internal("Lock poisoned"))?;
        states.retain(|_, state| state.expires_at > now);
        Ok(())
    }
}
