use async_trait::async_trait;
use authenc::models::{ConsentGrantRequest, UserConsent};
use authenc::services::stores::consent_store::ConsentStoreTrait;
use authenc::error::{AuthencError, Result};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct MockConsentStore {
    consents: Arc<RwLock<Vec<UserConsent>>>,
}

impl MockConsentStore {
    pub fn new() -> Self {
        Self {
            consents: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ConsentStoreTrait for MockConsentStore {
    async fn grant_consent(&self, user_id: Uuid, request: ConsentGrantRequest) -> Result<UserConsent> {
        let mut consents = self.consents.write().unwrap();
        let now = chrono::Utc::now();
        let expires_at = request.expires_in.map(|seconds| now + chrono::Duration::seconds(seconds));

        let consent = UserConsent {
            id: Uuid::new_v4(),
            user_id,
            client_id: request.client_id.clone(),
            scopes: request.scopes.clone(),
            granted_at: now,
            expires_at,
            metadata: request.metadata.unwrap_or(serde_json::json!({})),
        };
        consents.push(consent.clone());
        Ok(consent)
    }

    async fn revoke_consent(&self, user_id: Uuid, client_id: &str) -> Result<()> {
        let mut consents = self.consents.write().unwrap();
        consents.retain(|c| !(c.user_id == user_id && c.client_id == client_id));
        Ok(())
    }

    async fn revoke_consent_by_id(&self, user_id: Uuid, consent_id: Uuid) -> Result<()> {
        let mut consents = self.consents.write().unwrap();
        consents.retain(|c| !(c.user_id == user_id && c.id == consent_id));
        Ok(())
    }

    async fn get_user_consents(&self, user_id: Uuid) -> Result<Vec<UserConsent>> {
        let consents = self.consents.read().unwrap();
        Ok(consents.iter().filter(|c| c.user_id == user_id).cloned().collect())
    }

    async fn get_user_consent(&self, user_id: Uuid, client_id: &str) -> Result<Option<UserConsent>> {
        let consents = self.consents.read().unwrap();
        Ok(consents.iter().find(|c| c.user_id == user_id && c.client_id == client_id).cloned())
    }

    async fn has_consent(&self, user_id: Uuid, client_id: &str, scopes: &[String]) -> Result<bool> {
        let consents = self.consents.read().unwrap();
        if let Some(consent) = consents.iter().find(|c| c.user_id == user_id && c.client_id == client_id) {
            // Check if all requested scopes are present
            let has_all_scopes = scopes.iter().all(|s| consent.scopes.contains(s));
            Ok(has_all_scopes)
        } else {
            Ok(false)
        }
    }

    async fn cleanup_expired_consents(&self) -> Result<i64> {
        let mut consents = self.consents.write().unwrap();
        let initial_len = consents.len();
        let now = chrono::Utc::now();
        consents.retain(|c| c.expires_at.map(|exp| exp > now).unwrap_or(true));
        Ok((initial_len - consents.len()) as i64)
    }

    async fn get_consent_stats(&self, _user_id: Uuid) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "total": 0 }))
    }
}
