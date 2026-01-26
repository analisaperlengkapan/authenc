use async_trait::async_trait;
use authenc::models::session::Session;
use authenc::services::session_store::{SessionStoreTrait, CreateSessionParams, CreateOfflineTokenParams};
use authenc::error::{AuthencError, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::{Utc, Duration};

#[derive(Clone, Debug)]
pub struct MockSessionStore {
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
    token_map: Arc<RwLock<HashMap<String, String>>>, // token -> user_id
}

impl MockSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            token_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SessionStoreTrait for MockSessionStore {
    // Sync methods
    fn add(&self, token: &str, user_id: &str) -> std::result::Result<(), String> {
        let mut map = self.token_map.write().map_err(|e| e.to_string())?;
        map.insert(token.to_string(), user_id.to_string());
        Ok(())
    }

    fn remove(&self, token: &str) -> std::result::Result<(), String> {
        let mut map = self.token_map.write().map_err(|e| e.to_string())?;
        map.remove(token);
        Ok(())
    }

    fn get_user_id(&self, token: &str) -> std::result::Result<Option<String>, String> {
        let map = self.token_map.read().map_err(|e| e.to_string())?;
        Ok(map.get(token).cloned())
    }

    fn all_for_user(&self, user_id: &str) -> std::result::Result<Vec<String>, String> {
        let map = self.token_map.read().map_err(|e| e.to_string())?;
        Ok(map.iter()
            .filter(|(_, uid)| *uid == user_id)
            .map(|(t, _)| t.clone())
            .collect())
    }

    // Async methods
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let sessions = self.sessions.read().unwrap();
        Ok(sessions.values().filter(|s| s.user_id == user_id).cloned().collect())
    }

    async fn get_session(&self, id: Uuid) -> Result<Option<Session>> {
        let sessions = self.sessions.read().unwrap();
        Ok(sessions.get(&id).cloned())
    }

    async fn delete_session(&self, id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(&id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, s| s.user_id != user_id);
        Ok(())
    }

    async fn store_session(&self, session: Session) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn create_session(&self, params: CreateSessionParams<'_>) -> Result<Uuid> {
        let mut sessions = self.sessions.write().unwrap();
        let id = Uuid::new_v4();
        let session = Session {
            id,
            user_id: params.user_id,
            realm_id: params.realm_id,
            token: params.token.to_string(),
            refresh_token: params.refresh_token.map(|s| s.to_string()),
            ip_address: params.ip_address.map(|s| s.to_string()),
            user_agent: params.user_agent.map(|s| s.to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(params.expires_in),
            last_accessed: Utc::now(),
            revoked: false,
        };
        sessions.insert(id, session);
        Ok(id)
    }

    async fn get_session_by_token(&self, _token: &str) -> Result<Option<serde_json::Value>> {
        Ok(None) // Simplified
    }

    async fn touch_session_db(&self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(&session_id) {
            session.last_accessed = Utc::now();
        }
        Ok(())
    }

    async fn rotate_refresh_token(&self, _session_id: Uuid, _old_rt: &str, _new_rt: &str, _ip: Option<&str>, _ua: Option<&str>) -> Result<bool> {
        Ok(true)
    }

    async fn revoke_session_db(&self, session_id: Uuid, _reason: Option<&str>) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(&session_id) {
            session.revoked = true;
        }
        Ok(())
    }

    async fn create_offline_token(&self, _params: CreateOfflineTokenParams<'_>) -> Result<Uuid> {
        Ok(Uuid::new_v4())
    }

    async fn get_offline_token(&self, _token: &str) -> Result<Option<serde_json::Value>> {
        Ok(None)
    }

    async fn touch_offline_token(&self, _token_id: Uuid) -> Result<()> {
        Ok(())
    }

    async fn revoke_offline_token(&self, _token_id: Uuid) -> Result<()> {
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<i64> {
        Ok(0)
    }
}
