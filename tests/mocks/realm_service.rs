use async_trait::async_trait;
use authenc::models::realm::{Realm, CreateRealmRequest, UpdateRealmRequest, RealmResponse};
use authenc::services::realm::RealmService;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct MockRealmService {
    realms: Arc<RwLock<HashMap<Uuid, Realm>>>,
}

impl MockRealmService {
    pub fn new() -> Self {
        Self {
            realms: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl RealmService for MockRealmService {
    async fn create_realm(&self, req: CreateRealmRequest) -> Result<RealmResponse, String> {
        let mut realms = self.realms.write().map_err(|e| e.to_string())?;
        let id = Uuid::new_v4();
        let realm = Realm {
            id,
            name: req.name.clone(),
            display_name: req.display_name,
            enabled: req.enabled.unwrap_or(true),
            description: req.description,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            attributes: req.attributes,
            ..Default::default()
        };
        realms.insert(id, realm.clone());
        Ok(RealmResponse::from(realm))
    }

    async fn get_realm_by_id(&self, id: &Uuid) -> Result<Option<RealmResponse>, String> {
        let realms = self.realms.read().map_err(|e| e.to_string())?;
        Ok(realms.get(id).map(|r| RealmResponse::from(r.clone())))
    }

    async fn get_realm_by_name(&self, name: &str) -> Result<Option<RealmResponse>, String> {
        let realms = self.realms.read().map_err(|e| e.to_string())?;
        Ok(realms.values().find(|r| r.name == name).map(|r| RealmResponse::from(r.clone())))
    }

    async fn update_realm(&self, id: &Uuid, req: UpdateRealmRequest) -> Result<RealmResponse, String> {
         let mut realms = self.realms.write().map_err(|e| e.to_string())?;
         if let Some(realm) = realms.get_mut(id) {
             if let Some(display_name) = req.display_name { realm.display_name = Some(display_name); }
             if let Some(enabled) = req.enabled { realm.enabled = enabled; }
             // ... other fields
             Ok(RealmResponse::from(realm.clone()))
         } else {
             Err("Realm not found".to_string())
         }
    }

    async fn delete_realm(&self, id: &Uuid) -> Result<(), String> {
        let mut realms = self.realms.write().map_err(|e| e.to_string())?;
        realms.remove(id);
        Ok(())
    }

    async fn list_realms(&self) -> Result<Vec<RealmResponse>, String> {
        let realms = self.realms.read().map_err(|e| e.to_string())?;
        Ok(realms.values().map(|r| RealmResponse::from(r.clone())).collect())
    }

    async fn set_realm_enabled(&self, id: &Uuid, enabled: bool) -> Result<(), String> {
         let mut realms = self.realms.write().map_err(|e| e.to_string())?;
         if let Some(realm) = realms.get_mut(id) {
             realm.enabled = enabled;
             Ok(())
         } else {
             Err("Realm not found".to_string())
         }
    }
}
