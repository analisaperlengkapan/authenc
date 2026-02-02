use authenc_db::database::Database;
use authenc_db::database::operations;
use authenc_api::models::realm::{CreateRealmRequest, RealmResponse, UpdateRealmRequest};
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

/// Realm service trait for multi-tenant realm management
#[async_trait]
pub trait RealmService: Send + Sync {
    /// Create a new realm
    async fn create_realm(&self, request: CreateRealmRequest) -> Result<RealmResponse, String>;

    /// Get realm by ID
    async fn get_realm_by_id(&self, realm_id: &Uuid) -> Result<Option<RealmResponse>, String>;

    /// Get realm by name
    async fn get_realm_by_name(&self, name: &str) -> Result<Option<RealmResponse>, String>;

    /// Update realm
    async fn update_realm(
        &self,
        realm_id: &Uuid,
        request: UpdateRealmRequest,
    ) -> Result<RealmResponse, String>;

    /// Delete realm
    async fn delete_realm(&self, realm_id: &Uuid) -> Result<(), String>;

    /// List all realms
    async fn list_realms(&self) -> Result<Vec<RealmResponse>, String>;

    /// Enable/disable realm
    async fn set_realm_enabled(&self, realm_id: &Uuid, enabled: bool) -> Result<(), String>;
}

/// PostgreSQL implementation of RealmService
pub struct PostgresRealmService {
    /// Database connection
    db: Arc<Database>,
}

impl PostgresRealmService {
    /// Create new PostgreSQL realm service
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl RealmService for PostgresRealmService {
    async fn create_realm(&self, request: CreateRealmRequest) -> Result<RealmResponse, String> {
        operations::realms::create_realm(&self.db, &request)
            .await
            .map(|realm| realm.into())
            .map_err(|e| format!("Failed to create realm: {}", e))
    }

    async fn get_realm_by_id(&self, realm_id: &Uuid) -> Result<Option<RealmResponse>, String> {
        operations::realms::get_realm_by_id(&self.db, *realm_id)
            .await
            .map(|opt| opt.map(|realm| realm.into()))
            .map_err(|e| format!("Failed to get realm by ID: {}", e))
    }

    async fn get_realm_by_name(&self, name: &str) -> Result<Option<RealmResponse>, String> {
        operations::realms::get_realm_by_name(&self.db, name)
            .await
            .map(|opt| opt.map(|realm| realm.into()))
            .map_err(|e| format!("Failed to get realm by name: {}", e))
    }

    async fn update_realm(
        &self,
        realm_id: &Uuid,
        request: UpdateRealmRequest,
    ) -> Result<RealmResponse, String> {
        operations::realms::update_realm(&self.db, *realm_id, &request)
            .await
            .map(|realm| realm.into())
            .map_err(|e| format!("Failed to update realm: {}", e))
    }

    async fn delete_realm(&self, realm_id: &Uuid) -> Result<(), String> {
        operations::realms::delete_realm(&self.db, *realm_id)
            .await
            .map_err(|e| format!("Failed to delete realm: {}", e))
    }

    async fn list_realms(&self) -> Result<Vec<RealmResponse>, String> {
        operations::realms::list_realms(&self.db)
            .await
            .map(|realms| realms.into_iter().map(|r| r.into()).collect())
            .map_err(|e| format!("Failed to list realms: {}", e))
    }

    async fn set_realm_enabled(&self, realm_id: &Uuid, enabled: bool) -> Result<(), String> {
        let update_request = UpdateRealmRequest {
            display_name: None,
            description: None,
            enabled: Some(enabled),
            ssl_required: None,
            registration_allowed: None,
            verify_email: None,
            reset_password_allowed: None,
            brute_force_protected: None,
            attributes: None,
        };

        operations::realms::update_realm(&self.db, *realm_id, &update_request)
            .await
            .map(|_| ())
            .map_err(|e| format!("Failed to set realm enabled status: {}", e))
    }
}

/// Realm management service for multi-tenant operations
pub struct RealmManager {
    /// Realm service implementation
    service: Arc<dyn RealmService>,
}

impl RealmManager {
    /// Create new realm manager
    pub fn new(service: Arc<dyn RealmService>) -> Self {
        Self { service }
    }

    /// Create a new realm with default settings
    pub async fn create_realm(
        &self,
        name: &str,
        display_name: Option<String>,
        description: Option<String>,
    ) -> Result<RealmResponse, String> {
        let request = CreateRealmRequest {
            name: name.to_string(),
            display_name,
            description,
            enabled: Some(true),
            attributes: None,
        };

        self.service.create_realm(request).await
    }

    /// Get realm by name or ID
    pub async fn get_realm(&self, identifier: &str) -> Result<Option<RealmResponse>, String> {
        // Try to parse as UUID first
        if let Ok(uuid) = Uuid::parse_str(identifier) {
            self.service.get_realm_by_id(&uuid).await
        } else {
            self.service.get_realm_by_name(identifier).await
        }
    }

    /// List all active realms
    pub async fn list_active_realms(&self) -> Result<Vec<RealmResponse>, String> {
        let realms = self.service.list_realms().await?;
        Ok(realms.into_iter().filter(|r| r.enabled).collect())
    }

    /// Check if realm exists and is enabled
    pub async fn realm_exists_and_enabled(&self, identifier: &str) -> Result<bool, String> {
        match self.get_realm(identifier).await? {
            Some(realm) => Ok(realm.enabled),
            None => Ok(false),
        }
    }

    /// Enable or disable a realm
    pub async fn set_realm_status(&self, identifier: &str, enabled: bool) -> Result<(), String> {
        let realm = self
            .get_realm(identifier)
            .await?
            .ok_or_else(|| format!("Realm '{}' not found", identifier))?;

        self.service.set_realm_enabled(&realm.id, enabled).await
    }
}
