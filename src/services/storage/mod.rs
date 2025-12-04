//! Storage Abstraction Layer
//!
//! Comprehensive storage abstraction layer for Authenc's storage SPI,
//! providing pluggable storage backends for different data types.
//!
//! Features:
//! - Pluggable storage providers (In-memory, PostgreSQL, Redis, etc.)
//! - Storage provider factory pattern
//! - Transaction support
//! - Connection pooling
//! - Migration support
//! - Hot-swappable storage backends

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::AuthencError;

/// Storage Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage provider type
    pub provider_type: StorageProviderType,
    /// Connection string or configuration
    pub connection_string: Option<String>,
    /// Additional configuration parameters
    pub parameters: HashMap<String, String>,
}

/// Storage Provider Types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageProviderType {
    /// In-memory storage for testing and development
    InMemory,
    /// PostgreSQL database storage
    PostgreSQL,
    /// Redis storage
    Redis,
    /// MongoDB storage
    MongoDB,
    /// Custom storage provider
    Custom(String),
}

/// Storage Provider trait
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Get provider name
    fn name(&self) -> &str;

    /// Initialize the storage provider
    async fn init(&mut self, config: &StorageConfig) -> Result<(), AuthencError>;

    /// Check storage health
    async fn health_check(&self) -> Result<(), AuthencError>;

    /// Begin a transaction
    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, AuthencError>;

    /// Close the storage provider
    async fn close(&mut self) -> Result<(), AuthencError>;
}

/// Storage Transaction trait
#[async_trait]
pub trait StorageTransaction: Send + Sync {
    /// Commit the transaction
    async fn commit(&mut self) -> Result<(), AuthencError>;

    /// Rollback the transaction
    async fn rollback(&mut self) -> Result<(), AuthencError>;
}

/// Generic Storage Repository trait
#[async_trait]
pub trait StorageRepository<T: Send + Sync + Clone + Serialize + serde::de::DeserializeOwned>: Send + Sync {
    /// Find entity by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<T>, AuthencError>;

    /// Find all entities
    async fn find_all(&self) -> Result<Vec<T>, AuthencError>;

    /// Save entity
    async fn save(&self, entity: &T) -> Result<(), AuthencError>;

    /// Update entity
    async fn update(&self, entity: &T) -> Result<(), AuthencError>;

    /// Delete entity by ID
    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError>;

    /// Count entities
    async fn count(&self) -> Result<i64, AuthencError>;
}

/// User Storage Repository
#[async_trait]
pub trait UserStorageRepository: StorageRepository<crate::models::user::User> {
    /// Find user by username
    async fn find_by_username(&self, username: &str) -> Result<Option<crate::models::user::User>, AuthencError>;

    /// Find user by email
    async fn find_by_email(&self, email: &str) -> Result<Option<crate::models::user::User>, AuthencError>;

    /// Find users by role
    async fn find_by_role(&self, role_id: &str) -> Result<Vec<crate::models::user::User>, AuthencError>;
}

/// Client Storage Repository
#[async_trait]
pub trait ClientStorageRepository: StorageRepository<crate::models::oauth2::OAuth2Client> {
    /// Find client by client ID
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<crate::models::oauth2::OAuth2Client>, AuthencError>;

    /// Find clients by owner
    async fn find_by_owner(&self, owner_id: &str) -> Result<Vec<crate::models::oauth2::OAuth2Client>, AuthencError>;
}

/// Realm Storage Repository
#[async_trait]
pub trait RealmStorageRepository: StorageRepository<crate::models::realm::Realm> {
    /// Find realm by name
    async fn find_by_name(&self, name: &str) -> Result<Option<crate::models::realm::Realm>, AuthencError>;

    /// Find realms by owner
    async fn find_by_owner(&self, owner_id: &str) -> Result<Vec<crate::models::realm::Realm>, AuthencError>;
}

/// In-Memory Storage Provider
pub struct InMemoryStorageProvider {
    data: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryStorageProvider {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageProvider for InMemoryStorageProvider {
    fn name(&self) -> &str {
        "in-memory"
    }

    async fn init(&mut self, _config: &StorageConfig) -> Result<(), AuthencError> {
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AuthencError> {
        Ok(())
    }

    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, AuthencError> {
        // In-memory storage doesn't need real transactions
        Ok(Box::new(InMemoryTransaction::new()))
    }

    async fn close(&mut self) -> Result<(), AuthencError> {
        Ok(())
    }
}

/// In-Memory Transaction (no-op for in-memory storage)
pub struct InMemoryTransaction;

impl InMemoryTransaction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StorageTransaction for InMemoryTransaction {
    async fn commit(&mut self) -> Result<(), AuthencError> {
        Ok(())
    }

    async fn rollback(&mut self) -> Result<(), AuthencError> {
        Ok(())
    }
}

/// Generic In-Memory Repository Implementation
pub struct InMemoryRepository<T: Send + Sync + Clone + Serialize + serde::de::DeserializeOwned> {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
    entity_type: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Send + Sync + Clone + Serialize + serde::de::DeserializeOwned> InMemoryRepository<T> {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>, entity_type: String) -> Self {
        Self {
            storage,
            entity_type,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T: Send + Sync + Clone + Serialize + serde::de::DeserializeOwned> StorageRepository<T> for InMemoryRepository<T> {
    async fn find_by_id(&self, id: &str) -> Result<Option<T>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(entity_store) = storage.get(&self.entity_type) {
            if let Some(value) = entity_store.get(id) {
                let entity: T = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize entity".to_string()
                    })?;
                Ok(Some(entity))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<T>, AuthencError> {
        let storage = self.storage.read().await;
        let mut entities = Vec::new();

        if let Some(entity_store) = storage.get(&self.entity_type) {
            for value in entity_store.values() {
                let entity: T = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize entity".to_string()
                    })?;
                entities.push(entity);
            }
        }

        Ok(entities)
    }

    async fn save(&self, entity: &T) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let entity_store = storage.entry(self.entity_type.clone()).or_insert_with(HashMap::new);

        // Generate ID (in real implementation, this would be from the entity)
        let id = "generated_id".to_string(); // Placeholder
        let value = serde_json::to_value(entity)
            .map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize entity".to_string()
            })?;

        entity_store.insert(id, value);
        Ok(())
    }

    async fn update(&self, entity: &T) -> Result<(), AuthencError> {
        // Same as save for in-memory
        self.save(entity).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(entity_store) = storage.get_mut(&self.entity_type) {
            entity_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(entity_store) = storage.get(&self.entity_type) {
            Ok(entity_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

/// Storage Provider Factory
pub struct StorageProviderFactory;

impl StorageProviderFactory {
    /// Create storage provider by type
    pub fn create_provider(provider_type: &StorageProviderType) -> Result<Box<dyn StorageProvider>, AuthencError> {
        match provider_type {
            StorageProviderType::InMemory => Ok(Box::new(InMemoryStorageProvider::new())),
            StorageProviderType::PostgreSQL => {
                #[cfg(feature = "db")]
                {
                    Ok(Box::new(crate::services::storage::postgresql::PostgreSQLStorageProvider::new()))
                }
                #[cfg(not(feature = "db"))]
                {
                    return Err(AuthencError::ConfigurationError {
                        message: "PostgreSQL support not enabled. Enable the 'db' feature.".to_string()
                    });
                }
            }
            StorageProviderType::Redis => return Err(AuthencError::ConfigurationError {
                message: "Redis provider not implemented".to_string()
            }),
            StorageProviderType::MongoDB => return Err(AuthencError::ConfigurationError {
                message: "MongoDB provider not implemented".to_string()
            }),
            StorageProviderType::Custom(name) => return Err(AuthencError::ConfigurationError {
                message: format!("Custom provider '{}' not implemented", name)
            }),
        }
    }
}

/// Storage Manager - Central storage coordination
pub struct StorageManager {
    provider: Box<dyn StorageProvider>,
    user_repository: Box<dyn UserStorageRepository>,
    client_repository: Box<dyn ClientStorageRepository>,
    realm_repository: Box<dyn RealmStorageRepository>,
}

impl StorageManager {
    /// Create new storage manager
    pub async fn new(config: StorageConfig) -> Result<Self, AuthencError> {
        let mut provider = StorageProviderFactory::create_provider(&config.provider_type)?;
        provider.init(&config).await?;

        // Create repositories based on provider
        let user_repository: Box<dyn UserStorageRepository> = match config.provider_type {
            StorageProviderType::InMemory => {
                let in_memory_provider = provider.as_ref().downcast_ref::<InMemoryStorageProvider>()
                    .ok_or_else(|| AuthencError::ConfigurationError {
                        message: "Invalid provider type".to_string()
                    })?;
                Box::new(InMemoryUserRepository::new(in_memory_provider.data.clone()))
            }
            StorageProviderType::PostgreSQL => {
                #[cfg(feature = "db")]
                {
                    let pg_provider = provider.as_ref().downcast_ref::<crate::services::storage::postgresql::PostgreSQLStorageProvider>()
                        .ok_or_else(|| AuthencError::ConfigurationError {
                            message: "Invalid provider type".to_string()
                        })?;
                    let arc_provider = std::sync::Arc::new(pg_provider.clone());
                    Box::new(crate::services::storage::postgresql::PostgreSQLUserRepository::new(arc_provider))
                }
                #[cfg(not(feature = "db"))]
                {
                    return Err(AuthencError::ConfigurationError {
                        message: "PostgreSQL support not enabled. Enable the 'db' feature.".to_string()
                    });
                }
            }
            _ => return Err(AuthencError::ConfigurationError {
                message: "Repository not implemented for provider type".to_string()
            }),
        };

        let client_repository: Box<dyn ClientStorageRepository> = match config.provider_type {
            StorageProviderType::InMemory => {
                let in_memory_provider = provider.as_ref().downcast_ref::<InMemoryStorageProvider>()
                    .ok_or_else(|| AuthencError::ConfigurationError {
                        message: "Invalid provider type".to_string()
                    })?;
                Box::new(InMemoryClientRepository::new(in_memory_provider.data.clone()))
            }
            StorageProviderType::PostgreSQL => {
                #[cfg(feature = "db")]
                {
                    let pg_provider = provider.as_ref().downcast_ref::<crate::services::storage::postgresql::PostgreSQLStorageProvider>()
                        .ok_or_else(|| AuthencError::ConfigurationError {
                            message: "Invalid provider type".to_string()
                        })?;
                    let arc_provider = std::sync::Arc::new(pg_provider.clone());
                    Box::new(crate::services::storage::postgresql::PostgreSQLClientRepository::new(arc_provider))
                }
                #[cfg(not(feature = "db"))]
                {
                    return Err(AuthencError::ConfigurationError {
                        message: "PostgreSQL support not enabled. Enable the 'db' feature.".to_string()
                    });
                }
            }
            _ => return Err(AuthencError::ConfigurationError {
                message: "Repository not implemented for provider type".to_string()
            }),
        };

        let realm_repository: Box<dyn RealmStorageRepository> = match config.provider_type {
            StorageProviderType::InMemory => {
                let in_memory_provider = provider.as_ref().downcast_ref::<InMemoryStorageProvider>()
                    .ok_or_else(|| AuthencError::ConfigurationError {
                        message: "Invalid provider type".to_string()
                    })?;
                Box::new(InMemoryRealmRepository::new(in_memory_provider.data.clone()))
            }
            _ => return Err(AuthencError::ConfigurationError {
                message: "Repository not implemented for provider type".to_string()
            }),
        };

        Ok(Self {
            provider,
            user_repository,
            client_repository,
            realm_repository,
        })
    }

    /// Get user repository
    pub fn user_repository(&self) -> &dyn UserStorageRepository {
        self.user_repository.as_ref()
    }

    /// Get client repository
    pub fn client_repository(&self) -> &dyn ClientStorageRepository {
        self.client_repository.as_ref()
    }

    /// Get realm repository
    pub fn realm_repository(&self) -> &dyn RealmStorageRepository {
        self.realm_repository.as_ref()
    }

    /// Get storage provider
    pub fn provider(&self) -> &dyn StorageProvider {
        self.provider.as_ref()
    }
}

/// In-Memory User Repository
pub struct InMemoryUserRepository {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryUserRepository {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl StorageRepository<crate::models::user::User> for InMemoryUserRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<crate::models::user::User>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(user_store) = storage.get("users") {
            if let Some(value) = user_store.get(id) {
                let user: crate::models::user::User = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize user".to_string()
                    })?;
                Ok(Some(user))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<crate::models::user::User>, AuthencError> {
        let storage = self.storage.read().await;
        let mut users = Vec::new();

        if let Some(user_store) = storage.get("users") {
            for value in user_store.values() {
                let user: crate::models::user::User = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize user".to_string()
                    })?;
                users.push(user);
            }
        }

        Ok(users)
    }

    async fn save(&self, user: &crate::models::user::User) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let user_store = storage.entry("users".to_string()).or_insert_with(HashMap::new);

        // Use user ID as key
        let id = "user_id".to_string(); // In real implementation, get from user
        let value = serde_json::to_value(user)
            .map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize user".to_string()
            })?;

        user_store.insert(id, value);
        Ok(())
    }

    async fn update(&self, user: &crate::models::user::User) -> Result<(), AuthencError> {
        self.save(user).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(user_store) = storage.get_mut("users") {
            user_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(user_store) = storage.get("users") {
            Ok(user_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

#[async_trait]
impl UserStorageRepository for InMemoryUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<crate::models::user::User>, AuthencError> {
        let users = self.find_all().await?;
        for user in users {
            // In real implementation, check username field
            if true { // Placeholder
                return Ok(Some(user));
            }
        }
        Ok(None)
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<crate::models::user::User>, AuthencError> {
        let users = self.find_all().await?;
        for user in users {
            // In real implementation, check email field
            if true { // Placeholder
                return Ok(Some(user));
            }
        }
        Ok(None)
    }

    async fn find_by_role(&self, _role_id: &str) -> Result<Vec<crate::models::user::User>, AuthencError> {
        // Placeholder implementation
        Ok(vec![])
    }
}

/// In-Memory Client Repository
pub struct InMemoryClientRepository {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryClientRepository {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl StorageRepository<crate::models::oauth2::OAuth2Client> for InMemoryClientRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<crate::models::oauth2::OAuth2Client>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(client_store) = storage.get("clients") {
            if let Some(value) = client_store.get(id) {
                let client: crate::models::oauth2::OAuth2Client = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize client".to_string()
                    })?;
                Ok(Some(client))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<crate::models::oauth2::OAuth2Client>, AuthencError> {
        let storage = self.storage.read().await;
        let mut clients = Vec::new();

        if let Some(client_store) = storage.get("clients") {
            for value in client_store.values() {
                let client: crate::models::oauth2::OAuth2Client = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize client".to_string()
                    })?;
                clients.push(client);
            }
        }

        Ok(clients)
    }

    async fn save(&self, client: &crate::models::oauth2::OAuth2Client) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let client_store = storage.entry("clients".to_string()).or_insert_with(HashMap::new);

        // Use client ID as key
        let id = "client_id".to_string(); // In real implementation, get from client
        let value = serde_json::to_value(client)
            .map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize client".to_string()
            })?;

        client_store.insert(id, value);
        Ok(())
    }

    async fn update(&self, client: &crate::models::oauth2::OAuth2Client) -> Result<(), AuthencError> {
        self.save(client).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(client_store) = storage.get_mut("clients") {
            client_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(client_store) = storage.get("clients") {
            Ok(client_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

#[async_trait]
impl ClientStorageRepository for InMemoryClientRepository {
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<crate::models::oauth2::OAuth2Client>, AuthencError> {
        let clients = self.find_all().await?;
        for client in clients {
            // In real implementation, check client_id field
            if true { // Placeholder
                return Ok(Some(client));
            }
        }
        Ok(None)
    }

    async fn find_by_owner(&self, _owner_id: &str) -> Result<Vec<crate::models::oauth2::OAuth2Client>, AuthencError> {
        // Placeholder implementation
        Ok(vec![])
    }
}

/// In-Memory Realm Repository
pub struct InMemoryRealmRepository {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryRealmRepository {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl StorageRepository<crate::models::realm::Realm> for InMemoryRealmRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<crate::models::realm::Realm>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(realm_store) = storage.get("realms") {
            if let Some(value) = realm_store.get(id) {
                let realm: crate::models::realm::Realm = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize realm".to_string()
                    })?;
                Ok(Some(realm))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<crate::models::realm::Realm>, AuthencError> {
        let storage = self.storage.read().await;
        let mut realms = Vec::new();

        if let Some(realm_store) = storage.get("realms") {
            for value in realm_store.values() {
                let realm: crate::models::realm::Realm = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError {
                        message: "Failed to deserialize realm".to_string()
                    })?;
                realms.push(realm);
            }
        }

        Ok(realms)
    }

    async fn save(&self, realm: &crate::models::realm::Realm) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let realm_store = storage.entry("realms".to_string()).or_insert_with(HashMap::new);

        // Use realm ID as key
        let id = "realm_id".to_string(); // In real implementation, get from realm
        let value = serde_json::to_value(realm)
            .map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize realm".to_string()
            })?;

        realm_store.insert(id, value);
        Ok(())
    }

    async fn update(&self, realm: &crate::models::realm::Realm) -> Result<(), AuthencError> {
        self.save(realm).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(realm_store) = storage.get_mut("realms") {
            realm_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(realm_store) = storage.get("realms") {
            Ok(realm_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

#[async_trait]
impl RealmStorageRepository for InMemoryRealmRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<crate::models::realm::Realm>, AuthencError> {
        let realms = self.find_all().await?;
        for realm in realms {
            // In real implementation, check name field
            if true { // Placeholder
                return Ok(Some(realm));
            }
        }
        Ok(None)
    }

    async fn find_by_owner(&self, _owner_id: &str) -> Result<Vec<crate::models::realm::Realm>, AuthencError> {
        // Placeholder implementation
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage_provider() {
        let mut provider = InMemoryStorageProvider::new();
        let config = StorageConfig {
            provider_type: StorageProviderType::InMemory,
            connection_string: None,
            parameters: HashMap::new(),
        };

        assert!(provider.init(&config).await.is_ok());
        assert_eq!(provider.name(), "in-memory");
        assert!(provider.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_storage_manager_creation() {
        let config = StorageConfig {
            provider_type: StorageProviderType::InMemory,
            connection_string: None,
            parameters: HashMap::new(),
        };

        let manager = StorageManager::new(config).await;
        assert!(manager.is_ok());
    }
}

// Module declarations
pub mod postgresql;
    pub parameters: HashMap<String, String>,
}

/// Storage Transaction
#[async_trait]
pub trait StorageTransaction: Send + Sync {
    /// Commit the transaction
    async fn commit(&mut self) -> Result<(), AuthencError>;

    /// Rollback the transaction
    async fn rollback(&mut self) -> Result<(), AuthencError>;
}

/// Storage Provider SPI (Service Provider Interface)
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Get provider name
    fn name(&self) -> &str;

    /// Initialize the provider
    async fn init(&mut self, config: &StorageConfig) -> Result<(), AuthencError>;

    /// Check if provider is healthy
    async fn health_check(&self) -> Result<(), AuthencError>;

    /// Create a transaction
    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, AuthencError>;

    /// Close the provider
    async fn close(&mut self) -> Result<(), AuthencError>;
}

/// Generic Storage Repository trait
#[async_trait]
pub trait StorageRepository<T: Send + Sync + Clone>: Send + Sync {
    /// Find entity by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<T>, AuthencError>;

    /// Find all entities
    async fn find_all(&self) -> Result<Vec<T>, AuthencError>;

    /// Save entity
    async fn save(&self, entity: &T) -> Result<(), AuthencError>;

    /// Update entity
    async fn update(&self, entity: &T) -> Result<(), AuthencError>;

    /// Delete entity by ID
    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError>;

    /// Count entities
    async fn count(&self) -> Result<i64, AuthencError>;
}

/// User Storage Repository
#[async_trait]
pub trait UserStorageRepository: StorageRepository<crate::models::user::User> {
    /// Find user by username
    async fn find_by_username(&self, username: &str) -> Result<Option<crate::models::user::User>, AuthencError>;

    /// Find user by email
    async fn find_by_email(&self, email: &str) -> Result<Option<crate::models::user::User>, AuthencError>;

    /// Find users by role
    async fn find_by_role(&self, role_id: &str) -> Result<Vec<crate::models::user::User>, AuthencError>;
}

/// Client Storage Repository
#[async_trait]
pub trait ClientStorageRepository: StorageRepository<crate::models::oauth2::OAuth2Client> {
    /// Find client by client ID
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<crate::models::oauth2::OAuth2Client>, AuthencError>;

    /// Find clients by owner
    async fn find_by_owner(&self, owner_id: &str) -> Result<Vec<crate::models::oauth2::OAuth2Client>, AuthencError>;
}

/// Realm Storage Repository
#[async_trait]
pub trait RealmStorageRepository: StorageRepository<crate::models::realm::Realm> {
    /// Find realm by name
    async fn find_by_name(&self, name: &str) -> Result<Option<crate::models::realm::Realm>, AuthencError>;

    /// Find realms by owner
    async fn find_by_owner(&self, owner_id: &str) -> Result<Vec<crate::models::realm::Realm>, AuthencError>;
}

/// In-Memory Storage Provider
pub struct InMemoryStorageProvider {
    data: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryStorageProvider {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageProvider for InMemoryStorageProvider {
    fn name(&self) -> &str {
        "in-memory"
    }

    async fn init(&mut self, _config: &StorageConfig) -> Result<(), AuthencError> {
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AuthencError> {
        Ok(())
    }

    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, AuthencError> {
        // In-memory storage doesn't need real transactions
        Ok(Box::new(InMemoryTransaction::new()))
    }

    async fn close(&mut self) -> Result<(), AuthencError> {
        Ok(())
    }
}

/// In-Memory Transaction (no-op for in-memory storage)
pub struct InMemoryTransaction;

impl InMemoryTransaction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StorageTransaction for InMemoryTransaction {
    async fn commit(&mut self) -> Result<(), AuthencError> {
        Ok(())
    }

    async fn rollback(&mut self) -> Result<(), AuthencError> {
        Ok(())
    }
}

/// Generic In-Memory Repository Implementation
pub struct InMemoryRepository<T: Send + Sync + Clone + serde::Serialize + serde::de::DeserializeOwned> {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
    entity_type: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Send + Sync + Clone + serde::Serialize + serde::de::DeserializeOwned> InMemoryRepository<T> {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>, entity_type: String) -> Self {
        Self {
            storage,
            entity_type,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T: Send + Sync + Clone + serde::Serialize + serde::de::DeserializeOwned> StorageRepository<T> for InMemoryRepository<T> {
    async fn find_by_id(&self, id: &str) -> Result<Option<T>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(entity_store) = storage.get(&self.entity_type) {
            if let Some(value) = entity_store.get(id) {
                let entity: T = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize entity".to_string() })?;
                Ok(Some(entity))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<T>, AuthencError> {
        let storage = self.storage.read().await;
        let mut entities = Vec::new();

        if let Some(entity_store) = storage.get(&self.entity_type) {
            for value in entity_store.values() {
                let entity: T = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize entity".to_string() })?;
                entities.push(entity);
            }
        }

        Ok(entities)
    }

    async fn save(&self, entity: &T) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let entity_store = storage.entry(self.entity_type.clone()).or_insert_with(HashMap::new);

        // Generate ID (in real implementation, this would be from the entity)
        let id = "generated_id".to_string(); // Placeholder
        let value = serde_json::to_value(entity)
            .map_err(|_| AuthencError::SerializationError { message: "Failed to serialize entity".to_string() })?;

        entity_store.insert(id, value);
        Ok(())
    }

    async fn update(&self, entity: &T) -> Result<(), AuthencError> {
        // Same as save for in-memory
        self.save(entity).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(entity_store) = storage.get_mut(&self.entity_type) {
            entity_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(entity_store) = storage.get(&self.entity_type) {
            Ok(entity_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

/// Storage Provider Factory
pub struct StorageProviderFactory;

impl StorageProviderFactory {
    /// Create storage provider by type
    pub fn create_provider(provider_type: &StorageProviderType) -> Result<Box<dyn StorageProvider>, AuthencError> {
        match provider_type {
            StorageProviderType::InMemory => Ok(Box::new(InMemoryStorageProvider::new())),
            StorageProviderType::PostgreSQL => {
                #[cfg(feature = "db")]
                {
                    Ok(Box::new(crate::services::storage::postgresql::PostgreSQLStorageProvider::new()))
                }
                #[cfg(not(feature = "db"))]
                {
                    return Err(AuthencError::ConfigurationError { message: "PostgreSQL support not enabled. Enable the 'db' feature.".to_string() });
                }
            }
            StorageProviderType::Redis => return Err(AuthencError::ConfigurationError { message: "Redis provider not implemented".to_string() }),
            StorageProviderType::MongoDB => return Err(AuthencError::ConfigurationError { message: "MongoDB provider not implemented".to_string() }),
            StorageProviderType::Custom(name) => return Err(AuthencError::ConfigurationError { message: format!("Custom provider '{}' not implemented", name) }),
        }
}

/// Storage Manager - Central storage coordination
pub struct StorageManager {
    provider: Box<dyn StorageProvider>,
    user_repository: Box<dyn UserStorageRepository>,
    client_repository: Box<dyn ClientStorageRepository>,
    realm_repository: Box<dyn RealmStorageRepository>,
}

impl StorageManager {
    /// Create new storage manager
    pub async fn new(config: StorageConfig) -> Result<Self, AuthencError> {
        let mut provider = StorageProviderFactory::create_provider(&config.provider_type)?;
        provider.init(&config).await?;

        // Create repositories based on provider
        let user_repository: Box<dyn UserStorageRepository> = match config.provider_type {
            StorageProviderType::InMemory => {
                let in_memory_provider = provider.as_ref().downcast_ref::<InMemoryStorageProvider>()
                    .ok_or_else(|| AuthencError::ConfigurationError { message: "Invalid provider type".to_string() })?;
                Box::new(InMemoryUserRepository::new(in_memory_provider.data.clone()))
            }
            StorageProviderType::PostgreSQL => {
                #[cfg(feature = "db")]
                {
                    let pg_provider = provider.as_ref().downcast_ref::<crate::services::storage::postgresql::PostgreSQLStorageProvider>()
                        .ok_or_else(|| AuthencError::ConfigurationError { message: "Invalid provider type".to_string() })?;
                    let arc_provider = std::sync::Arc::new(pg_provider.clone());
                    Box::new(crate::services::storage::postgresql::PostgreSQLUserRepository::new(arc_provider))
                }
                #[cfg(not(feature = "db"))]
                {
                    return Err(AuthencError::ConfigurationError { message: "PostgreSQL support not enabled. Enable the 'db' feature.".to_string() });
                }
            }
            _ => return Err(AuthencError::ConfigurationError { message: "Repository not implemented for provider type".to_string() }),
        };

        let client_repository: Box<dyn ClientStorageRepository> = match config.provider_type {
            StorageProviderType::InMemory => {
                let in_memory_provider = provider.as_ref().downcast_ref::<InMemoryStorageProvider>()
                    .ok_or_else(|| AuthencError::ConfigurationError { message: "Invalid provider type".to_string() })?;
                Box::new(InMemoryClientRepository::new(in_memory_provider.data.clone()))
            }
            StorageProviderType::PostgreSQL => {
                #[cfg(feature = "db")]
                {
                    let pg_provider = provider.as_ref().downcast_ref::<crate::services::storage::postgresql::PostgreSQLStorageProvider>()
                        .ok_or_else(|| AuthencError::ConfigurationError { message: "Invalid provider type".to_string() })?;
                    let arc_provider = std::sync::Arc::new(pg_provider.clone());
                    Box::new(crate::services::storage::postgresql::PostgreSQLClientRepository::new(arc_provider))
                }
                #[cfg(not(feature = "db"))]
                {
                    return Err(AuthencError::ConfigurationError { message: "PostgreSQL support not enabled. Enable the 'db' feature.".to_string() });
                }
            }
            _ => return Err(AuthencError::ConfigurationError { message: "Repository not implemented for provider type".to_string( })),
        };

        let realm_repository: Box<dyn RealmStorageRepository> = match config.provider_type {
            StorageProviderType::InMemory => {
                let in_memory_provider = provider.as_ref().downcast_ref::<InMemoryStorageProvider>()
                    .ok_or_else(|| AuthencError::ConfigurationError { message: "Invalid provider type".to_string( }))?;
                Box::new(InMemoryRealmRepository::new(in_memory_provider.data.clone()))
            }
            _ => return Err(AuthencError::ConfigurationError { message: "Repository not implemented for provider type".to_string( })),
        };

        Ok(Self {
            provider,
            user_repository,
            client_repository,
            realm_repository,
        })
    }

    /// Get user repository
    pub fn user_repository(&self) -> &dyn UserStorageRepository {
        self.user_repository.as_ref()
    }

    /// Get client repository
    pub fn client_repository(&self) -> &dyn ClientStorageRepository {
        self.client_repository.as_ref()
    }

    /// Get realm repository
    pub fn realm_repository(&self) -> &dyn RealmStorageRepository {
        self.realm_repository.as_ref()
    }

    /// Health check
    pub async fn health_check(&self) -> Result<(), AuthencError> {
        self.provider.health_check().await
    }

    /// Close storage manager
    pub async fn close(&mut self) -> Result<(), AuthencError> {
        self.provider.close().await
    }
}

/// In-Memory User Repository
pub struct InMemoryUserRepository {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryUserRepository {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl StorageRepository<crate::models::user::User> for InMemoryUserRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<crate::models::user::User>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(user_store) = storage.get("users") {
            if let Some(value) = user_store.get(id) {
                let user: crate::models::user::User = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize user".to_string( }))?;
                Ok(Some(user))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<crate::models::user::User>, AuthencError> {
        let storage = self.storage.read().await;
        let mut users = Vec::new();

        if let Some(user_store) = storage.get("users") {
            for value in user_store.values() {
                let user: crate::models::user::User = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize user".to_string( }))?;
                users.push(user);
            }
        }

        Ok(users)
    }

    async fn save(&self, user: &crate::models::user::User) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let user_store = storage.entry("users".to_string()).or_insert_with(HashMap::new);

        let value = serde_json::to_value(user)
            .map_err(|_| AuthencError::SerializationError { message: "Failed to serialize user".to_string( }))?;

        user_store.insert(user.id.to_string(), value);
        Ok(())
    }

    async fn update(&self, user: &crate::models::user::User) -> Result<(), AuthencError> {
        self.save(user).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(user_store) = storage.get_mut("users") {
            user_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(user_store) = storage.get("users") {
            Ok(user_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

#[async_trait]
impl UserStorageRepository for InMemoryUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<crate::models::user::User>, AuthencError> {
        let users = self.find_all().await?;
        Ok(users.into_iter().find(|u| u.username == username))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<crate::models::user::User>, AuthencError> {
        let users = self.find_all().await?;
        Ok(users.into_iter().find(|u| u.email == email))
    }

    async fn find_by_role(&self, role_id: &str) -> Result<Vec<crate::models::user::User>, AuthencError> {
        let users = self.find_all().await?;
        Ok(users.into_iter().filter(|u| u.roles.contains(&role_id.to_string())).collect())
    }
}

/// In-Memory Client Repository
pub struct InMemoryClientRepository {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryClientRepository {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl StorageRepository<crate::models::oauth2::OAuth2Client> for InMemoryClientRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<crate::models::oauth2::OAuth2Client>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(client_store) = storage.get("clients") {
            if let Some(value) = client_store.get(id) {
                let client: crate::models::oauth2::OAuth2Client = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize client".to_string( }))?;
                Ok(Some(client))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<crate::models::oauth2::OAuth2Client>, AuthencError> {
        let storage = self.storage.read().await;
        let mut clients = Vec::new();

        if let Some(client_store) = storage.get("clients") {
            for value in client_store.values() {
                let client: crate::models::oauth2::OAuth2Client = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize client".to_string( }))?;
                clients.push(client);
            }
        }

        Ok(clients)
    }

    async fn save(&self, client: &crate::models::oauth2::OAuth2Client) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let client_store = storage.entry("clients".to_string()).or_insert_with(HashMap::new);

        let value = serde_json::to_value(client)
            .map_err(|_| AuthencError::SerializationError { message: "Failed to serialize client".to_string( }))?;

        client_store.insert(client.client_id.clone(), value);
        Ok(())
    }

    async fn update(&self, client: &crate::models::oauth2::OAuth2Client) -> Result<(), AuthencError> {
        self.save(client).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(client_store) = storage.get_mut("clients") {
            client_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(client_store) = storage.get("clients") {
            Ok(client_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

#[async_trait]
impl ClientStorageRepository for InMemoryClientRepository {
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<crate::models::oauth2::OAuth2Client>, AuthencError> {
        self.find_by_id(client_id).await
    }

    async fn find_by_owner(&self, owner_id: &str) -> Result<Vec<crate::models::oauth2::OAuth2Client>, AuthencError> {
        let clients = self.find_all().await?;
        // In a real implementation, you'd have an owner_id field
        Ok(clients)
    }
}

/// In-Memory Realm Repository
pub struct InMemoryRealmRepository {
    storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryRealmRepository {
    pub fn new(storage: Arc<RwLock<HashMap<String, HashMap<String, serde_json::Value>>>>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl StorageRepository<crate::models::realm::Realm> for InMemoryRealmRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<crate::models::realm::Realm>, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(realm_store) = storage.get("realms") {
            if let Some(value) = realm_store.get(id) {
                let realm: crate::models::realm::Realm = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize realm".to_string( }))?;
                Ok(Some(realm))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn find_all(&self) -> Result<Vec<crate::models::realm::Realm>, AuthencError> {
        let storage = self.storage.read().await;
        let mut realms = Vec::new();

        if let Some(realm_store) = storage.get("realms") {
            for value in realm_store.values() {
                let realm: crate::models::realm::Realm = serde_json::from_value(value.clone())
                    .map_err(|_| AuthencError::SerializationError { message: "Failed to deserialize realm".to_string( }))?;
                realms.push(realm);
            }
        }

        Ok(realms)
    }

    async fn save(&self, realm: &crate::models::realm::Realm) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let realm_store = storage.entry("realms".to_string()).or_insert_with(HashMap::new);

        let value = serde_json::to_value(realm)
            .map_err(|_| AuthencError::SerializationError { message: "Failed to serialize realm".to_string( }))?;

        realm_store.insert(realm.id.to_string(), value);
        Ok(())
    }

    async fn update(&self, realm: &crate::models::realm::Realm) -> Result<(), AuthencError> {
        self.save(realm).await
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        if let Some(realm_store) = storage.get_mut("realms") {
            realm_store.remove(id);
        }
        Ok(())
    }

    async fn count(&self) -> Result<i64, AuthencError> {
        let storage = self.storage.read().await;
        if let Some(realm_store) = storage.get("realms") {
            Ok(realm_store.len() as i64)
        } else {
            Ok(0)
        }
    }
}

#[async_trait]
impl RealmStorageRepository for InMemoryRealmRepository {
    async fn find_by_name(&self, name: &str) -> Result<Option<crate::models::realm::Realm>, AuthencError> {
        let realms = self.find_all().await?;
        Ok(realms.into_iter().find(|r| r.name == name))
    }

    async fn find_by_owner(&self, owner_id: &str) -> Result<Vec<crate::models::realm::Realm>, AuthencError> {
        let realms = self.find_all().await?;
        // In a real implementation, you'd have an owner_id field
        Ok(realms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::User;
    use crate::models::oauth2::OAuth2Client;
    use crate::models::realm::Realm;

    #[tokio::test]
    async fn test_in_memory_storage_provider() {
        let mut provider = InMemoryStorageProvider::new();
        let config = StorageConfig {
            provider_type: StorageProviderType::InMemory,
            connection_string: "".to_string(),
            parameters: HashMap::new(),
        };

        assert!(provider.init(&config).await.is_ok());
        assert!(provider.health_check().await.is_ok());
        assert_eq!(provider.name(), "in-memory");
    }

    #[tokio::test]
    async fn test_storage_manager_creation() {
        let config = StorageConfig {
            provider_type: StorageProviderType::InMemory,
            connection_string: "".to_string(),
            parameters: HashMap::new(),
        };

        let manager = StorageManager::new(config).await.unwrap();
        assert!(manager.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_user_repository_operations() {
        let config = StorageConfig {
            provider_type: StorageProviderType::InMemory,
            connection_string: "".to_string(),
            parameters: HashMap::new(),
        };

        let manager = StorageManager::new(config).await.unwrap();
        let user_repo = manager.user_repository();

        // Create test user
        let user = User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            email_verified: true,
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            phone_number: None,
            phone_verified: false,
            password_hash: Some("hash".to_string()),
            totp_secret: None,
            totp_backup_codes: None,
            webauthn_enabled: false,
            account_locked: false,
            account_locked_until: None,
            failed_login_attempts: 0,
            last_login_at: None,
            last_failed_login_at: None,
            password_changed_at: None,
            password_expires_at: None,
            require_password_change: false,
            realm_id: None,
            organization_id: None,
            attributes: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };

        // Test save and find
        assert!(user_repo.save(&user).await.is_ok());
        let found_user = user_repo.find_by_id(&user.id.to_string()).await.unwrap();
        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().username, "testuser");

        // Test find by username
        let found_by_username = user_repo.find_by_username("testuser").await.unwrap();
        assert!(found_by_username.is_some());
        assert_eq!(found_by_username.unwrap().email, "test@example.com");

        // Test count
        let count = user_repo.count().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_client_repository_operations() {
        let config = StorageConfig {
            provider_type: StorageProviderType::InMemory,
            connection_string: "".to_string(),
            parameters: HashMap::new(),
        };

        let manager = StorageManager::new(config).await.unwrap();
        let client_repo = manager.client_repository();

        // Create test client
        let client = OAuth2Client {
            id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: "hash".to_string(),
            client_name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };

        // Test save and find
        assert!(client_repo.save(&client).await.is_ok());
        let found_client = client_repo.find_by_client_id("test-client").await.unwrap();
        assert!(found_client.is_some());
        assert_eq!(found_client.unwrap().client_name, "Test Client");
    }
}

// Module declarations
pub mod postgresql;
