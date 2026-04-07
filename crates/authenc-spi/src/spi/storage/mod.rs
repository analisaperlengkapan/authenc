use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use authenc_core::error::{AuthencError as Error, Result};
use authenc_models::models::group::Group;
use authenc_models::models::oidc_client::OidcClient;
use authenc_models::models::role::Role;
use authenc_models::models::user::User;
use crate::spi::store_traits::{UserStoreTrait, OidcClientStoreTrait, RoleStoreTrait, GroupStoreTrait};
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Storage provider types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageProviderType {
    /// User storage provider
    User,
    /// Client storage provider
    Client,
    /// Role storage provider
    Role,
    /// Group storage provider
    Group,
}

/// Storage query context for filtering and pagination
#[derive(Debug, Clone, Default)]
pub struct StorageQueryContext {
    /// Optional realm identifier to filter storage items
    pub realm_id: Option<String>,
    /// Optional search string for storage filtering
    pub search: Option<String>,
    /// Optional first result index for pagination
    pub first: Option<i32>,
    /// Optional maximum number of results for pagination
    pub max: Option<i32>,
    /// Additional filters as key-value pairs
    pub filters: HashMap<String, String>,
}

/// Storage provider trait - base trait for all storage providers
#[async_trait]
pub trait StorageProvider: Provider + Send + Sync {
    /// Get the storage provider type
    fn get_type(&self) -> StorageProviderType;

    /// Get the provider name
    fn get_name(&self) -> &str;
}

/// User storage provider trait
#[async_trait]
pub trait UserStorageProvider: StorageProvider {
    /// Get user by ID
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>>;

    /// Get user by username
    async fn get_user_by_username(
        &self,
        realm_id: &Uuid,
        username: &str,
    ) -> Result<Option<User>>;

    /// Get user by email
    async fn get_user_by_email(
        &self,
        realm_id: &Uuid,
        email: &str,
    ) -> Result<Option<User>>;

    /// Search users
    async fn search_users(&self, query: &str, context: &StorageQueryContext) -> Result<Vec<User>>;

    /// Count users
    async fn count_users(&self, context: &StorageQueryContext) -> Result<i64>;

    /// Create user
    async fn create_user(&self, user: User) -> Result<User>;

    /// Update user
    async fn update_user(&self, user: User) -> Result<User>;

    /// Delete user
    async fn delete_user(&self, user_id: Uuid) -> Result<bool>;
}

/// Client storage provider trait
#[async_trait]
pub trait ClientStorageProvider: StorageProvider {
    /// Get client by ID
    async fn get_client(&self, client_id: Uuid) -> Result<Option<OidcClient>>;

    /// Get client by client_id string
    async fn get_client_by_client_id(&self, client_id: &str) -> Result<Option<OidcClient>>;

    /// Search clients
    async fn search_clients(
        &self,
        query: &str,
        context: &StorageQueryContext,
    ) -> Result<Vec<OidcClient>>;

    /// Count clients
    async fn count_clients(&self, context: &StorageQueryContext) -> Result<i64>;

    /// Create client
    async fn create_client(&self, client: OidcClient) -> Result<OidcClient>;

    /// Update client
    async fn update_client(&self, client: OidcClient) -> Result<OidcClient>;

    /// Delete client
    async fn delete_client(&self, client_id: Uuid) -> Result<bool>;
}

/// Role storage provider trait
#[async_trait]
pub trait RoleStorageProvider: StorageProvider {
    /// Get role by ID
    async fn get_role(&self, role_id: Uuid) -> Result<Option<Role>>;

    /// Get role by name
    async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>>;

    /// Search roles
    async fn search_roles(&self, query: &str, context: &StorageQueryContext) -> Result<Vec<Role>>;

    /// Count roles
    async fn count_roles(&self, context: &StorageQueryContext) -> Result<i64>;

    /// Create role
    async fn create_role(&self, role: Role) -> Result<Role>;

    /// Update role
    async fn update_role(&self, role: Role) -> Result<Role>;

    /// Delete role
    async fn delete_role(&self, role_id: Uuid) -> Result<bool>;
}

/// Group storage provider trait
#[async_trait]
pub trait GroupStorageProvider: StorageProvider {
    /// Get group by ID
    async fn get_group(&self, group_id: Uuid) -> Result<Option<Group>>;

    /// Get group by name
    async fn get_group_by_name(&self, name: &str) -> Result<Option<Group>>;

    /// Search groups
    async fn search_groups(&self, query: &str, context: &StorageQueryContext)
    -> Result<Vec<Group>>;

    /// Count groups
    async fn count_groups(&self, context: &StorageQueryContext) -> Result<i64>;

    /// Create group
    async fn create_group(&self, group: Group) -> Result<Group>;

    /// Update group
    async fn update_group(&self, group: Group) -> Result<Group>;

    /// Delete group
    async fn delete_group(&self, group_id: Uuid) -> Result<bool>;
}

/// Default user storage provider implementation
pub struct DefaultUserStorageProvider {
    user_store: Arc<dyn UserStoreTrait>,
}

impl DefaultUserStorageProvider {
    /// Create a new default user storage provider
    pub fn new(user_store: Arc<dyn UserStoreTrait>) -> Self {
        Self { user_store }
    }
}

#[async_trait]
impl StorageProvider for DefaultUserStorageProvider {
    fn get_type(&self) -> StorageProviderType {
        StorageProviderType::User
    }

    fn get_name(&self) -> &str {
        "default-user"
    }
}

#[async_trait]
impl UserStorageProvider for DefaultUserStorageProvider {
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>> {
        self.user_store.get_user(user_id).await
    }

    async fn get_user_by_username(
        &self,
        realm_id: &Uuid,
        username: &str,
    ) -> Result<Option<User>> {
        self.user_store.get_user_by_username(realm_id, username).await
    }

    async fn get_user_by_email(
        &self,
        realm_id: &Uuid,
        email: &str,
    ) -> Result<Option<User>> {
        self.user_store.get_user_by_email(realm_id, email).await
    }

    async fn search_users(&self, query: &str, _context: &StorageQueryContext) -> Result<Vec<User>> {
        let all_users = self.user_store.get_all().await?;
        if query.is_empty() {
            Ok(all_users)
        } else {
            Ok(all_users
                .into_iter()
                .filter(|user: &User| user.username.contains(query) || user.email.contains(query))
                .collect())
        }
    }

    async fn count_users(&self, _context: &StorageQueryContext) -> Result<i64> {
        let all_users = self.user_store.get_all().await?;
        Ok(all_users.len() as i64)
    }

    async fn create_user(&self, user: User) -> Result<User> {
        let request = authenc_models::models::user::CreateUserRequest {
            username: user.username.clone(),
            email: user.email.clone(),
            password: None,
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            phone_number: user.phone_number.clone(),
            realm_id: user.realm_id,
            organization_id: user.organization_id,
            attributes: user.attributes.clone(),
            enabled: Some(user.enabled),
            email_verified: Some(user.email_verified),
            require_password_change: Some(user.require_password_change),
        };
        self.user_store.add_user(request).await
    }

    async fn update_user(&self, user: User) -> Result<User> {
        let request = authenc_models::models::user::UpdateUserRequest {
            username: Some(user.username.clone()),
            email: Some(user.email.clone()),
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            phone_number: user.phone_number.clone(),
            enabled: Some(user.enabled),
            email_verified: Some(user.email_verified),
            phone_verified: Some(user.phone_verified),
            require_password_change: Some(user.require_password_change),
            organization_id: user.organization_id,
            attributes: user.attributes.clone(),
        };
        self.user_store.update_user(user.id, request).await
    }

    async fn delete_user(&self, _user_id: Uuid) -> Result<bool> {
        Ok(false)
    }
}

impl Provider for DefaultUserStorageProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Default client storage provider implementation
pub struct DefaultClientStorageProvider {
    oidc_client_store: Arc<dyn OidcClientStoreTrait>,
}

impl DefaultClientStorageProvider {
    /// Create a new default client storage provider
    pub fn new(
        oidc_client_store: Arc<dyn OidcClientStoreTrait>,
    ) -> Self {
        Self { oidc_client_store }
    }
}

#[async_trait]
impl StorageProvider for DefaultClientStorageProvider {
    fn get_type(&self) -> StorageProviderType {
        StorageProviderType::Client
    }

    fn get_name(&self) -> &str {
        "default-client"
    }
}

#[async_trait]
impl ClientStorageProvider for DefaultClientStorageProvider {
    async fn get_client(&self, _client_id: Uuid) -> Result<Option<OidcClient>> {
        Ok(None)
    }

    async fn get_client_by_client_id(&self, client_id: &str) -> Result<Option<OidcClient>> {
        self.oidc_client_store.get(client_id).await
    }

    async fn search_clients(
        &self,
        query: &str,
        _context: &StorageQueryContext,
    ) -> Result<Vec<OidcClient>> {
        let all_clients = self.oidc_client_store.all().await?;
        if query.is_empty() {
            Ok(all_clients)
        } else {
            Ok(all_clients
                .into_iter()
                .filter(|client| client.name.contains(query) || client.client_id.contains(query))
                .collect())
        }
    }

    async fn count_clients(&self, _context: &StorageQueryContext) -> Result<i64> {
        let all_clients = self.oidc_client_store.all().await?;
        Ok(all_clients.len() as i64)
    }

    async fn create_client(&self, client: OidcClient) -> Result<OidcClient> {
        self.oidc_client_store.add(client.clone()).await?;
        Ok(client)
    }

    async fn update_client(&self, _client: OidcClient) -> Result<OidcClient> {
        Err(Error::validation(
            "Client update not implemented".to_string(),
        ))
    }

    async fn delete_client(&self, client_id: Uuid) -> Result<bool> {
        let client_id_str = client_id.to_string();
        self.oidc_client_store.delete(&client_id_str).await
    }
}

impl Provider for DefaultClientStorageProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Default role storage provider implementation
pub struct DefaultRoleStorageProvider {
    role_store: Arc<dyn RoleStoreTrait>,
}

impl DefaultRoleStorageProvider {
    /// Create a new default role storage provider
    pub fn new(role_store: Arc<dyn RoleStoreTrait>) -> Self {
        Self { role_store }
    }
}

#[async_trait]
impl StorageProvider for DefaultRoleStorageProvider {
    fn get_type(&self) -> StorageProviderType {
        StorageProviderType::Role
    }

    fn get_name(&self) -> &str {
        "default-role"
    }
}

#[async_trait]
impl RoleStorageProvider for DefaultRoleStorageProvider {
    async fn get_role(&self, _role_id: Uuid) -> Result<Option<Role>> {
        Ok(None)
    }

    async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>> {
        Ok(self.role_store.get_by_name(name))
    }

    async fn search_roles(&self, query: &str, _context: &StorageQueryContext) -> Result<Vec<Role>> {
        let all_roles = self.role_store.get_all();
        if query.is_empty() {
            Ok(all_roles.as_ref().clone())
        } else {
            Ok(all_roles
                .iter()
                .filter(|role| role.name.contains(query))
                .cloned()
                .collect())
        }
    }

    async fn count_roles(&self, _context: &StorageQueryContext) -> Result<i64> {
        Ok(self.role_store.get_all().len() as i64)
    }

    async fn create_role(&self, role: Role) -> Result<Role> {
        self.role_store.add_role(role.clone());
        Ok(role)
    }

    async fn update_role(&self, role: Role) -> Result<Role> {
        if let Err(e) = self.role_store.update_role(role.clone()) {
            return Err(Error::validation(format!("Failed to update role: {}", e)));
        }
        Ok(role)
    }

    async fn delete_role(&self, role_id: Uuid) -> Result<bool> {
        // Find the role first to get its name and realm_id
        let role = self.role_store.get_all().iter().find(|r| r.id == role_id).cloned();

        if let Some(r) = role {
            let realm_id = r.realm_id.unwrap_or_default().to_string();
            if self.role_store.delete_by_name(&realm_id, &r.name).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Provider for DefaultRoleStorageProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Default group storage provider implementation
pub struct DefaultGroupStorageProvider {
    group_store: Arc<dyn GroupStoreTrait>,
}

impl DefaultGroupStorageProvider {
    /// Create a new default group storage provider
    pub fn new(group_store: Arc<dyn GroupStoreTrait>) -> Self {
        Self { group_store }
    }
}

#[async_trait]
impl StorageProvider for DefaultGroupStorageProvider {
    fn get_type(&self) -> StorageProviderType {
        StorageProviderType::Group
    }

    fn get_name(&self) -> &str {
        "default-group"
    }
}

#[async_trait]
impl GroupStorageProvider for DefaultGroupStorageProvider {
    async fn get_group(&self, group_id: Uuid) -> Result<Option<Group>> {
        Ok(self.group_store.get(&group_id))
    }

    async fn get_group_by_name(&self, name: &str) -> Result<Option<Group>> {
        let all_groups = self.group_store.all();
        Ok(all_groups.into_iter().find(|g| g.name == name))
    }

    async fn search_groups(
        &self,
        query: &str,
        _context: &StorageQueryContext,
    ) -> Result<Vec<Group>> {
        let all_groups = self.group_store.all();
        if query.is_empty() {
            Ok(all_groups)
        } else {
            Ok(all_groups
                .into_iter()
                .filter(|group| group.name.contains(query))
                .collect())
        }
    }

    async fn count_groups(&self, _context: &StorageQueryContext) -> Result<i64> {
        Ok(self.group_store.all().len() as i64)
    }

    async fn create_group(&self, group: Group) -> Result<Group> {
        if let Some(created) =
            self.group_store
                .create(group.realm_id, &group.name, group.description.clone())
        {
            Ok(created)
        } else {
            Err(Error::validation("Failed to create group".to_string()))
        }
    }

    async fn update_group(&self, _group: Group) -> Result<Group> {
        Err(Error::validation(
            "Group update not implemented".to_string(),
        ))
    }

    async fn delete_group(&self, group_id: Uuid) -> Result<bool> {
        Ok(self.group_store.delete(&group_id))
    }
}

impl Provider for DefaultGroupStorageProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Storage provider factory trait
#[async_trait]
pub trait StorageProviderFactory: ProviderFactory<dyn StorageProvider> {
    /// Create a storage provider instance
    fn create_storage_provider(
        &self,
        provider_type: StorageProviderType,
    ) -> Box<dyn StorageProvider + Send + Sync>;
}

/// Default storage provider factory
pub struct DefaultStorageProviderFactory {
    user_store: Arc<dyn UserStoreTrait>,
    oidc_client_store: Arc<dyn OidcClientStoreTrait>,
    role_store: Arc<dyn RoleStoreTrait>,
    group_store: Arc<dyn GroupStoreTrait>,
}

impl DefaultStorageProviderFactory {
    /// Create a new default storage provider factory with the given stores
    pub fn new(
        user_store: Arc<dyn UserStoreTrait>,
        oidc_client_store: Arc<dyn OidcClientStoreTrait>,
        role_store: Arc<dyn RoleStoreTrait>,
        group_store: Arc<dyn GroupStoreTrait>,
    ) -> Self {
        Self {
            user_store,
            oidc_client_store,
            role_store,
            group_store,
        }
    }
}

impl ProviderFactory<dyn StorageProvider> for DefaultStorageProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn StorageProvider>, SpiError> {
        Ok(Box::new(DefaultUserStorageProvider::new(
            self.user_store.clone(),
        )))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-storage"
    }
}

impl StorageProviderFactory for DefaultStorageProviderFactory {
    fn create_storage_provider(
        &self,
        provider_type: StorageProviderType,
    ) -> Box<dyn StorageProvider + Send + Sync> {
        match provider_type {
            StorageProviderType::User => {
                Box::new(DefaultUserStorageProvider::new(self.user_store.clone()))
            }
            StorageProviderType::Client => Box::new(DefaultClientStorageProvider::new(
                self.oidc_client_store.clone(),
            )),
            StorageProviderType::Role => {
                Box::new(DefaultRoleStorageProvider::new(self.role_store.clone()))
            }
            StorageProviderType::Group => {
                Box::new(DefaultGroupStorageProvider::new(self.group_store.clone()))
            }
        }
    }
}

/// Storage SPI implementation
pub struct StorageSpi;

impl Spi for StorageSpi {
    fn get_name(&self) -> &'static str {
        "storage"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "StorageProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "StorageProviderFactory"
    }
}
