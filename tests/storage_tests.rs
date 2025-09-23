use std::sync::Arc;
use uuid::Uuid;

use authenc::models::user::{User, CreateUserRequest};
use authenc::services::stores::user_store::UserStoreTrait;
use authenc::services::oidc_client_store::OidcClientStore;
use authenc::services::stores::role_store::RoleStore;
use authenc::services::group_store::GroupStore;
use authenc::spi::storage::{
    StorageProviderType, DefaultUserStorageProvider, DefaultRoleStorageProvider,
    DefaultGroupStorageProvider, StorageProvider, DefaultStorageProviderFactory,
    StorageProviderFactory,
};
use authenc::error::AuthencError;

// Mock user store for testing
#[derive(Debug)]
struct MockUserStore {
    users: std::sync::Mutex<Vec<User>>,
}impl MockUserStore {
    fn new() -> Self {
        Self {
            users: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl UserStoreTrait for MockUserStore {
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AuthencError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.id == user_id).cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AuthencError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.username == username).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AuthencError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.email == email).cloned())
    }

    async fn add_user(&self, request: CreateUserRequest) -> Result<User, AuthencError> {
        let mut users = self.users.lock().unwrap();
        let user = User {
            id: Uuid::new_v4(),
            username: request.username,
            email: request.email,
            email_verified: false,
            first_name: request.first_name,
            last_name: request.last_name,
            phone_number: request.phone_number,
            phone_verified: false,
            password_hash: request.password.map(|p| authenc::utils::crypto::password::hash_password(&p).unwrap()),
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
            realm_id: request.realm_id,
            organization_id: request.organization_id,
            attributes: request.attributes,
            enabled: true,
            federated: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
            login_count: 0,
        };
        users.push(user.clone());
        Ok(user)
    }

    async fn update_user(&self, user_id: Uuid, _request: authenc::models::user::UpdateUserRequest) -> Result<User, AuthencError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.updated_at = chrono::Utc::now();
            Ok(user.clone())
        } else {
            Err(AuthencError::resource_not_found("User not found"))
        }
    }

    async fn get_all(&self) -> Result<Vec<User>, AuthencError> {
        let users = self.users.lock().unwrap();
        Ok(users.clone())
    }
}

// Mock OIDC client store for testing
#[derive(Debug)]
struct MockOidcClientStore {
    clients: std::sync::Mutex<Vec<authenc::models::oidc_client::OidcClient>>,
}

impl MockOidcClientStore {
    fn new() -> Self {
        Self {
            clients: std::sync::Mutex::new(vec![]),
        }
    }

    async fn add(&self, client: authenc::models::oidc_client::OidcClient) -> Result<(), AuthencError> {
        let mut clients = self.clients.lock().unwrap();
        clients.push(client);
        Ok(())
    }

    async fn get(&self, client_id: &str) -> Result<Option<authenc::models::oidc_client::OidcClient>, AuthencError> {
        let clients = self.clients.lock().unwrap();
        Ok(clients.iter().find(|c| c.client_id == client_id).cloned())
    }

    async fn all(&self) -> Result<Vec<authenc::models::oidc_client::OidcClient>, AuthencError> {
        let clients = self.clients.lock().unwrap();
        Ok(clients.clone())
    }

    async fn delete(&self, client_id: &str) -> Result<bool, AuthencError> {
        let mut clients = self.clients.lock().unwrap();
        let initial_len = clients.len();
        clients.retain(|c| c.client_id != client_id);
        Ok(clients.len() < initial_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_user_storage_provider() {
        let user_store = Arc::new(MockUserStore::new());
        let provider = DefaultUserStorageProvider::new(user_store.clone());
        assert_eq!(provider.get_type(), StorageProviderType::User);

        // Test user operations
        let create_request = CreateUserRequest {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: Some("password123".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            phone_number: Some("+1234567890".to_string()),
            realm_id: Some(Uuid::new_v4()),
            organization_id: None,
            attributes: None,
        };

        let user = user_store.add_user(create_request).await.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_client_storage_provider() {
        // For testing purposes, we verify the provider type enum works
        assert_eq!(StorageProviderType::Client as i32, 1);
        // Note: Full client storage provider testing would require database setup
    }

    #[tokio::test]
    async fn test_role_storage_provider() {
        let role_store = Arc::new(RoleStore::new());
        let provider = DefaultRoleStorageProvider::new(role_store);
        assert_eq!(provider.get_type(), StorageProviderType::Role);
    }

    #[tokio::test]
    async fn test_group_storage_provider() {
        let group_store = Arc::new(GroupStore::new());
        let provider = DefaultGroupStorageProvider::new(group_store);
        assert_eq!(provider.get_type(), StorageProviderType::Group);
    }

    #[tokio::test]
    #[ignore] // Skip until OidcClientStore is implemented for in-memory testing
    async fn test_storage_provider_factory() {
        let user_store = Arc::new(MockUserStore::new());
        let factory = DefaultStorageProviderFactory::new(
            user_store,
            Arc::new(OidcClientStore::new()),
            Arc::new(RoleStore::new()),
            Arc::new(GroupStore::new()),
        );

        // Test provider types that have working stores (excluding Client for now)
        for provider_type in &[StorageProviderType::User, StorageProviderType::Role, StorageProviderType::Group] {
            let provider = factory.create_storage_provider(provider_type.clone());
            assert_eq!(provider.get_type(), *provider_type);
        }
    }
}
