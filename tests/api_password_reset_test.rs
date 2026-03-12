use authenc_core::error::{AuthencError, Result};
use authenc_models::models::user::{CreateUserRequest, UpdateUserRequest, User};
use authenc_services::services::password_reset::PasswordResetService;
use authenc_spi::spi::store_traits::UserStoreTrait;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use sha2::Digest;

// Mock UserStore
struct MockUserStore {
    users: Arc<Mutex<Vec<User>>>,
}

impl MockUserStore {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_test_user(&self, user: User) {
        self.users.lock().unwrap().push(user);
    }
}

#[async_trait]
impl UserStoreTrait for MockUserStore {
    async fn get_user_by_email(&self, _realm_id: &Uuid, email: &str) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.email == email).cloned())
    }

    async fn set_reset_token(&self, user_id: Uuid, token_hash: Option<String>, expires_at: Option<DateTime<Utc>>) -> Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.reset_token_hash = token_hash;
            user.reset_token_expires_at = expires_at;
            Ok(())
        } else {
            // For dummy requests, we return Ok even if user not found (simulating DB behavior for random UUID)
            Ok(())
        }
    }

    async fn get_user_by_reset_token(&self, token_hash: &str) -> Result<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.reset_token_hash.as_deref() == Some(token_hash)).cloned())
    }

    async fn reset_password_transaction(&self, user_id: Uuid, password_hash: String, _token_hash: String) -> Result<()> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.password_hash = Some(password_hash);
            user.reset_token_hash = None;
            user.reset_token_expires_at = None;
            Ok(())
        } else {
            Err(AuthencError::validation("User not found"))
        }
    }

    // Implement other required methods with unimplemented! or dummy returns
    async fn get_user(&self, _user_id: Uuid) -> Result<Option<User>> { Ok(None) }
    async fn get_user_by_username(&self, _realm_id: &Uuid, _username: &str) -> Result<Option<User>> { Ok(None) }
    async fn add_user(&self, _request: CreateUserRequest) -> Result<User> { Err(AuthencError::not_implemented("")) }
    async fn update_user(&self, _user_id: Uuid, _request: UpdateUserRequest) -> Result<User> { Err(AuthencError::not_implemented("")) }
    async fn delete_user(&self, _user_id: Uuid) -> Result<()> { Ok(()) }
    async fn get_all(&self) -> Result<Vec<User>> { Ok(vec![]) }
    async fn get_users_by_realm(&self, _realm_id: Uuid) -> Result<Vec<User>> { Ok(vec![]) }
    async fn update_password(&self, _user_id: Uuid, _password_hash: String) -> Result<()> { Ok(()) }
    async fn record_login(&self, _user_id: Uuid) -> Result<()> { Ok(()) }
    async fn record_failed_login(&self, _user_id: Uuid) -> Result<i32> { Ok(0) }
    async fn lock_account(&self, _user_id: Uuid, _until: Option<DateTime<Utc>>) -> Result<()> { Ok(()) }
    async fn unlock_account(&self, _user_id: Uuid) -> Result<()> { Ok(()) }
}

#[tokio::test]
async fn test_password_reset_service_flow() {
    let mock_store = Arc::new(MockUserStore::new());
    let service = PasswordResetService::new(mock_store.clone());

    // 1. Setup user
    let user_id = Uuid::new_v4();
    let realm_id = Uuid::new_v4();
    let email = "test_reset@example.com";
    let user = User {
        id: user_id,
        email: email.to_string(),
        username: "testresetuser".to_string(),
        realm_id: Some(realm_id),
        enabled: true,
        password_hash: Some("old_password_hash".to_string()),
        ..User::new("testresetuser".to_string(), email.to_string(), None, Some(realm_id))
    };
    mock_store.add_test_user(user);

    // 2. Request Reset
    let result = service.request_reset(email, &realm_id).await;
    assert!(result.is_ok());

    // Check that token is set in mock store
    let users = mock_store.users.lock().unwrap();
    let stored_user = users.iter().find(|u| u.id == user_id).unwrap();
    assert!(stored_user.reset_token_hash.is_some());
    assert!(stored_user.reset_token_expires_at.is_some());

    // 3. Test reset logic manually since we can't extract the random token from service
    // We manually set a known token hash
    let raw_token = "valid-reset-token-for-test";
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw_token.as_bytes());
    let expected_hash = hex::encode(hasher.finalize());
    drop(users); // Release lock before calling set_reset_token on the store directly if needed, or just modify user

    // Update store with known token
    let _ = mock_store.set_reset_token(
        user_id,
        Some(expected_hash),
        Some(Utc::now() + chrono::Duration::hours(1))
    ).await;

    // 4. Call reset_password with known token
    let new_password = "new_secure_password";
    let reset_result = service.reset_password(raw_token, new_password).await;
    assert!(reset_result.is_ok());

    // 5. Assert user's password was changed and token cleared
    let users = mock_store.users.lock().unwrap();
    let updated_user = users.iter().find(|u| u.id == user_id).unwrap();
    assert!(updated_user.reset_token_hash.is_none());
    assert!(updated_user.reset_token_expires_at.is_none());

    // The password hash should have changed
    assert!(updated_user.password_hash.as_deref().unwrap_or("") != "old_password_hash");
}
