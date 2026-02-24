use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use authenc_database::database::{Database, operations};
use authenc_core::error::AuthencError;
use authenc_models::models::user::{CreateUserRequest, UpdateUserRequest, User};
pub use authenc_spi::spi::store_traits::UserStoreTrait;

/// User store for managing users in the database
#[derive(Debug, Clone)]
pub struct UserStore {
    /// Database instance
    database: Arc<Database>,
}

impl UserStore {
    /// Create a new user store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    /// Get a reference to the database
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }
}

/// Implementation of UserStoreTrait for UserStore
#[async_trait]
impl UserStoreTrait for UserStore {
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_id(&self.database, user_id).await
    }

    async fn get_user_by_username(
        &self,
        realm_id: &Uuid,
        username: &str,
    ) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_username(&self.database, realm_id, username).await
    }

    async fn get_user_by_email(
        &self,
        realm_id: &Uuid,
        email: &str,
    ) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_email(&self.database, realm_id, email).await
    }

    async fn add_user(&self, request: CreateUserRequest) -> Result<User, AuthencError> {
        operations::users::create_user(&self.database, &request).await
    }

    async fn update_user(
        &self,
        user_id: Uuid,
        request: UpdateUserRequest,
    ) -> Result<User, AuthencError> {
        operations::users::update_user(&self.database, user_id, &request).await
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthencError> {
        operations::users::delete_user(&self.database, user_id).await
    }

    async fn get_all(&self) -> Result<Vec<User>, AuthencError> {
        operations::users::get_all_users(&self.database).await
    }

    async fn get_users_by_realm(&self, realm_id: Uuid) -> Result<Vec<User>, AuthencError> {
        operations::users::get_users_by_realm(&self.database, realm_id).await
    }

    async fn update_password(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthencError> {
        operations::users::update_password(&self.database, user_id, &password_hash).await
    }

    async fn record_login(&self, user_id: Uuid) -> Result<(), AuthencError> {
        operations::users::record_login(&self.database, user_id).await
    }

    async fn record_failed_login(&self, user_id: Uuid) -> Result<i32, AuthencError> {
        operations::users::record_failed_login(&self.database, user_id).await
    }

    async fn lock_account(
        &self,
        user_id: Uuid,
        until: Option<DateTime<Utc>>,
    ) -> Result<(), AuthencError> {
        operations::users::lock_account(&self.database, user_id, until).await
    }

    async fn unlock_account(&self, user_id: Uuid) -> Result<(), AuthencError> {
        operations::users::unlock_account(&self.database, user_id).await
    }

    async fn set_reset_token(
        &self,
        user_id: Uuid,
        token_hash: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), AuthencError> {
        operations::users::set_reset_token(&self.database, user_id, token_hash, expires_at).await
    }

    async fn get_user_by_reset_token(&self, token_hash: &str) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_reset_token(&self.database, token_hash).await
    }

    async fn reset_password_transaction(
        &self,
        user_id: Uuid,
        password_hash: String,
        token_hash: String,
    ) -> Result<(), AuthencError> {
        operations::users::reset_password_transaction(&self.database, user_id, &password_hash, &token_hash).await
    }
}
