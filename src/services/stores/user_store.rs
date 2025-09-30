use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::database::{operations, Database};
use crate::error::AuthencError;
use crate::models::user::{CreateUserRequest, UpdateUserRequest, User};

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

/// Trait for user store operations
#[async_trait]
pub trait UserStoreTrait: Send + Sync {
    /// Get user by ID
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AuthencError>;

    /// Get user by username
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AuthencError>;

    /// Get user by email
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AuthencError>;

    /// Create a new user
    async fn add_user(&self, request: CreateUserRequest) -> Result<User, AuthencError>;

    /// Update user
    async fn update_user(
        &self,
        user_id: Uuid,
        request: UpdateUserRequest,
    ) -> Result<User, AuthencError>;

    /// Delete user (soft delete)
    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthencError>;

    /// Get all users
    async fn get_all(&self) -> Result<Vec<User>, AuthencError>;
}

/// Implementation of UserStoreTrait for UserStore
#[async_trait]
impl UserStoreTrait for UserStore {
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_id(&self.database, user_id).await
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_username(&self.database, username).await
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AuthencError> {
        operations::users::get_user_by_email(&self.database, email).await
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
}
