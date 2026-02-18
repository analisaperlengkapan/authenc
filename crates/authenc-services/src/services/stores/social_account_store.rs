use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use authenc_database::database::{Database, operations};
use authenc_core::error::AuthencError;
use authenc_models::models::social_account::{CreateSocialAccountRequest, SocialAccount};
use authenc_models::models::social_account::SocialProvider;

/// Social account store for managing social account links in the database
#[derive(Debug, Clone)]
pub struct SocialAccountStore {
    /// Database instance
    database: Arc<Database>,
}

impl SocialAccountStore {
    /// Create a new social account store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    /// Get a reference to the database
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }
}

/// Trait for social account store operations
#[async_trait]
pub trait SocialAccountStoreTrait: Send + Sync {
    /// Get social account by ID
    async fn get_social_account(
        &self,
        account_id: Uuid,
    ) -> Result<Option<SocialAccount>, AuthencError>;

    /// Get social accounts for a user
    async fn get_user_social_accounts(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SocialAccount>, AuthencError>;

    /// Get social account by provider and provider user ID
    async fn get_social_account_by_provider(
        &self,
        provider: &SocialProvider,
        provider_user_id: &str,
    ) -> Result<Option<SocialAccount>, AuthencError>;

    /// Check if user has social account linked for provider
    async fn has_social_account(
        &self,
        user_id: Uuid,
        provider: &SocialProvider,
    ) -> Result<bool, AuthencError>;

    /// Create a new social account link
    async fn add_social_account(
        &self,
        user_id: Uuid,
        request: CreateSocialAccountRequest,
    ) -> Result<SocialAccount, AuthencError>;

    /// Update social account information
    async fn update_social_account(
        &self,
        account_id: Uuid,
        request: CreateSocialAccountRequest,
    ) -> Result<SocialAccount, AuthencError>;

    /// Remove social account link
    async fn remove_social_account(&self, account_id: Uuid) -> Result<(), AuthencError>;

    /// Remove social account link by user and provider
    async fn remove_social_account_by_provider(
        &self,
        user_id: Uuid,
        provider: &SocialProvider,
    ) -> Result<(), AuthencError>;
}

#[async_trait]
impl SocialAccountStoreTrait for SocialAccountStore {
    async fn get_social_account(
        &self,
        account_id: Uuid,
    ) -> Result<Option<SocialAccount>, AuthencError> {
        operations::social_accounts::get_social_account(&self.database, account_id).await
    }

    async fn get_user_social_accounts(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SocialAccount>, AuthencError> {
        operations::social_accounts::get_user_social_accounts(&self.database, user_id).await
    }

    async fn get_social_account_by_provider(
        &self,
        provider: &SocialProvider,
        provider_user_id: &str,
    ) -> Result<Option<SocialAccount>, AuthencError> {
        operations::social_accounts::get_social_account_by_provider(
            &self.database,
            provider,
            provider_user_id,
        )
        .await
    }

    async fn has_social_account(
        &self,
        user_id: Uuid,
        provider: &SocialProvider,
    ) -> Result<bool, AuthencError> {
        operations::social_accounts::has_social_account(&self.database, user_id, provider).await
    }

    async fn add_social_account(
        &self,
        user_id: Uuid,
        request: CreateSocialAccountRequest,
    ) -> Result<SocialAccount, AuthencError> {
        operations::social_accounts::add_social_account(&self.database, user_id, request).await
    }

    async fn update_social_account(
        &self,
        account_id: Uuid,
        request: CreateSocialAccountRequest,
    ) -> Result<SocialAccount, AuthencError> {
        operations::social_accounts::update_social_account(&self.database, account_id, request)
            .await
    }

    async fn remove_social_account(&self, account_id: Uuid) -> Result<(), AuthencError> {
        operations::social_accounts::remove_social_account(&self.database, account_id).await
    }

    async fn remove_social_account_by_provider(
        &self,
        user_id: Uuid,
        provider: &SocialProvider,
    ) -> Result<(), AuthencError> {
        operations::social_accounts::remove_social_account_by_provider(
            &self.database,
            user_id,
            provider.clone(),
        )
        .await
    }
}
