use crate::database::Database;
use crate::error::Result;
use crate::models::oauth2::{OAuth2AccessToken, OAuth2AuthorizationCode};
use crate::database::operations::oauth2;
use crate::database::operations::tokens;
use uuid::Uuid;
use std::sync::Arc;

/// OAuth2 service for token persistence and management
#[derive(Clone)]
pub struct OAuth2Service {
    db: Arc<Database>,
}

impl OAuth2Service {
    /// Create a new OAuth2 service
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Store an access token in the database
    pub async fn store_access_token_db(&self, token: &OAuth2AccessToken) -> Result<()> {
        oauth2::store_access_token(&self.db, token).await
    }

    /// Get access token by hash
    pub async fn get_access_token_by_hash(&self, token_hash: &str) -> Result<Option<OAuth2AccessToken>> {
        oauth2::get_access_token(&self.db, token_hash).await
    }

    /// Get access token by refresh token
    pub async fn get_access_token_by_refresh_token(&self, refresh_token: &str) -> Result<Option<OAuth2AccessToken>> {
        oauth2::get_access_token_by_refresh_token(&self.db, refresh_token).await
    }

    /// Revoke an access token
    pub async fn revoke_access_token(&self, token_hash: &str) -> Result<()> {
        oauth2::revoke_token(&self.db, token_hash).await
    }

    /// Revoke all tokens for a user
    pub async fn revoke_user_tokens(&self, user_id: Uuid) -> Result<()> {
        oauth2::revoke_user_tokens(&self.db, user_id).await
    }

    /// Store a refresh token (if managed separately or as part of access token flow)
    /// Note: In the current model, refresh_token is part of OAuth2AccessToken, but we can have logic here.
    /// If separate table or logic is needed, implement here.
    /// Currently, `store_access_token_db` handles both access and refresh token hashes if they are in the same record.
    /// If refresh tokens are tracked independently for rotation, we can use `tokens::rotate_refresh_token` logic but that is session based.
    ///
    /// Store authorization code
    pub async fn store_authorization_code(&self, code: &OAuth2AuthorizationCode) -> Result<()> {
        oauth2::store_authorization_code(&self.db, code).await
    }

    /// Get authorization code
    pub async fn get_authorization_code(&self, code: &str) -> Result<Option<OAuth2AuthorizationCode>> {
        oauth2::get_authorization_code(&self.db, code).await
    }

    /// Mark authorization code as used
    pub async fn mark_code_used(&self, code: &str) -> Result<()> {
        oauth2::mark_code_used(&self.db, code).await
    }

    /// Clean up expired tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        tokens::delete_expired_tokens(&self.db).await
    }

    /// Get token statistics
    pub async fn get_token_statistics(&self) -> Result<tokens::TokenStatistics> {
        tokens::get_token_statistics(&self.db).await
    }
}
