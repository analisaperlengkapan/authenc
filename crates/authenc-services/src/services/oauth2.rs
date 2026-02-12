use authenc_database::database::Database;
use authenc_core::error::{AuthencError, Result};
use authenc_models::models::oauth2::{AccessTokenClaims, OAuth2AccessToken, OAuth2AuthorizationCode, OAuth2Client};
use authenc_database::database::operations::oauth2;
use authenc_database::database::operations::tokens;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use std::sync::Arc;
use async_trait::async_trait;
use authenc_crypto::utils::crypto::password::verify_password;

/// Trait for validating OAuth2 clients
#[async_trait]
pub trait ClientValidator: Send + Sync {
    /// Validate client credentials and return client if valid
    async fn validate_client(&self, client_id: &str, client_secret: Option<&str>) -> Result<Option<OAuth2Client>>;
}

/// Database-backed client validator
pub struct DbClientValidator {
    db: Arc<Database>,
}

impl DbClientValidator {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ClientValidator for DbClientValidator {
    async fn validate_client(&self, client_id: &str, client_secret: Option<&str>) -> Result<Option<OAuth2Client>> {
        // Try to find client in database
        if let Ok(Some(client)) = oauth2::get_client_by_id(&self.db, client_id).await {
            if !client.enabled {
                return Ok(None);
            }

            if let Some(secret) = client_secret {
                // Verify secret
                if verify_password(&client.client_secret_hash, secret)
                    .await
                    .unwrap_or(false)
                {
                    return Ok(Some(client));
                }

                // Fallback for simple comparison
                if client.client_secret_hash == secret {
                    return Ok(Some(client));
                }
            } else {
                // Public client check
                if client.client_type == "public" {
                    return Ok(Some(client));
                }
            }
        }

        Ok(None)
    }
}

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

    /// Store a token from claims and raw strings
    pub async fn store_token(
        &self,
        access_token: &str,
        refresh_token: Option<&str>,
        claims: &AccessTokenClaims,
    ) -> Result<()> {
        // Hash tokens
        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let token_hash = format!("{:x}", hasher.finalize());

        let refresh_token_hash = refresh_token.map(|t| {
            let mut hasher = Sha256::new();
            hasher.update(t.as_bytes());
            format!("{:x}", hasher.finalize())
        });

        // Parse IDs
        let id = Uuid::parse_str(&claims.jti)
            .map_err(|_| AuthencError::validation("Invalid JTI in claims"))?;

        let client_id = Uuid::parse_str(&claims.client_id)
            .map_err(|_| AuthencError::validation("Invalid client_id in claims"))?;

        // Handle user_id (sub) which might be a user UUID or client_id (for client_credentials)
        let user_id = if let Ok(uid) = Uuid::parse_str(&claims.sub) {
            // Check if sub equals client_id, meaning it's a client credentials token (no user)
            // But sometimes client credentials sub is client_id.
            // If the sub is the same as client_id, we might treat user_id as None,
            // OR we treat it as None if we can't parse it (but here we can).
            // Let's assume if it parses, it's a valid ID.
            // If the flow was client_credentials, usually user_id is null in DB, but sub is client_id.
            // We'll set user_id to Some(uid) generally.
            // However, in our DB schema, user_id implies a user from users table.
            // If sub == client_id, it might not be in users table.
            if uid == client_id {
                None
            } else {
                Some(uid)
            }
        } else {
            None
        };

        let scopes = claims.scope.as_ref()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();

        let expires_at = DateTime::<Utc>::from_timestamp(claims.exp, 0)
            .ok_or(AuthencError::validation("Invalid expiration time"))?;

        // Default refresh expiration to 30 days if not specified in claims (claims usually don't have it)
        let refresh_expires_at = if refresh_token.is_some() {
            Some(Utc::now() + chrono::Duration::days(30))
        } else {
            None
        };

        let created_at = DateTime::<Utc>::from_timestamp(claims.iat, 0)
            .unwrap_or_else(Utc::now);

        let model = OAuth2AccessToken {
            id,
            token_hash,
            refresh_token_hash,
            client_id,
            user_id,
            scopes,
            expires_at,
            refresh_expires_at,
            revoked: false,
            revoked_at: None,
            created_at,
            last_used_at: None,
            session_id: claims.sid.clone(),
        };

        self.store_access_token_db(&model).await
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
