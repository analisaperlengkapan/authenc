use crate::database::Database;
use crate::error::{AuthencError, Result};
use crate::models::token::TokenResponse;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Token Manager for handling access tokens, refresh tokens, and token lifecycle
pub struct TokenManager {
    /// Database connection
    db: Arc<Database>,
    /// Default access token lifetime (seconds)
    access_token_ttl: i64,
    /// Default refresh token lifetime (seconds)
    refresh_token_ttl: i64,
    /// Enable refresh token rotation (security best practice)
    enable_rotation: bool,
}

impl TokenManager {
    /// Create new TokenManager with database connection
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            access_token_ttl: 3600,     // 1 hour
            refresh_token_ttl: 2592000, // 30 days
            enable_rotation: true,
        }
    }

    /// Create TokenManager with custom configuration
    pub fn with_config(
        db: Arc<Database>,
        access_token_ttl: i64,
        refresh_token_ttl: i64,
        enable_rotation: bool,
    ) -> Self {
        Self {
            db,
            access_token_ttl,
            refresh_token_ttl,
            enable_rotation,
        }
    }

    /// Generate access token and optional refresh token
    pub async fn generate_token_pair(
        &self,
        user_id: Uuid,
        client_id: String,
        scope: Option<String>,
        include_refresh: bool,
    ) -> Result<TokenResponse> {
        // Generate access token
        let access_token_value = self.generate_random_token();
        let access_token_hash = self.hash_token(&access_token_value);

        // Generate refresh token if requested
        let (refresh_token_value, refresh_token_hash) = if include_refresh {
            let rt_value = self.generate_random_token();
            let rt_hash = self.hash_token(&rt_value);
            (Some(rt_value), Some(rt_hash))
        } else {
            (None, None)
        };

        // Parse client_id as UUID
        let client_uuid = Uuid::parse_str(&client_id)
            .map_err(|_| AuthencError::validation("Invalid client_id format"))?;

        // Calculate expiration times
        let expires_at = Utc::now() + Duration::seconds(self.access_token_ttl);
        let refresh_expires_at = if include_refresh {
            Some(Utc::now() + Duration::seconds(self.refresh_token_ttl))
        } else {
            None
        };

        // Store in database
        use crate::database::operations::tokens;
        tokens::create_access_token(
            &self.db,
            &access_token_hash,
            refresh_token_hash.as_deref(),
            client_uuid,
            Some(user_id),
            scope
                .as_deref()
                .unwrap_or("")
                .split_whitespace()
                .map(String::from)
                .collect(),
            expires_at,
            refresh_expires_at,
            None, // session_id
        )
        .await?;

        Ok(TokenResponse {
            access_token: access_token_value,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl,
            refresh_token: refresh_token_value,
            scope,
        })
    }

    /// Validate access token and return user ID if valid
    pub async fn validate_access_token(&self, token: &str) -> Result<(Uuid, String, Vec<String>)> {
        let token_hash = self.hash_token(token);

        use crate::database::operations::tokens;
        match tokens::get_access_token(&self.db, &token_hash).await? {
            Some(token_data) => {
                // Check expiration
                if token_data.expires_at < Utc::now() {
                    return Err(AuthencError::unauthorized("Token expired"));
                }

                // Check revocation
                if token_data.revoked {
                    return Err(AuthencError::unauthorized("Token revoked"));
                }

                // Update last_used_at
                tokens::update_token_last_used(&self.db, &token_hash).await?;

                // Extract user_id
                let user_id = token_data
                    .user_id
                    .ok_or_else(|| AuthencError::unauthorized("Token has no associated user"))?;

                // Extract client_id
                let client_id = token_data.client_id.to_string();

                Ok((user_id, client_id, token_data.scopes))
            }
            None => Err(AuthencError::unauthorized("Invalid token")),
        }
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let refresh_token_hash = self.hash_token(refresh_token);

        use crate::database::operations::tokens;

        // Get existing token by refresh_token_hash
        match tokens::get_token_by_refresh(&self.db, &refresh_token_hash).await? {
            Some(token_data) => {
                // Check refresh token expiration
                if let Some(refresh_expires_at) = token_data.refresh_expires_at {
                    if refresh_expires_at < Utc::now() {
                        return Err(AuthencError::unauthorized("Refresh token expired"));
                    }
                } else {
                    return Err(AuthencError::unauthorized("No refresh token associated"));
                }

                // Check revocation
                if token_data.revoked {
                    return Err(AuthencError::unauthorized("Token revoked"));
                }

                // Get user_id and client_id
                let user_id = token_data
                    .user_id
                    .ok_or_else(|| AuthencError::unauthorized("Token has no associated user"))?;
                let client_id = token_data.client_id.to_string();
                let scope = if token_data.scopes.is_empty() {
                    None
                } else {
                    Some(token_data.scopes.join(" "))
                };

                // Revoke old token if rotation enabled
                if self.enable_rotation {
                    tokens::revoke_access_token(&self.db, &token_data.token_hash).await?;
                }

                // Generate new token pair
                self.generate_token_pair(user_id, client_id, scope, true)
                    .await
            }
            None => Err(AuthencError::unauthorized("Invalid refresh token")),
        }
    }

    /// Revoke access token (and associated refresh token)
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        let token_hash = self.hash_token(token);

        use crate::database::operations::tokens;
        tokens::revoke_access_token(&self.db, &token_hash).await?;

        Ok(())
    }

    /// Revoke all tokens for a user
    pub async fn revoke_user_tokens(&self, user_id: Uuid) -> Result<u64> {
        use crate::database::operations::tokens;
        tokens::revoke_user_tokens(&self.db, user_id).await
    }

    /// Revoke all tokens for a client
    pub async fn revoke_client_tokens(&self, client_id: Uuid) -> Result<u64> {
        use crate::database::operations::tokens;
        tokens::revoke_client_tokens(&self.db, client_id).await
    }

    /// Get active tokens for a user
    pub async fn get_user_tokens(&self, user_id: Uuid) -> Result<Vec<TokenInfo>> {
        use crate::database::operations::tokens;
        let tokens = tokens::get_user_active_tokens(&self.db, user_id).await?;

        Ok(tokens
            .into_iter()
            .map(|t| TokenInfo {
                id: t.id,
                client_id: t.client_id,
                scopes: t.scopes,
                expires_at: t.expires_at,
                created_at: t.created_at,
                last_used_at: t.last_used_at,
            })
            .collect())
    }

    /// Token introspection (RFC 7662)
    pub async fn introspect_token(&self, token: &str) -> Result<TokenIntrospectionResponse> {
        let token_hash = self.hash_token(token);

        use crate::database::operations::tokens;
        match tokens::get_access_token(&self.db, &token_hash).await? {
            Some(token_data) => {
                let active = !token_data.revoked && token_data.expires_at > Utc::now();

                Ok(TokenIntrospectionResponse {
                    active,
                    scope: if token_data.scopes.is_empty() {
                        None
                    } else {
                        Some(token_data.scopes.join(" "))
                    },
                    client_id: Some(token_data.client_id.to_string()),
                    username: None, // Could be populated from user table
                    token_type: Some("Bearer".to_string()),
                    exp: Some(token_data.expires_at.timestamp()),
                    iat: Some(token_data.created_at.timestamp()),
                    sub: token_data.user_id.map(|id| id.to_string()),
                    sid: token_data.session_id,
                })
            }
            None => Ok(TokenIntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                sub: None,
                sid: None,
            }),
        }
    }

    /// Cleanup expired tokens (maintenance task)
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        use crate::database::operations::tokens;
        tokens::delete_expired_tokens(&self.db).await
    }

    // ========== Private helper methods ==========

    /// Generate cryptographically secure random token
    fn generate_random_token(&self) -> String {
        use base64::Engine;
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes)
    }

    /// Hash token for storage (SHA-256)
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Token information for listing (no sensitive data)
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// Unique token identifier
    pub id: Uuid,
    /// Client that owns the token
    pub client_id: Uuid,
    /// OAuth2 scopes granted to the token
    pub scopes: Vec<String>,
    /// Token expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Token creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last time the token was used
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Token introspection response (RFC 7662)
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenIntrospectionResponse {
    /// Whether the token is active
    pub active: bool,
    /// OAuth2 scope
    pub scope: Option<String>,
    /// Client identifier
    pub client_id: Option<String>,
    /// Username
    pub username: Option<String>,
    /// Token type (usually "Bearer")
    pub token_type: Option<String>,
    /// Expiration timestamp (Unix time)
    pub exp: Option<i64>,
    /// Issued at timestamp (Unix time)
    pub iat: Option<i64>,
    /// Subject identifier (user ID)
    pub sub: Option<String>,
    /// Session identifier
    pub sid: Option<String>,
}
