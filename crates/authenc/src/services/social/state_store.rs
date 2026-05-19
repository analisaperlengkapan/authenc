use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use authenc_core::error::Result;

/// Social login state stored in the backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialLoginState {
    /// Unique state token
    pub state: String,
    /// Provider ID or Name
    pub provider: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Realm ID associated with this state
    pub realm_id: Option<String>,
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Trait for storing and retrieving social login states
#[async_trait]
pub trait SocialStateStore: Send + Sync {
    /// Create a new state
    async fn create_state(
        &self,
        state: &str,
        provider: &str,
        redirect_uri: &str,
        realm_id: Option<&str>,
        expires_in: i64,
    ) -> Result<()>;

    /// Validate and consume (delete) a state
    /// Returns the state if valid, None if not found or expired
    async fn validate_and_consume_state(&self, state: &str) -> Result<Option<SocialLoginState>>;

    /// Clean up expired states (optional, can be no-op for DB stores with TTL)
    async fn cleanup_expired(&self) -> Result<()>;
}
