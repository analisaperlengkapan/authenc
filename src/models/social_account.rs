use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::services::social::SocialProvider;

/// Social account linking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAccount {
    /// Unique identifier for the social account link
    pub id: Uuid,
    /// ID of the user this social account is linked to
    pub user_id: Uuid,
    /// Social provider type
    pub provider: SocialProvider,
    /// User ID on the social provider
    pub provider_user_id: String,
    /// Display name from social provider
    pub display_name: Option<String>,
    /// Email from social provider
    pub email: Option<String>,
    /// Profile picture URL from social provider
    pub profile_picture_url: Option<String>,
    /// Access token from social provider (encrypted)
    pub access_token: Option<String>,
    /// Refresh token from social provider (encrypted)
    pub refresh_token: Option<String>,
    /// Token expiration timestamp
    pub token_expires_at: Option<DateTime<Utc>>,
    /// When the account was linked
    pub linked_at: DateTime<Utc>,
    /// When the account was last updated
    pub updated_at: DateTime<Utc>,
}

/// Request to create a social account link
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateSocialAccountRequest {
    /// Social provider type
    pub provider: SocialProvider,
    /// User ID on the social provider
    pub provider_user_id: String,
    /// Display name from social provider
    pub display_name: Option<String>,
    /// Email from social provider
    pub email: Option<String>,
    /// Profile picture URL from social provider
    pub profile_picture_url: Option<String>,
    /// Access token from social provider
    pub access_token: Option<String>,
    /// Refresh token from social provider
    pub refresh_token: Option<String>,
    /// Token expiration timestamp
    pub token_expires_at: Option<DateTime<Utc>>,
}

/// Response for social account information (without sensitive tokens)
#[derive(Debug, Deserialize, Serialize)]
pub struct SocialAccountResponse {
    /// Social provider (google, github, etc.)
    pub provider: String,
    /// User ID on the social provider
    pub provider_user_id: String,
    /// Display name from social provider
    pub display_name: Option<String>,
    /// Email from social provider
    pub email: Option<String>,
    /// Profile picture URL from social provider
    pub profile_picture_url: Option<String>,
    /// When the account was linked
    pub linked_at: String,
    /// When the account was last updated
    pub updated_at: String,
}

impl From<SocialAccount> for SocialAccountResponse {
    fn from(account: SocialAccount) -> Self {
        Self {
            provider: format!("{:?}", account.provider).to_lowercase(),
            provider_user_id: account.provider_user_id,
            display_name: account.display_name,
            email: account.email,
            profile_picture_url: account.profile_picture_url,
            linked_at: account.linked_at.to_rfc3339(),
            updated_at: account.updated_at.to_rfc3339(),
        }
    }
}
