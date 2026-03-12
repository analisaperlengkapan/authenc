use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported social login providers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SocialProvider {
    /// Google OAuth provider
    Google,
    /// Facebook OAuth provider
    Facebook,
    /// Twitter OAuth provider
    Twitter,
    /// GitHub OAuth provider
    GitHub,
    /// LinkedIn OAuth provider
    LinkedIn,
    /// Microsoft OAuth provider
    Microsoft,
    /// Apple OAuth provider
    Apple,
    /// Amazon OAuth provider
    Amazon,
    /// Discord OAuth provider
    Discord,
    /// Slack OAuth provider
    Slack,
    /// Okta OAuth provider
    Okta,
    /// Auth0 OAuth provider
    Auth0,
    /// Custom OAuth provider with name
    Custom(String),
}

impl SocialProvider {
    /// Get the string representation of the provider
    pub fn as_str(&self) -> &str {
        match self {
            SocialProvider::Google => "google",
            SocialProvider::Facebook => "facebook",
            SocialProvider::Twitter => "twitter",
            SocialProvider::GitHub => "github",
            SocialProvider::LinkedIn => "linkedin",
            SocialProvider::Microsoft => "microsoft",
            SocialProvider::Apple => "apple",
            SocialProvider::Amazon => "amazon",
            SocialProvider::Discord => "discord",
            SocialProvider::Slack => "slack",
            SocialProvider::Okta => "okta",
            SocialProvider::Auth0 => "auth0",
            SocialProvider::Custom(name) => name,
        }
    }
}

impl std::fmt::Display for SocialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SocialProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(SocialProvider::Google),
            "facebook" => Ok(SocialProvider::Facebook),
            "twitter" => Ok(SocialProvider::Twitter),
            "github" => Ok(SocialProvider::GitHub),
            "linkedin" => Ok(SocialProvider::LinkedIn),
            "microsoft" => Ok(SocialProvider::Microsoft),
            "apple" => Ok(SocialProvider::Apple),
            "amazon" => Ok(SocialProvider::Amazon),
            "discord" => Ok(SocialProvider::Discord),
            "slack" => Ok(SocialProvider::Slack),
            "okta" => Ok(SocialProvider::Okta),
            "auth0" => Ok(SocialProvider::Auth0),
            _ => Err(format!("Unknown social provider: {}", s)),
        }
    }
}

/// Social account linking information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
            provider: account.provider.to_string(),
            provider_user_id: account.provider_user_id,
            display_name: account.display_name,
            email: account.email,
            profile_picture_url: account.profile_picture_url,
            linked_at: account.linked_at.to_rfc3339(),
            updated_at: account.updated_at.to_rfc3339(),
        }
    }
}
