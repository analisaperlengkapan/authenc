use serde::{Deserialize, Serialize};

/// Social login provider types
#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
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
    /// Convert the provider to a string representation
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
            custom => Ok(SocialProvider::Custom(custom.to_string())),
        }
    }
}

/// OAuth 2.0 configuration for social providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    pub client_secret: String,
    /// OAuth redirect URI
    pub redirect_uri: String,
    /// OAuth authorization endpoint URL
    pub authorization_url: String,
    /// OAuth token endpoint URL
    pub token_url: String,
    /// OAuth user info endpoint URL
    pub user_info_url: String,
    /// OAuth scopes to request
    pub scopes: Vec<String>,
    /// Social provider type
    pub provider: SocialProvider,
}

/// Social user profile from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserProfile {
    /// Social provider type
    pub provider: SocialProvider,
    /// User ID from the social provider
    pub provider_user_id: String,
    /// User's email address
    pub email: Option<String>,
    /// User's full name
    pub name: Option<String>,
    /// User's first name
    pub first_name: Option<String>,
    /// User's last name
    pub last_name: Option<String>,
    /// URL to user's profile picture
    pub picture_url: Option<String>,
    /// User's locale/language
    pub locale: Option<String>,
    /// Whether the email is verified
    pub verified_email: bool,
    /// Raw JSON data from the provider
    pub raw_data: serde_json::Value,
}

/// OAuth 2.0 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// Access token for API calls
    pub access_token: String,
    /// Type of the token (usually "Bearer")
    pub token_type: String,
    /// Token expiration time in seconds
    pub expires_in: Option<u64>,
    /// Refresh token for token renewal
    pub refresh_token: Option<String>,
    /// Granted OAuth scopes
    pub scope: Option<String>,
    /// OpenID Connect ID token
    pub id_token: Option<String>,
}

/// Social login state stored during the OAuth flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialLoginState {
    /// Unique state identifier
    pub state: String,
    /// Social provider name
    pub provider: String,
    /// Redirect URI to return to after login
    pub redirect_uri: String,
    /// Optional Realm ID
    pub realm_id: Option<String>,
    /// Creation timestamp
    pub created_at: i64,
    /// Expiration timestamp
    pub expires_at: i64,
}
