pub mod state_store;
pub mod in_memory_store;
pub mod pg_store;
pub mod db_sync;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use self::state_store::SocialStateStore;
pub use state_store::SocialLoginState;

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

/// Social login service trait
#[async_trait]
pub trait SocialLoginService: Send + Sync {
    /// Initiate OAuth login flow
    async fn initiate_login(
        &self,
        provider: SocialProvider,
        redirect_uri: &str,
        realm_id: Option<String>,
    ) -> Result<String, String>;

    /// Handle OAuth callback
    async fn handle_callback(&self, code: &str, state: &str) -> Result<(SocialUserProfile, SocialLoginState), String>;

    /// Exchange authorization code for access token
    async fn exchange_code_for_token(
        &self,
        code: &str,
        config: &OAuthConfig,
    ) -> Result<OAuthTokenResponse, String>;

    /// Get user profile from provider
    async fn get_user_profile(
        &self,
        access_token: &str,
        config: &OAuthConfig,
    ) -> Result<SocialUserProfile, String>;
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

/// Social Login Manager
pub struct SocialLoginManager {
    /// Configured OAuth providers
    providers: RwLock<HashMap<SocialProvider, OAuthConfig>>,
    /// State store for OAuth sessions
    store: Arc<dyn SocialStateStore>,
    /// HTTP client for API calls
    http_client: reqwest::Client,
}

impl Default for SocialLoginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SocialLoginManager {
    /// Create new social login manager with in-memory store (default)
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            store: Arc::new(in_memory_store::InMemorySocialStateStore::new()),
            http_client: reqwest::Client::new(),
        }
    }

    /// Create new social login manager with custom store
    pub fn with_store(store: Arc<dyn SocialStateStore>) -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            store,
            http_client: reqwest::Client::new(),
        }
    }

    /// Register OAuth provider
    pub fn register_provider(&self, config: OAuthConfig) {
        if let Ok(mut providers) = self.providers.write() {
            providers.insert(config.provider.clone(), config);
        }
    }

    /// Get OAuth configuration for provider
    pub fn get_provider_config(&self, provider: &SocialProvider) -> Option<OAuthConfig> {
        if let Ok(providers) = self.providers.read() {
            return providers.get(provider).cloned();
        }
        None
    }

    /// Generate OAuth authorization URL
    pub async fn generate_auth_url(
        &self,
        provider: &SocialProvider,
        redirect_uri: &str,
        realm_id: Option<String>,
    ) -> Result<String, String> {
        // Clean expired sessions before creating a new one (best effort)
        let _ = self.store.cleanup_expired().await;

        let config = self
            .get_provider_config(provider)
            .ok_or_else(|| format!("Provider {:?} not configured", provider))?;

        let state = uuid::Uuid::new_v4().to_string();

        // Store state in backend
        // Note: The `redirect_uri` passed here is stored in the state but currently NOT used
        // during the callback phase for verification. It is intended for future use where the
        // application might want to redirect the user to a specific page after successful login.
        // For the OAuth flow itself, we MUST use the pre-registered `config.redirect_uri`.
        self.store.create_state(&state, provider.as_str(), redirect_uri, realm_id.as_deref(), 600) // 10 minutes
            .await
            .map_err(|e| format!("Failed to store state: {}", e))?;

        // Build authorization URL
        let mut url = url::Url::parse(&config.authorization_url)
            .map_err(|e| format!("Invalid authorization URL: {}", e))?;

        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &config.scopes.join(" "))
            .append_pair("state", &state);

        Ok(url.to_string())
    }

    /// Validate and consume OAuth state parameter
    pub async fn validate_and_consume_state(&self, state: &str) -> Result<state_store::SocialLoginState, String> {
        let session = self.store.validate_and_consume_state(state)
            .await
            .map_err(|e| format!("State validation error: {}", e))?;

        session.ok_or_else(|| "Invalid or expired state parameter".to_string())
    }
}

#[async_trait]
impl SocialLoginService for SocialLoginManager {
    async fn initiate_login(
        &self,
        provider: SocialProvider,
        redirect_uri: &str,
        realm_id: Option<String>,
    ) -> Result<String, String> {
        self.generate_auth_url(&provider, redirect_uri, realm_id).await
    }

    async fn handle_callback(&self, code: &str, state: &str) -> Result<(SocialUserProfile, SocialLoginState), String> {
        // Validate and consume state to prevent replay attacks
        let session = self.validate_and_consume_state(state).await?;

        // Convert string provider back to enum
        let provider = std::str::FromStr::from_str(&session.provider)
            .map_err(|e| format!("Invalid provider in state: {}", e))?;

        let config = self
            .get_provider_config(&provider)
            .ok_or_else(|| "Provider configuration not found".to_string())?;

        // Exchange code for token
        let token_response = self.exchange_code_for_token(code, &config).await?;

        // Get user profile
        let profile = self
            .get_user_profile(&token_response.access_token, &config)
            .await?;

        Ok((profile, session))
    }

    async fn exchange_code_for_token(
        &self,
        code: &str,
        config: &OAuthConfig,
    ) -> Result<OAuthTokenResponse, String> {
        let mut params = HashMap::new();
        params.insert("client_id", config.client_id.clone());
        params.insert("client_secret", config.client_secret.clone());
        params.insert("code", code.to_string());
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("redirect_uri", config.redirect_uri.clone());

        let response = self
            .http_client
            .post(&config.token_url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token exchange failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Token exchange failed with status: {}",
                response.status()
            ));
        }

        let token_response: OAuthTokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        Ok(token_response)
    }

    async fn get_user_profile(
        &self,
        access_token: &str,
        config: &OAuthConfig,
    ) -> Result<SocialUserProfile, String> {
        let response = self
            .http_client
            .get(&config.user_info_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("User info request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "User info request failed with status: {}",
                response.status()
            ));
        }

        let user_data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse user info: {}", e))?;

        // Parse user profile based on provider
        let profile = match config.provider {
            SocialProvider::Google => self.parse_google_profile(user_data),
            SocialProvider::Facebook => self.parse_facebook_profile(user_data),
            SocialProvider::GitHub => self.parse_github_profile(user_data),
            SocialProvider::Microsoft => self.parse_microsoft_profile(user_data),
            SocialProvider::LinkedIn => self.parse_linkedin_profile(user_data),
            SocialProvider::Twitter => self.parse_twitter_profile(user_data),
            SocialProvider::Apple => self.parse_apple_profile(user_data),
            SocialProvider::Amazon => self.parse_amazon_profile(user_data),
            SocialProvider::Okta => self.parse_okta_profile(user_data),
            SocialProvider::Auth0 => self.parse_auth0_profile(user_data),
            SocialProvider::Discord => self.parse_discord_profile(user_data),
            SocialProvider::Slack => self.parse_slack_profile(user_data),
            SocialProvider::Custom(ref _provider_name) => {
                self.parse_generic_profile(user_data, &config.provider)
            }
        };

        Ok(profile)
    }
}

impl SocialLoginManager {
    /// Parse Google user profile
    fn parse_google_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Google,
            provider_user_id: data["sub"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            picture_url: data["picture"].as_str().map(|s| s.to_string()),
            locale: data["locale"].as_str().map(|s| s.to_string()),
            verified_email: data["email_verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }

    /// Parse Facebook user profile
    fn parse_facebook_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Facebook,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["first_name"].as_str().map(|s| s.to_string()),
            last_name: data["last_name"].as_str().map(|s| s.to_string()),
            picture_url: data["picture"]["data"]["url"]
                .as_str()
                .map(|s| s.to_string()),
            locale: data["locale"].as_str().map(|s| s.to_string()),
            verified_email: false, // Facebook doesn't provide this
            raw_data: data,
        }
    }

    /// Parse GitHub user profile
    fn parse_github_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::GitHub,
            provider_user_id: data["id"].to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["name"]
                .as_str()
                .map(|s| s.split(' ').next().unwrap_or("").to_string()),
            last_name: data["name"]
                .as_str()
                .map(|s| s.split(' ').skip(1).collect::<Vec<&str>>().join(" ")),
            picture_url: data["avatar_url"].as_str().map(|s| s.to_string()),
            locale: None,
            verified_email: false, // GitHub doesn't provide this directly
            raw_data: data,
        }
    }

    /// Parse generic OAuth provider profile
    fn parse_generic_profile(
        &self,
        data: serde_json::Value,
        provider: &SocialProvider,
    ) -> SocialUserProfile {
        SocialUserProfile {
            provider: provider.clone(),
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            picture_url: data["picture"].as_str().map(|s| s.to_string()),
            locale: data["locale"].as_str().map(|s| s.to_string()),
            verified_email: data["email_verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }

    /// Parse Microsoft user profile
    fn parse_microsoft_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Microsoft,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["mail"]
                .as_str()
                .or_else(|| data["userPrincipalName"].as_str())
                .map(|s| s.to_string()),
            name: data["displayName"].as_str().map(|s| s.to_string()),
            first_name: data["givenName"].as_str().map(|s| s.to_string()),
            last_name: data["surname"].as_str().map(|s| s.to_string()),
            picture_url: None, // Microsoft Graph API requires separate call
            locale: None,
            verified_email: false,
            raw_data: data,
        }
    }

    /// Parse LinkedIn user profile
    fn parse_linkedin_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::LinkedIn,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["emailAddress"].as_str().map(|s| s.to_string()),
            name: data["formattedName"].as_str().map(|s| s.to_string()),
            first_name: data["firstName"].as_str().map(|s| s.to_string()),
            last_name: data["lastName"].as_str().map(|s| s.to_string()),
            picture_url: data["pictureUrl"].as_str().map(|s| s.to_string()),
            locale: None,
            verified_email: false,
            raw_data: data,
        }
    }

    /// Parse Twitter user profile
    fn parse_twitter_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Twitter,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["name"].as_str().map(|s| s.to_string()),
            last_name: None,
            picture_url: data["profile_image_url"].as_str().map(|s| s.to_string()),
            locale: None,
            verified_email: false,
            raw_data: data,
        }
    }

    /// Parse Apple user profile
    fn parse_apple_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Apple,
            provider_user_id: data["sub"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"]["firstName"].as_str().map(|s| s.to_string()),
            first_name: data["name"]["firstName"].as_str().map(|s| s.to_string()),
            last_name: data["name"]["lastName"].as_str().map(|s| s.to_string()),
            picture_url: None,
            locale: None,
            verified_email: data["email_verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }

    /// Parse Discord user profile
    fn parse_discord_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Discord,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["username"].as_str().map(|s| s.to_string()),
            first_name: data["username"].as_str().map(|s| s.to_string()),
            last_name: data["discriminator"].as_str().map(|s| s.to_string()),
            picture_url: data["avatar"]
                .as_str()
                .map(|s| format!("https://cdn.discordapp.com/avatars/{}/{}", data["id"], s)),
            locale: data["locale"].as_str().map(|s| s.to_string()),
            verified_email: data["verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }

    /// Parse Slack user profile
    fn parse_slack_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Slack,
            provider_user_id: data["user"]["id"].as_str().unwrap_or("").to_string(),
            email: data["user"]["email"].as_str().map(|s| s.to_string()),
            name: data["user"]["name"].as_str().map(|s| s.to_string()),
            first_name: data["user"]["name"].as_str().map(|s| s.to_string()),
            last_name: None,
            picture_url: data["user"]["image_192"].as_str().map(|s| s.to_string()),
            locale: data["user"]["locale"].as_str().map(|s| s.to_string()),
            verified_email: false,
            raw_data: data,
        }
    }

    /// Parse Amazon user profile
    fn parse_amazon_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Amazon,
            provider_user_id: data["user_id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            picture_url: None,
            locale: None,
            verified_email: data["email_verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }

    /// Parse Okta user profile
    fn parse_okta_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Okta,
            provider_user_id: data["sub"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            picture_url: data["picture"].as_str().map(|s| s.to_string()),
            locale: data["locale"].as_str().map(|s| s.to_string()),
            verified_email: data["email_verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }

    /// Parse Auth0 user profile
    fn parse_auth0_profile(&self, data: serde_json::Value) -> SocialUserProfile {
        SocialUserProfile {
            provider: SocialProvider::Auth0,
            provider_user_id: data["sub"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            picture_url: data["picture"].as_str().map(|s| s.to_string()),
            locale: data["locale"].as_str().map(|s| s.to_string()),
            verified_email: data["email_verified"].as_bool().unwrap_or(false),
            raw_data: data,
        }
    }
}
