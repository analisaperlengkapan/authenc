use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Social login provider types
#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub enum SocialProvider {
    Google,
    Facebook,
    Twitter,
    GitHub,
    LinkedIn,
    Microsoft,
    Apple,
    Custom(String),
}

/// OAuth 2.0 configuration for social providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub authorization_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
    pub provider: SocialProvider,
}

/// Social user profile from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserProfile {
    pub provider: SocialProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub picture_url: Option<String>,
    pub locale: Option<String>,
    pub verified_email: bool,
    pub raw_data: serde_json::Value,
}

/// Social login session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialLoginSession {
    pub session_id: String,
    pub state: String,
    pub provider: SocialProvider,
    pub redirect_uri: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Social login service trait
#[async_trait]
pub trait SocialLoginService: Send + Sync {
    /// Initiate OAuth login flow
    async fn initiate_login(&self, provider: SocialProvider, redirect_uri: &str) -> Result<String, String>;

    /// Handle OAuth callback
    async fn handle_callback(&self, code: &str, state: &str) -> Result<SocialUserProfile, String>;

    /// Exchange authorization code for access token
    async fn exchange_code_for_token(&self, code: &str, config: &OAuthConfig) -> Result<OAuthTokenResponse, String>;

    /// Get user profile from provider
    async fn get_user_profile(&self, access_token: &str, config: &OAuthConfig) -> Result<SocialUserProfile, String>;

    /// Validate session
    async fn validate_session(&self, session_id: &str) -> Result<bool, String>;
}

/// OAuth 2.0 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

use std::sync::RwLock;

/// Social Login Manager
pub struct SocialLoginManager {
    providers: HashMap<SocialProvider, OAuthConfig>,
    sessions: RwLock<HashMap<String, SocialLoginSession>>,
    http_client: reqwest::Client,
}

impl SocialLoginManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            sessions: RwLock::new(HashMap::new()),
            http_client: reqwest::Client::new(),
        }
    }

    /// Register OAuth provider
    pub fn register_provider(&mut self, config: OAuthConfig) {
        self.providers.insert(config.provider.clone(), config);
    }

    /// Get OAuth configuration for provider
    pub fn get_provider_config(&self, provider: &SocialProvider) -> Option<&OAuthConfig> {
        self.providers.get(provider)
    }

    /// Generate OAuth authorization URL
    pub fn generate_auth_url(&self, provider: &SocialProvider, redirect_uri: &str) -> Result<String, String> {
        let config = self.get_provider_config(provider)
            .ok_or_else(|| format!("Provider {:?} not configured", provider))?;

        let state = uuid::Uuid::new_v4().to_string();
        let session_id = uuid::Uuid::new_v4().to_string();

        // Create session
        let session = SocialLoginSession {
            session_id: session_id.clone(),
            state: state.clone(),
            provider: provider.clone(),
            redirect_uri: redirect_uri.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        };

        self.sessions.write().unwrap().insert(session_id, session);

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

    /// Validate OAuth state parameter
    pub fn validate_state(&self, state: &str) -> Result<SocialLoginSession, String> {
        // Find session by state
        for session in self.sessions.read().unwrap().values() {
            if session.state == state {
                // Check if session is expired
                if chrono::Utc::now() > session.expires_at {
                    return Err("Session expired".to_string());
                }
                return Ok(session.clone());
            }
        }
        Err("Invalid state parameter".to_string())
    }

    /// Clean expired sessions
    pub fn clean_expired_sessions(&mut self) {
        let now = chrono::Utc::now();
        self.sessions.write().unwrap().retain(|_, session| session.expires_at > now);
    }
}

#[async_trait]
impl SocialLoginService for SocialLoginManager {
    async fn initiate_login(&self, provider: SocialProvider, redirect_uri: &str) -> Result<String, String> {
        self.generate_auth_url(&provider, redirect_uri)
    }

    async fn handle_callback(&self, code: &str, state: &str) -> Result<SocialUserProfile, String> {
        let session = self.validate_state(state)?;

        let config = self.get_provider_config(&session.provider)
            .ok_or_else(|| "Provider configuration not found".to_string())?;

        // Exchange code for token
        let token_response = self.exchange_code_for_token(code, config).await?;

        // Get user profile
        let profile = self.get_user_profile(&token_response.access_token, config).await?;

        Ok(profile)
    }

    async fn exchange_code_for_token(&self, code: &str, config: &OAuthConfig) -> Result<OAuthTokenResponse, String> {
        let mut params = HashMap::new();
        params.insert("client_id", config.client_id.clone());
        params.insert("client_secret", config.client_secret.clone());
        params.insert("code", code.to_string());
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("redirect_uri", config.redirect_uri.clone());

        let response = self.http_client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token exchange failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Token exchange failed with status: {}", response.status()));
        }

        let token_response: OAuthTokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        Ok(token_response)
    }

    async fn get_user_profile(&self, access_token: &str, config: &OAuthConfig) -> Result<SocialUserProfile, String> {
        let response = self.http_client
            .get(&config.user_info_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("User info request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("User info request failed with status: {}", response.status()));
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
            _ => self.parse_generic_profile(user_data, &config.provider),
        };

        Ok(profile)
    }

    async fn validate_session(&self, session_id: &str) -> Result<bool, String> {
        if let Some(session) = self.sessions.read().unwrap().get(session_id) {
            Ok(chrono::Utc::now() <= session.expires_at)
        } else {
            Ok(false)
        }
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
            picture_url: data["picture"]["data"]["url"].as_str().map(|s| s.to_string()),
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
            first_name: data["name"].as_str().map(|s| s.to_string().split(' ').next().unwrap_or("").to_string()),
            last_name: data["name"].as_str().map(|s| s.to_string().split(' ').skip(1).collect::<Vec<&str>>().join(" ")),
            picture_url: data["avatar_url"].as_str().map(|s| s.to_string()),
            locale: None,
            verified_email: false, // GitHub doesn't provide this directly
            raw_data: data,
        }
    }

    /// Parse generic OAuth provider profile
    fn parse_generic_profile(&self, data: serde_json::Value, provider: &SocialProvider) -> SocialUserProfile {
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
}

/// Pre-configured OAuth configurations for popular providers
pub struct OAuthConfigs;

impl OAuthConfigs {
    pub fn google() -> OAuthConfig {
        OAuthConfig {
            client_id: std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
            redirect_uri: std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_default(),
            authorization_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            provider: SocialProvider::Google,
        }
    }

    pub fn github() -> OAuthConfig {
        OAuthConfig {
            client_id: std::env::var("GITHUB_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default(),
            redirect_uri: std::env::var("GITHUB_REDIRECT_URI").unwrap_or_default(),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string()],
            provider: SocialProvider::GitHub,
        }
    }

    pub fn facebook() -> OAuthConfig {
        OAuthConfig {
            client_id: std::env::var("FACEBOOK_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("FACEBOOK_CLIENT_SECRET").unwrap_or_default(),
            redirect_uri: std::env::var("FACEBOOK_REDIRECT_URI").unwrap_or_default(),
            authorization_url: "https://www.facebook.com/v12.0/dialog/oauth".to_string(),
            token_url: "https://graph.facebook.com/v12.0/oauth/access_token".to_string(),
            user_info_url: "https://graph.facebook.com/me".to_string(),
            scopes: vec!["email".to_string(), "public_profile".to_string()],
            provider: SocialProvider::Facebook,
        }
    }
}
