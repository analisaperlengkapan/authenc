use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use reqwest::Client;
use url::Url;

/// Social login providers supported by Authenc
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocialProvider {
    Google,
    Facebook,
    Twitter,
    GitHub,
    LinkedIn,
    Microsoft,
    Apple,
    Amazon,
    Discord,
    Slack,
    Okta,
    Auth0,
    Custom(String),
}

/// OAuth2/OIDC configuration for a social provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProviderConfig {
    pub provider: SocialProvider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub authorization_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub additional_params: HashMap<String, String>,
}

/// User profile information from social provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserProfile {
    pub provider: SocialProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    pub raw_data: serde_json::Value,
}

/// OAuth2 authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub provider: SocialProvider,
    pub state: String,
    pub scope: Vec<String>,
    pub redirect_uri: String,
}

/// OAuth2 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// Social login service trait
#[async_trait]
pub trait SocialLoginService: Send + Sync {
    /// Get authorization URL for a provider
    async fn get_authorization_url(&self, request: AuthorizationRequest) -> Result<String, SocialLoginError>;

    /// Exchange authorization code for access token
    async fn exchange_code(&self, provider: &SocialProvider, code: &str, redirect_uri: &str) -> Result<TokenResponse, SocialLoginError>;

    /// Get user profile information
    async fn get_user_profile(&self, provider: &SocialProvider, access_token: &str) -> Result<SocialUserProfile, SocialLoginError>;

    /// Validate and decode ID token (for OIDC providers)
    async fn validate_id_token(&self, provider: &SocialProvider, id_token: &str) -> Result<serde_json::Value, SocialLoginError>;

    /// Refresh access token
    async fn refresh_token(&self, provider: &SocialProvider, refresh_token: &str) -> Result<TokenResponse, SocialLoginError>;
}

/// Social login error types
#[derive(Debug, thiserror::Error)]
pub enum SocialLoginError {
    #[error("Provider not configured: {0}")]
    ProviderNotConfigured(String),

    #[error("Provider not enabled: {0}")]
    ProviderNotEnabled(String),

    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,

    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("User info request failed: {0}")]
    UserInfoFailed(String),

    #[error("Invalid ID token: {0}")]
    InvalidIdToken(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("URL parsing failed: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Base64 decoding failed: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("JWT validation failed: {0}")]
    JwtError(String),
}

/// Comprehensive social login implementation
pub struct AuthencSocialLogin {
    client: Client,
    providers: HashMap<SocialProvider, SocialProviderConfig>,
}

impl AuthencSocialLogin {
    /// Create a new social login service
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            providers: HashMap::new(),
        }
    }

    /// Add or update a social provider configuration
    pub fn add_provider(&mut self, config: SocialProviderConfig) {
        self.providers.insert(config.provider.clone(), config);
    }

    /// Remove a social provider
    pub fn remove_provider(&mut self, provider: &SocialProvider) {
        self.providers.remove(provider);
    }

    /// Get provider configuration
    pub fn get_provider_config(&self, provider: &SocialProvider) -> Option<&SocialProviderConfig> {
        self.providers.get(provider)
    }

    /// List all configured providers
    pub fn list_providers(&self) -> Vec<&SocialProviderConfig> {
        self.providers.values().collect()
    }

    /// Check if a provider is enabled
    pub fn is_provider_enabled(&self, provider: &SocialProvider) -> bool {
        self.providers.get(provider)
            .map(|config| config.enabled)
            .unwrap_or(false)
    }

    /// Get default configurations for popular providers
    pub fn get_default_provider_configs() -> Vec<SocialProviderConfig> {
        vec![
            // Google OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Google,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
                scopes: vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Facebook OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Facebook,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://www.facebook.com/v12.0/dialog/oauth".to_string(),
                token_url: "https://graph.facebook.com/v12.0/oauth/access_token".to_string(),
                user_info_url: "https://graph.facebook.com/me".to_string(),
                scopes: vec![
                    "email".to_string(),
                    "public_profile".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // GitHub OAuth2
            SocialProviderConfig {
                provider: SocialProvider::GitHub,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://github.com/login/oauth/authorize".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                user_info_url: "https://api.github.com/user".to_string(),
                scopes: vec![
                    "user:email".to_string(),
                    "read:user".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Microsoft OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Microsoft,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
                token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                user_info_url: "https://graph.microsoft.com/v1.0/me".to_string(),
                scopes: vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                    "User.Read".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Apple Sign In
            SocialProviderConfig {
                provider: SocialProvider::Apple,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://appleid.apple.com/auth/authorize".to_string(),
                token_url: "https://appleid.apple.com/auth/token".to_string(),
                user_info_url: "".to_string(), // Apple doesn't provide user info endpoint
                scopes: vec![
                    "name".to_string(),
                    "email".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // LinkedIn OAuth2
            SocialProviderConfig {
                provider: SocialProvider::LinkedIn,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://www.linkedin.com/oauth/v2/authorization".to_string(),
                token_url: "https://www.linkedin.com/oauth/v2/accessToken".to_string(),
                user_info_url: "https://api.linkedin.com/v2/people/~".to_string(),
                scopes: vec![
                    "r_liteprofile".to_string(),
                    "r_emailaddress".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Twitter OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Twitter,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://twitter.com/i/oauth2/authorize".to_string(),
                token_url: "https://api.twitter.com/2/oauth2/token".to_string(),
                user_info_url: "https://api.twitter.com/2/users/me".to_string(),
                scopes: vec![
                    "tweet.read".to_string(),
                    "users.read".to_string(),
                    "follows.read".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Amazon OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Amazon,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://www.amazon.com/ap/oa".to_string(),
                token_url: "https://api.amazon.com/auth/o2/token".to_string(),
                user_info_url: "https://api.amazon.com/user/profile".to_string(),
                scopes: vec![
                    "profile".to_string(),
                    "profile:user_id".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Discord OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Discord,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://discord.com/api/oauth2/authorize".to_string(),
                token_url: "https://discord.com/api/oauth2/token".to_string(),
                user_info_url: "https://discord.com/api/users/@me".to_string(),
                scopes: vec![
                    "identify".to_string(),
                    "email".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
            // Slack OAuth2
            SocialProviderConfig {
                provider: SocialProvider::Slack,
                client_id: String::new(),
                client_secret: String::new(),
                redirect_uri: String::new(),
                authorization_url: "https://slack.com/oauth/v2/authorize".to_string(),
                token_url: "https://slack.com/api/oauth.v2.access".to_string(),
                user_info_url: "https://slack.com/api/users.identity".to_string(),
                scopes: vec![
                    "identity.basic".to_string(),
                    "identity.email".to_string(),
                ],
                enabled: false,
                additional_params: HashMap::new(),
            },
        ]
    }
}

#[async_trait]
impl SocialLoginService for AuthencSocialLogin {
    async fn get_authorization_url(&self, request: AuthorizationRequest) -> Result<String, SocialLoginError> {
        let config = self.providers.get(&request.provider)
            .ok_or_else(|| SocialLoginError::ProviderNotConfigured(format!("{:?}", request.provider)))?;

        if !config.enabled {
            return Err(SocialLoginError::ProviderNotEnabled(format!("{:?}", request.provider)));
        }

        let mut url = Url::parse(&config.authorization_url)?;
        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &request.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &request.scope.join(" "))
            .append_pair("state", &request.state);

        // Add provider-specific parameters
        for (key, value) in &config.additional_params {
            url.query_pairs_mut().append_pair(key, value);
        }

        Ok(url.to_string())
    }

    async fn exchange_code(&self, provider: &SocialProvider, code: &str, redirect_uri: &str) -> Result<TokenResponse, SocialLoginError> {
        let config = self.providers.get(provider)
            .ok_or_else(|| SocialLoginError::ProviderNotConfigured(format!("{:?}", provider)))?;

        if !config.enabled {
            return Err(SocialLoginError::ProviderNotEnabled(format!("{:?}", provider)));
        }

        let mut form_data = HashMap::new();
        form_data.insert("grant_type", "authorization_code");
        form_data.insert("client_id", &config.client_id);
        form_data.insert("client_secret", &config.client_secret);
        form_data.insert("code", code);
        form_data.insert("redirect_uri", redirect_uri);

        let response = self.client
            .post(&config.token_url)
            .form(&form_data)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SocialLoginError::TokenExchangeFailed(
                format!("HTTP {}: {}", response.status(), response.text().await.unwrap_or_default())
            ));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response)
    }

    async fn get_user_profile(&self, provider: &SocialProvider, access_token: &str) -> Result<SocialUserProfile, SocialLoginError> {
        let config = self.providers.get(provider)
            .ok_or_else(|| SocialLoginError::ProviderNotConfigured(format!("{:?}", provider)))?;

        if !config.enabled {
            return Err(SocialLoginError::ProviderNotEnabled(format!("{:?}", provider)));
        }

        // Skip user info for Apple (handled via ID token)
        if matches!(provider, SocialProvider::Apple) {
            return Err(SocialLoginError::UserInfoFailed("Apple Sign In requires ID token validation".to_string()));
        }

        let response = self.client
            .get(&config.user_info_url)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SocialLoginError::UserInfoFailed(
                format!("HTTP {}: {}", response.status(), response.text().await.unwrap_or_default())
            ));
        }

        let user_data: serde_json::Value = response.json().await?;
        let profile = self.parse_user_profile(provider, &user_data)?;

        Ok(profile)
    }

    async fn validate_id_token(&self, provider: &SocialProvider, id_token: &str) -> Result<serde_json::Value, SocialLoginError> {
        // Basic JWT parsing - in production, you'd want proper JWT validation
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(SocialLoginError::InvalidIdToken("Invalid JWT format".to_string()));
        }

        let payload = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)?;
        let payload_str = String::from_utf8(payload)
            .map_err(|e| SocialLoginError::InvalidIdToken(format!("Invalid UTF-8 in payload: {}", e)))?;

        let claims: serde_json::Value = serde_json::from_str(&payload_str)?;
        Ok(claims)
    }

    async fn refresh_token(&self, provider: &SocialProvider, refresh_token: &str) -> Result<TokenResponse, SocialLoginError> {
        let config = self.providers.get(provider)
            .ok_or_else(|| SocialLoginError::ProviderNotConfigured(format!("{:?}", provider)))?;

        if !config.enabled {
            return Err(SocialLoginError::ProviderNotEnabled(format!("{:?}", provider)));
        }

        let mut form_data = HashMap::new();
        form_data.insert("grant_type", "refresh_token");
        form_data.insert("client_id", &config.client_id);
        form_data.insert("client_secret", &config.client_secret);
        form_data.insert("refresh_token", refresh_token);

        let response = self.client
            .post(&config.token_url)
            .form(&form_data)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SocialLoginError::TokenExchangeFailed(
                format!("HTTP {}: {}", response.status(), response.text().await.unwrap_or_default())
            ));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response)
    }
}

impl AuthencSocialLogin {
    /// Parse user profile from provider-specific response format
    fn parse_user_profile(&self, provider: &SocialProvider, data: &serde_json::Value) -> Result<SocialUserProfile, SocialLoginError> {
        match provider {
            SocialProvider::Google => Ok(SocialUserProfile {
                provider: provider.clone(),
                provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
                email: data["email"].as_str().map(|s| s.to_string()),
                email_verified: data["verified_email"].as_bool().unwrap_or(false),
                name: data["name"].as_str().map(|s| s.to_string()),
                first_name: data["given_name"].as_str().map(|s| s.to_string()),
                last_name: data["family_name"].as_str().map(|s| s.to_string()),
                picture: data["picture"].as_str().map(|s| s.to_string()),
                locale: data["locale"].as_str().map(|s| s.to_string()),
                raw_data: data.clone(),
            }),
            SocialProvider::Facebook => Ok(SocialUserProfile {
                provider: provider.clone(),
                provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
                email: data["email"].as_str().map(|s| s.to_string()),
                email_verified: true, // Facebook emails are verified
                name: data["name"].as_str().map(|s| s.to_string()),
                first_name: data["first_name"].as_str().map(|s| s.to_string()),
                last_name: data["last_name"].as_str().map(|s| s.to_string()),
                picture: data["picture"]["data"]["url"].as_str().map(|s| s.to_string()),
                locale: data["locale"].as_str().map(|s| s.to_string()),
                raw_data: data.clone(),
            }),
            SocialProvider::GitHub => Ok(SocialUserProfile {
                provider: provider.clone(),
                provider_user_id: data["id"].to_string(),
                email: data["email"].as_str().map(|s| s.to_string()),
                email_verified: true, // GitHub emails are verified
                name: data["name"].as_str().map(|s| s.to_string()),
                first_name: None,
                last_name: None,
                picture: data["avatar_url"].as_str().map(|s| s.to_string()),
                locale: None,
                raw_data: data.clone(),
            }),
            SocialProvider::Microsoft => Ok(SocialUserProfile {
                provider: provider.clone(),
                provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
                email: data["mail"].as_str().or_else(|| data["userPrincipalName"].as_str()).map(|s| s.to_string()),
                email_verified: true, // Microsoft emails are verified
                name: data["displayName"].as_str().map(|s| s.to_string()),
                first_name: data["givenName"].as_str().map(|s| s.to_string()),
                last_name: data["surname"].as_str().map(|s| s.to_string()),
                picture: None,
                locale: data["preferredLanguage"].as_str().map(|s| s.to_string()),
                raw_data: data.clone(),
            }),
            _ => Ok(SocialUserProfile {
                provider: provider.clone(),
                provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
                email: data["email"].as_str().map(|s| s.to_string()),
                email_verified: false,
                name: data["name"].as_str().map(|s| s.to_string()),
                first_name: data["first_name"].as_str().map(|s| s.to_string()),
                last_name: data["last_name"].as_str().map(|s| s.to_string()),
                picture: data["picture"].as_str().map(|s| s.to_string()),
                locale: data["locale"].as_str().map(|s| s.to_string()),
                raw_data: data.clone(),
            }),
        }
    }
}
