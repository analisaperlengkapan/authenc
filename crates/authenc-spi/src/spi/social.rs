use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use authenc_core::error::{AuthencError as Error, Result};
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Social provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SocialProviderType {
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
    /// Custom OAuth provider with custom name
    Custom(String),
}

/// Social user profile from external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserProfile {
    /// Provider type
    pub provider_type: SocialProviderType,

    /// Provider-specific user ID
    pub provider_user_id: String,

    /// Email address
    pub email: Option<String>,

    /// Display name
    pub display_name: Option<String>,

    /// First name
    pub first_name: Option<String>,

    /// Last name
    pub last_name: Option<String>,

    /// Username
    pub username: Option<String>,

    /// Profile picture URL
    pub picture_url: Option<String>,

    /// Raw profile data from provider
    pub raw_profile: serde_json::Value,

    /// Additional attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

/// OAuth2 token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    /// Access token
    pub access_token: String,

    /// Token type (usually "Bearer")
    pub token_type: String,

    /// Expires in seconds
    pub expires_in: Option<u64>,

    /// Refresh token
    pub refresh_token: Option<String>,

    /// Scope
    pub scope: Option<String>,

    /// ID token (for OpenID Connect)
    pub id_token: Option<String>,
}

/// SPI for social identity providers (OAuth2/OIDC)
#[async_trait]
pub trait SocialProvider: Provider {
    /// Check if the provider is enabled
    fn is_enabled(&self) -> bool {
        true
    }

    /// Get the provider type
    fn get_provider_type(&self) -> SocialProviderType;

    /// Get authorization URL for OAuth2 flow
    async fn get_authorization_url(&self, state: &str, redirect_uri: &str) -> Result<String>;

    /// Exchange authorization code for access token
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<OAuth2Token>;

    /// Get user profile from provider
    async fn get_user_profile(&self, token: &OAuth2Token) -> Result<SocialUserProfile>;

    /// Refresh access token
    async fn refresh_token(&self, refresh_token: &str) -> Result<OAuth2Token>;

    /// Validate access token
    async fn validate_token(&self, token: &str) -> Result<bool>;

    /// Revoke token
    async fn revoke_token(&self, token: &str) -> Result<()>;
}

/// Configuration for social providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProviderConfig {
    /// Provider type
    pub provider_type: SocialProviderType,

    /// Client ID from provider
    pub client_id: String,

    /// Client secret from provider
    pub client_secret: String,

    /// Authorization endpoint URL
    pub authorization_url: String,

    /// Token endpoint URL
    pub token_url: String,

    /// User info endpoint URL
    pub user_info_url: String,

    /// Scope to request
    pub scope: Option<String>,

    /// Redirect URI
    pub redirect_uri: Option<String>,

    /// Enable provider
    pub enabled: Option<bool>,

    /// Trust email from provider
    pub trust_email: Option<bool>,

    /// Store tokens
    pub store_tokens: Option<bool>,

    /// Link only existing users
    pub link_only: Option<bool>,

    /// First broker login flow alias
    pub first_broker_login_flow_alias: Option<String>,

    /// Post broker login flow alias
    pub post_broker_login_flow_alias: Option<String>,

    /// Custom attributes mapping
    pub attribute_mapping: Option<HashMap<String, String>>,

    /// GUI order
    pub gui_order: Option<i32>,
}

impl Default for SocialProviderConfig {
    fn default() -> Self {
        Self {
            provider_type: SocialProviderType::Google,
            client_id: String::new(),
            client_secret: String::new(),
            authorization_url: String::new(),
            token_url: String::new(),
            user_info_url: String::new(),
            scope: Some("openid email profile".to_string()),
            redirect_uri: None,
            enabled: Some(true),
            trust_email: Some(false),
            store_tokens: Some(true),
            link_only: Some(false),
            first_broker_login_flow_alias: Some("first broker login".to_string()),
            post_broker_login_flow_alias: Some("post broker login".to_string()),
            attribute_mapping: None,
            gui_order: Some(0),
        }
    }
}

/// Factory for creating social providers
#[async_trait]
pub trait SocialProviderFactory: ProviderFactory<dyn SocialProvider> {
    /// Create a new social provider
    async fn create(&self, config: &SocialProviderConfig) -> Result<Arc<dyn SocialProvider>>;
}

/// Default implementation of social provider
pub struct DefaultSocialProvider {
    /// Provider configuration
    config: SocialProviderConfig,
}

impl DefaultSocialProvider {
    /// Create a new default social provider with the given configuration
    pub fn new(config: SocialProviderConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Provider for DefaultSocialProvider {
    fn close(&mut self) {
        // Close connections
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl SocialProvider for DefaultSocialProvider {
    fn is_enabled(&self) -> bool {
        self.config.enabled.unwrap_or(true)
    }

    fn get_provider_type(&self) -> SocialProviderType {
        self.config.provider_type.clone()
    }

    async fn get_authorization_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        // Build OAuth2 authorization URL
        let mut url = url::Url::parse(&self.config.authorization_url).map_err(|e| {
            Error::ConfigurationError {
                message: e.to_string(),
            }
        })?;

        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair(
                "scope",
                self.config
                    .scope
                    .as_deref()
                    .unwrap_or("openid email profile"),
            )
            .append_pair("state", state)
            .append_pair("redirect_uri", redirect_uri);

        Ok(url.to_string())
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<OAuth2Token> {
        // Implement OAuth2 token exchange
        // This would make HTTP request to token endpoint
        let client = reqwest::Client::new();

        let params = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("code", &code.to_string()),
            ("grant_type", &"authorization_code".to_string()),
            ("redirect_uri", &redirect_uri.to_string()),
        ];

        let response = client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|_e| Error::ExternalServiceError {
                service: "oauth2_token_exchange".to_string(),
            })?;

        if !response.status().is_success() {
            return Err(Error::ExternalServiceError {
                service: "oauth2_token_exchange".to_string(),
            });
        }

        let token_response: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| Error::SerializationError {
                    message: e.to_string(),
                })?;

        let access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| Error::ExternalServiceError {
                service: "oauth2_token_exchange".to_string(),
            })?
            .to_string();

        let token_type = token_response["token_type"]
            .as_str()
            .unwrap_or("Bearer")
            .to_string();

        let expires_in = token_response["expires_in"].as_u64().unwrap_or(3600);

        let refresh_token = token_response["refresh_token"]
            .as_str()
            .map(|s| s.to_string());

        let scope = token_response["scope"].as_str().map(|s| s.to_string());

        Ok(OAuth2Token {
            access_token,
            token_type,
            expires_in: Some(expires_in),
            refresh_token,
            scope,
            id_token: token_response["id_token"].as_str().map(|s| s.to_string()),
        })
    }

    async fn get_user_profile(&self, token: &OAuth2Token) -> Result<SocialUserProfile> {
        // Implement user profile fetching
        let client = reqwest::Client::new();

        let response = client
            .get(&self.config.user_info_url)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|_e| Error::ExternalServiceError {
                service: "user_profile_fetch".to_string(),
            })?;

        if !response.status().is_success() {
            return Err(Error::ExternalServiceError {
                service: "user_profile_fetch".to_string(),
            });
        }

        let profile_data: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| Error::SerializationError {
                    message: e.to_string(),
                })?;

        // Parse profile data based on provider
        let profile = match self.config.provider_type {
            SocialProviderType::Google => self.parse_google_profile(&profile_data)?,
            SocialProviderType::Facebook => self.parse_facebook_profile(&profile_data)?,
            SocialProviderType::GitHub => self.parse_github_profile(&profile_data)?,
            SocialProviderType::Microsoft => self.parse_microsoft_profile(&profile_data)?,
            SocialProviderType::LinkedIn => self.parse_linkedin_profile(&profile_data)?,
            SocialProviderType::Twitter => self.parse_twitter_profile(&profile_data)?,
            SocialProviderType::Apple => self.parse_apple_profile(&profile_data)?,
            _ => self.parse_generic_profile(&profile_data)?,
        };

        Ok(profile)
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<OAuth2Token> {
        // Implement token refresh
        let client = reqwest::Client::new();

        let params = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("refresh_token", &refresh_token.to_string()),
            ("grant_type", &"refresh_token".to_string()),
        ];

        let response = client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|_e| Error::ExternalServiceError {
                service: "oauth2_token_refresh".to_string(),
            })?;

        if !response.status().is_success() {
            return Err(Error::ExternalServiceError {
                service: "oauth2_token_refresh".to_string(),
            });
        }

        let token_response: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| Error::SerializationError {
                    message: e.to_string(),
                })?;

        let access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| Error::ExternalServiceError {
                service: "oauth2_token_refresh".to_string(),
            })?
            .to_string();

        let token_type = token_response["token_type"]
            .as_str()
            .unwrap_or("Bearer")
            .to_string();

        let expires_in = token_response["expires_in"].as_u64().unwrap_or(3600);

        let new_refresh_token = token_response["refresh_token"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| refresh_token.to_string()); // Keep old refresh token if not provided

        let scope = token_response["scope"].as_str().map(|s| s.to_string());

        Ok(OAuth2Token {
            access_token,
            token_type,
            expires_in: Some(expires_in),
            refresh_token: Some(new_refresh_token),
            scope,
            id_token: token_response["id_token"].as_str().map(|s| s.to_string()),
        })
    }

    async fn validate_token(&self, token: &str) -> Result<bool> {
        // Basic token validation - check if we can fetch user profile
        match self
            .get_user_profile(&OAuth2Token {
                access_token: token.to_string(),
                token_type: "Bearer".to_string(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None,
                id_token: None,
            })
            .await
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn revoke_token(&self, _token: &str) -> Result<()> {
        // Token revocation - implementation depends on provider
        // For now, just return success as tokens are typically short-lived
        Ok(())
    }
}

impl DefaultSocialProvider {
    /// Parse Google OAuth2 user profile
    fn parse_google_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::Google,
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            display_name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            username: None, // Google doesn't provide username
            picture_url: data["picture"].as_str().map(|s| s.to_string()),
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse Facebook OAuth2 user profile
    fn parse_facebook_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::Facebook,
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            display_name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["first_name"].as_str().map(|s| s.to_string()),
            last_name: data["last_name"].as_str().map(|s| s.to_string()),
            username: None,
            picture_url: Some(format!(
                "https://graph.facebook.com/{}/picture?type=large",
                data["id"].as_str().unwrap_or("")
            )),
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse GitHub OAuth2 user profile
    fn parse_github_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::GitHub,
            provider_user_id: data["id"]
                .as_u64()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            display_name: data["name"].as_str().map(|s| s.to_string()),
            first_name: None,
            last_name: None,
            username: data["login"].as_str().map(|s| s.to_string()),
            picture_url: data["avatar_url"].as_str().map(|s| s.to_string()),
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse Microsoft OAuth2 user profile
    fn parse_microsoft_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::Microsoft,
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["mail"]
                .as_str()
                .or_else(|| data["userPrincipalName"].as_str())
                .map(|s| s.to_string()),
            display_name: data["displayName"].as_str().map(|s| s.to_string()),
            first_name: data["givenName"].as_str().map(|s| s.to_string()),
            last_name: data["surname"].as_str().map(|s| s.to_string()),
            username: None,
            picture_url: None, // Microsoft Graph API requires separate call for photo
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse LinkedIn OAuth2 user profile
    fn parse_linkedin_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::LinkedIn,
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["emailAddress"].as_str().map(|s| s.to_string()),
            display_name: data["formattedName"].as_str().map(|s| s.to_string()),
            first_name: data["firstName"].as_str().map(|s| s.to_string()),
            last_name: data["lastName"].as_str().map(|s| s.to_string()),
            username: None,
            picture_url: data["pictureUrl"].as_str().map(|s| s.to_string()),
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse Twitter OAuth2 user profile
    fn parse_twitter_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::Twitter,
            provider_user_id: data["id"]
                .as_str()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            display_name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["name"].as_str().map(|s| s.to_string()),
            last_name: None,
            username: None,
            picture_url: data["profile_image_url"].as_str().map(|s| s.to_string()),
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse Apple OAuth2 user profile
    fn parse_apple_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: SocialProviderType::Apple,
            provider_user_id: data["sub"]
                .as_str()
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            display_name: data["name"]["firstName"].as_str().map(|s| s.to_string()),
            first_name: data["name"]["firstName"].as_str().map(|s| s.to_string()),
            last_name: data["name"]["lastName"].as_str().map(|s| s.to_string()),
            username: None,
            picture_url: None,
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }

    /// Parse generic OAuth2 user profile
    fn parse_generic_profile(&self, data: &serde_json::Value) -> Result<SocialUserProfile> {
        Ok(SocialUserProfile {
            provider_type: self.config.provider_type.clone(),
            provider_user_id: data["id"]
                .as_str()
                .or_else(|| data["sub"].as_str())
                .ok_or_else(|| Error::ValidationError {
                    message: "Missing user ID".to_string(),
                })?
                .to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            display_name: data["name"]
                .as_str()
                .or_else(|| data["display_name"].as_str())
                .map(|s| s.to_string()),
            first_name: data["given_name"]
                .as_str()
                .or_else(|| data["first_name"].as_str())
                .map(|s| s.to_string()),
            last_name: data["family_name"]
                .as_str()
                .or_else(|| data["last_name"].as_str())
                .map(|s| s.to_string()),
            username: data["username"]
                .as_str()
                .or_else(|| data["login"].as_str())
                .map(|s| s.to_string()),
            picture_url: data["picture"]
                .as_str()
                .or_else(|| data["avatar_url"].as_str())
                .or_else(|| data["photo"].as_str())
                .map(|s| s.to_string()),
            raw_profile: data.clone(),
            attributes: HashMap::new(),
        })
    }
}

/// Default factory for social providers
pub struct DefaultSocialProviderFactory;

impl Default for DefaultSocialProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultSocialProviderFactory {
    /// Create a new default social provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn SocialProvider> for DefaultSocialProviderFactory {
    fn create(
        &self,
        config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn SocialProvider>, SpiError> {
        let social_config: SocialProviderConfig =
            serde_json::from_value(serde_json::Value::Object(
                config
                    .properties
                    .iter()
                    .map(|(k, v)| {
                        // Try to parse as JSON first, fall back to string
                        let value =
                            serde_json::from_str(v).unwrap_or(serde_json::Value::String(v.clone()));
                        (k.clone(), value)
                    })
                    .collect(),
            ))
            .map_err(|e| SpiError::ConfigurationError(e.to_string()))?;
        let provider = DefaultSocialProvider::new(social_config);
        Ok(Box::new(provider))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

#[async_trait]
impl SocialProviderFactory for DefaultSocialProviderFactory {
    async fn create(&self, config: &SocialProviderConfig) -> Result<Arc<dyn SocialProvider>> {
        let provider = DefaultSocialProvider::new(config.clone());
        Ok(Arc::new(provider))
    }
}

/// SPI definition for social providers
pub struct SocialProviderSpi;

impl Spi for SocialProviderSpi {
    fn get_name(&self) -> &'static str {
        "social"
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.broker.social.SocialProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.broker.social.SocialProviderFactory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_social_provider() {
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::Google,
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            authorization_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            ..Default::default()
        };

        let provider = DefaultSocialProvider::new(config);
        assert!(provider.is_enabled());
        assert_eq!(provider.get_provider_type(), SocialProviderType::Google);
    }

    #[tokio::test]
    async fn test_social_provider_config() {
        let config = SocialProviderConfig::default();

        assert_eq!(config.provider_type, SocialProviderType::Google);
        assert_eq!(config.scope, Some("openid email profile".to_string()));
        assert_eq!(config.enabled, Some(true));
    }

    #[tokio::test]
    async fn test_authorization_url() {
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::Google,
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            authorization_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            ..Default::default()
        };

        let provider = DefaultSocialProvider::new(config);
        let url = provider
            .get_authorization_url("test-state", "http://localhost:8080/callback")
            .await
            .unwrap();

        assert!(url.contains("client_id=test-client"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=test-state"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback"));
    }

    #[tokio::test]
    async fn test_default_social_factory() {
        let factory = DefaultSocialProviderFactory::new();
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::Facebook,
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            authorization_url: "https://www.facebook.com/v12.0/dialog/oauth".to_string(),
            token_url: "https://graph.facebook.com/v12.0/oauth/access_token".to_string(),
            user_info_url: "https://graph.facebook.com/me".to_string(),
            ..Default::default()
        };

        let mut properties = HashMap::new();
        properties.insert("provider_type".to_string(), "Facebook".to_string());
        properties.insert("client_id".to_string(), config.client_id.clone());
        properties.insert("client_secret".to_string(), config.client_secret.clone());
        properties.insert(
            "authorization_url".to_string(),
            config.authorization_url.clone(),
        );
        properties.insert("token_url".to_string(), config.token_url.clone());
        properties.insert("user_info_url".to_string(), config.user_info_url.clone());
        properties.insert(
            "enabled".to_string(),
            config.enabled.unwrap_or(true).to_string(),
        );
        properties.insert(
            "trust_email".to_string(),
            config.trust_email.unwrap_or(false).to_string(),
        );
        properties.insert(
            "store_tokens".to_string(),
            config.store_tokens.unwrap_or(true).to_string(),
        );
        properties.insert(
            "link_only".to_string(),
            config.link_only.unwrap_or(false).to_string(),
        );

        let provider_config = ProviderConfig {
            properties,
            global_config: None,
        };

        let provider =
            <DefaultSocialProviderFactory as ProviderFactory<dyn SocialProvider>>::create(
                &factory,
                &provider_config,
            )
            .unwrap();
        assert!(provider.is_enabled());
        assert_eq!(provider.get_provider_type(), SocialProviderType::Facebook);
    }

    #[tokio::test]
    async fn test_microsoft_profile_parsing() {
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::Microsoft,
            ..Default::default()
        };
        let provider = DefaultSocialProvider::new(config);

        let data = serde_json::json!({
            "id": "12345",
            "displayName": "John Doe",
            "givenName": "John",
            "surname": "Doe",
            "userPrincipalName": "john.doe@example.com",
            "mail": "john.doe@example.com"
        });

        let profile = provider.parse_microsoft_profile(&data).unwrap();

        assert_eq!(profile.provider_type, SocialProviderType::Microsoft);
        assert_eq!(profile.provider_user_id, "12345");
        assert_eq!(profile.display_name, Some("John Doe".to_string()));
        assert_eq!(profile.first_name, Some("John".to_string()));
        assert_eq!(profile.last_name, Some("Doe".to_string()));
        assert_eq!(profile.email, Some("john.doe@example.com".to_string()));
    }

    #[tokio::test]
    async fn test_linkedin_profile_parsing() {
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::LinkedIn,
            ..Default::default()
        };
        let provider = DefaultSocialProvider::new(config);

        let data = serde_json::json!({
            "id": "linked_123",
            "formattedName": "Jane Doe",
            "firstName": "Jane",
            "lastName": "Doe",
            "emailAddress": "jane.doe@linkedin.com",
            "pictureUrl": "http://example.com/pic.jpg"
        });

        let profile = provider.parse_linkedin_profile(&data).unwrap();

        assert_eq!(profile.provider_type, SocialProviderType::LinkedIn);
        assert_eq!(profile.provider_user_id, "linked_123");
        assert_eq!(profile.display_name, Some("Jane Doe".to_string()));
        assert_eq!(profile.first_name, Some("Jane".to_string()));
        assert_eq!(profile.last_name, Some("Doe".to_string()));
        assert_eq!(profile.email, Some("jane.doe@linkedin.com".to_string()));
        assert_eq!(profile.picture_url, Some("http://example.com/pic.jpg".to_string()));
    }

    #[tokio::test]
    async fn test_twitter_profile_parsing() {
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::Twitter,
            ..Default::default()
        };
        let provider = DefaultSocialProvider::new(config);

        let data = serde_json::json!({
            "id": "twitter_123",
            "name": "Twitter User",
            "email": "user@twitter.com",
            "profile_image_url": "http://example.com/twitter_pic.jpg"
        });

        let profile = provider.parse_twitter_profile(&data).unwrap();

        assert_eq!(profile.provider_type, SocialProviderType::Twitter);
        assert_eq!(profile.provider_user_id, "twitter_123");
        assert_eq!(profile.display_name, Some("Twitter User".to_string()));
        assert_eq!(profile.email, Some("user@twitter.com".to_string()));
        assert_eq!(profile.picture_url, Some("http://example.com/twitter_pic.jpg".to_string()));
    }

    #[tokio::test]
    async fn test_apple_profile_parsing() {
        let config = SocialProviderConfig {
            provider_type: SocialProviderType::Apple,
            ..Default::default()
        };
        let provider = DefaultSocialProvider::new(config);

        let data = serde_json::json!({
            "sub": "apple_123",
            "email": "user@privaterelay.appleid.com",
            "name": {
                "firstName": "Apple",
                "lastName": "User"
            }
        });

        let profile = provider.parse_apple_profile(&data).unwrap();

        assert_eq!(profile.provider_type, SocialProviderType::Apple);
        assert_eq!(profile.provider_user_id, "apple_123");
        assert_eq!(profile.email, Some("user@privaterelay.appleid.com".to_string()));
        assert_eq!(profile.display_name, Some("Apple".to_string()));
        assert_eq!(profile.first_name, Some("Apple".to_string()));
        assert_eq!(profile.last_name, Some("User".to_string()));
    }
}
