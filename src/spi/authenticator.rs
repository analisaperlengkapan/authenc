use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::models::user::User;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Authenticator types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticatorType {
    /// Username/password authentication
    UsernamePassword,
    /// One-time password (TOTP)
    OTP,
    /// WebAuthn/FIDO2 authentication
    WebAuthn,
    /// Recovery codes
    RecoveryCode,
    /// Social login
    Social,
    /// Custom authenticator
    Custom(String),
}

/// Authentication flow types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticationFlowType {
    /// Browser-based authentication flow
    Browser,
    /// Direct access grants (resource owner password credentials)
    DirectGrant,
    /// Client authentication flow
    Client,
    /// Registration flow
    Registration,
    /// Reset credentials flow
    ResetCredentials,
    /// Custom flow
    Custom(String),
}

/// Authentication context
#[derive(Debug, Clone)]
pub struct AuthenticationContext {
    /// The realm ID
    pub realm_id: String,
    /// The client ID
    pub client_id: String,
    /// The user being authenticated (if known)
    pub user: Option<Arc<User>>,
    /// Authentication flow type
    pub flow_type: AuthenticationFlowType,
    /// HTTP request parameters
    pub parameters: HashMap<String, String>,
    /// Session data
    pub session_data: HashMap<String, String>,
    /// Current authentication step
    pub current_step: Option<String>,
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// Whether authentication was successful
    pub success: bool,
    /// The authenticated user (if successful)
    pub user: Option<Arc<User>>,
    /// Authentication method used
    pub authenticator_type: AuthenticatorType,
    /// Additional authentication data
    pub auth_data: HashMap<String, String>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Authenticator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorConfig {
    /// Unique identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Authenticator type
    pub authenticator_type: AuthenticatorType,
    /// Priority/order in authentication flow
    pub priority: i32,
    /// Whether this authenticator is required
    pub required: bool,
    /// Whether this authenticator is enabled
    pub enabled: bool,
    /// Configuration properties
    pub config: HashMap<String, String>,
}

/// Authenticator trait
#[async_trait]
pub trait Authenticator: Provider + Send + Sync {
    /// Get the authenticator configuration
    fn get_config(&self) -> &AuthenticatorConfig;

    /// Authenticate a user
    async fn authenticate(&self, context: &AuthenticationContext) -> Result<AuthenticationResult>;

    /// Check if this authenticator is configured for the given context
    fn is_configured_for(&self, context: &AuthenticationContext) -> bool;

    /// Get the authenticator type
    fn get_authenticator_type(&self) -> AuthenticatorType;

    /// Set required actions for the user (if authentication succeeds)
    async fn set_required_actions(&self, _user: &User) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

/// Username/password authenticator
pub struct UsernamePasswordAuthenticator {
    config: AuthenticatorConfig,
}

impl UsernamePasswordAuthenticator {
    /// Creates a new username/password authenticator with the given configuration
    pub fn new(config: AuthenticatorConfig) -> Self {
        Self { config }
    }
}

impl Provider for UsernamePasswordAuthenticator {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl Authenticator for UsernamePasswordAuthenticator {
    fn get_config(&self) -> &AuthenticatorConfig {
        &self.config
    }

    async fn authenticate(&self, context: &AuthenticationContext) -> Result<AuthenticationResult> {
        // Extract username and password from parameters
        let username = context.parameters.get("username");
        let password = context.parameters.get("password");

        if let (Some(_username), Some(_password)) = (username, password) {
            // In a real implementation, this would validate against the user store
            // For now, return a placeholder result
            Ok(AuthenticationResult {
                success: true,
                user: None, // Would be populated from user store
                authenticator_type: AuthenticatorType::UsernamePassword,
                auth_data: HashMap::new(),
                error_message: None,
            })
        } else {
            Ok(AuthenticationResult {
                success: false,
                user: None,
                authenticator_type: AuthenticatorType::UsernamePassword,
                auth_data: HashMap::new(),
                error_message: Some("Username and password required".to_string()),
            })
        }
    }

    fn is_configured_for(&self, _context: &AuthenticationContext) -> bool {
        true // Username/password is always available
    }

    fn get_authenticator_type(&self) -> AuthenticatorType {
        AuthenticatorType::UsernamePassword
    }
}

/// OTP authenticator
pub struct OTPAuthenticator {
    config: AuthenticatorConfig,
}

impl OTPAuthenticator {
    /// Creates a new OTP authenticator with the given configuration
    pub fn new(config: AuthenticatorConfig) -> Self {
        Self { config }
    }
}

impl Provider for OTPAuthenticator {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl Authenticator for OTPAuthenticator {
    fn get_config(&self) -> &AuthenticatorConfig {
        &self.config
    }

    async fn authenticate(&self, context: &AuthenticationContext) -> Result<AuthenticationResult> {
        // Extract OTP code from parameters
        let code = context.parameters.get("otp");

        if let Some(_code) = code {
            // In a real implementation, this would validate the TOTP code
            // For now, return a placeholder result
            Ok(AuthenticationResult {
                success: true,
                user: None, // Would be populated from user store
                authenticator_type: AuthenticatorType::OTP,
                auth_data: HashMap::new(),
                error_message: None,
            })
        } else {
            Ok(AuthenticationResult {
                success: false,
                user: None,
                authenticator_type: AuthenticatorType::OTP,
                auth_data: HashMap::new(),
                error_message: Some("OTP code required".to_string()),
            })
        }
    }

    fn is_configured_for(&self, _context: &AuthenticationContext) -> bool {
        // Check if user has TOTP configured
        // For now, assume it's available
        true
    }

    fn get_authenticator_type(&self) -> AuthenticatorType {
        AuthenticatorType::OTP
    }
}

/// Authenticator provider trait
#[async_trait]
pub trait AuthenticatorProvider: Provider + Send + Sync {
    /// Get all available authenticators
    async fn get_authenticators(&self) -> Result<Vec<Box<dyn Authenticator + Send + Sync>>>;

    /// Get authenticator by ID
    async fn get_authenticator(
        &self,
        authenticator_id: &str,
    ) -> Result<Option<Box<dyn Authenticator + Send + Sync>>>;

    /// Get authenticators for a specific flow type
    async fn get_authenticators_for_flow(
        &self,
        flow_type: AuthenticationFlowType,
    ) -> Result<Vec<Box<dyn Authenticator + Send + Sync>>>;

    /// Create authentication context
    fn create_authentication_context(
        &self,
        realm_id: &str,
        client_id: &str,
        flow_type: AuthenticationFlowType,
        parameters: HashMap<String, String>,
    ) -> AuthenticationContext {
        AuthenticationContext {
            realm_id: realm_id.to_string(),
            client_id: client_id.to_string(),
            user: None,
            flow_type,
            parameters,
            session_data: HashMap::new(),
            current_step: None,
        }
    }
}

/// Default authenticator provider
pub struct DefaultAuthenticatorProvider;

impl Default for DefaultAuthenticatorProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultAuthenticatorProvider {
    /// Creates a new default authenticator provider
    pub fn new() -> Self {
        Self
    }
}

impl Provider for DefaultAuthenticatorProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl AuthenticatorProvider for DefaultAuthenticatorProvider {
    async fn get_authenticators(&self) -> Result<Vec<Box<dyn Authenticator + Send + Sync>>> {
        let mut authenticators: Vec<Box<dyn Authenticator + Send + Sync>> = Vec::new();

        // Add default username/password authenticator
        let username_password_config = AuthenticatorConfig {
            id: "username-password".to_string(),
            name: "Username Password".to_string(),
            authenticator_type: AuthenticatorType::UsernamePassword,
            priority: 10,
            required: true,
            enabled: true,
            config: HashMap::new(),
        };
        authenticators.push(Box::new(UsernamePasswordAuthenticator::new(
            username_password_config,
        )));

        // Add default OTP authenticator
        let otp_config = AuthenticatorConfig {
            id: "otp".to_string(),
            name: "One-Time Password".to_string(),
            authenticator_type: AuthenticatorType::OTP,
            priority: 20,
            required: false,
            enabled: true,
            config: HashMap::new(),
        };
        authenticators.push(Box::new(OTPAuthenticator::new(otp_config)));

        Ok(authenticators)
    }

    async fn get_authenticator(
        &self,
        authenticator_id: &str,
    ) -> Result<Option<Box<dyn Authenticator + Send + Sync>>> {
        let authenticators = self.get_authenticators().await?;
        Ok(authenticators
            .into_iter()
            .find(|a| a.get_config().id == authenticator_id))
    }

    async fn get_authenticators_for_flow(
        &self,
        _flow_type: AuthenticationFlowType,
    ) -> Result<Vec<Box<dyn Authenticator + Send + Sync>>> {
        let all_authenticators = self.get_authenticators().await?;
        // For now, return all authenticators for all flows
        // In a real implementation, this would filter based on flow requirements
        Ok(all_authenticators)
    }
}

/// Authenticator provider factory
pub struct DefaultAuthenticatorProviderFactory;

impl Default for DefaultAuthenticatorProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultAuthenticatorProviderFactory {
    /// Create a new default authenticator provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn AuthenticatorProvider> for DefaultAuthenticatorProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn AuthenticatorProvider>, SpiError> {
        Ok(Box::new(DefaultAuthenticatorProvider::new()))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-authenticator"
    }
}

/// Authenticator SPI implementation
pub struct AuthenticatorSpi;

impl Spi for AuthenticatorSpi {
    fn get_name(&self) -> &'static str {
        "authenticator"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "AuthenticatorProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "AuthenticatorProviderFactory"
    }
}
