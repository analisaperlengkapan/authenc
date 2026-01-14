use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{AuthencError as Error, Result};
use crate::models::user::User;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, SpiError};

/// Provider for required actions
#[async_trait]
pub trait RequiredActionProvider: Provider + Send + Sync {
    /// Get the ID of this required action provider
    fn get_id(&self) -> &str;

    /// Get the display name of this required action
    fn get_display_name(&self) -> &str;

    /// Check if this action is configurable
    fn is_configurable(&self) -> bool;

    /// Get the configuration properties for this action
    fn get_config_properties(&self) -> Vec<RequiredActionConfigProperty>;

    /// Evaluate if this required action should be triggered for the user
    async fn evaluate_triggers(&self, context: &RequiredActionContext) -> Result<bool>;

    /// Execute the required action
    async fn execute(&self, context: &RequiredActionContext) -> Result<RequiredActionResult>;

    /// Process the response from a challenge (e.g., form submission)
    async fn process_action_response(
        &self,
        context: &RequiredActionContext,
        response_data: HashMap<String, String>,
    ) -> Result<RequiredActionResult>;

    /// Check if the required action is complete for the user
    async fn is_action_complete(&self, context: &RequiredActionContext) -> Result<bool>;
}

/// Context for required action execution
#[derive(Debug)]
pub struct RequiredActionContext {
    /// The user for whom the action is being executed
    pub user: User,
    /// The realm ID
    pub realm_id: String,
    /// Additional context data
    pub context_data: HashMap<String, String>,
}

/// Result of required action execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequiredActionResult {
    /// Action completed successfully
    Success,
    /// Action failed with error message
    Failed(String),
    /// Action requires user interaction (e.g., redirect to form)
    Challenge {
        /// Challenge type (e.g., "redirect", "form")
        challenge_type: String,
        /// Additional challenge data
        challenge_data: HashMap<String, String>,
    },
}

/// Configuration property for required actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredActionConfigProperty {
    /// Property name
    pub name: String,
    /// Display label
    pub label: String,
    /// Help text
    pub help_text: Option<String>,
    /// Property type
    pub property_type: RequiredActionPropertyType,
    /// Default value
    pub default_value: Option<String>,
    /// Whether the property is required
    pub required: bool,
    /// Whether the property contains secret data
    pub secret: bool,
}

/// Types of configuration properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequiredActionPropertyType {
    /// String property type
    String,
    /// Text property type
    Text,
    /// Boolean property type
    Boolean,
    /// Number property type
    Number,
    /// Password property type
    Password,
    /// Select property type with options
    Select {
        /// Available options
        options: Vec<String>,
    },
    /// Multiselect property type with options
    Multiselect {
        /// Available options
        options: Vec<String>,
    },
}

/// Factory for creating required action providers
#[async_trait]
pub trait RequiredActionProviderFactory: Send + Sync {
    /// Get the ID of the provider this factory creates
    fn get_id(&self) -> &str;

    /// Create a new provider instance with configuration
    async fn create_provider(
        &self,
        config: HashMap<String, String>,
    ) -> Result<Arc<dyn RequiredActionProvider>>;

    /// Get the configuration properties for this provider
    fn get_config_properties(&self) -> Vec<RequiredActionConfigProperty>;
}

/// Default required action provider factory
pub struct DefaultRequiredActionProviderFactory;

impl Default for DefaultRequiredActionProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultRequiredActionProviderFactory {
    /// Create a new default required action provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn RequiredActionProvider> for DefaultRequiredActionProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn RequiredActionProvider>, SpiError> {
        Ok(Box::new(DefaultRequiredActionProvider::new()))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-required-action"
    }
}

/// Default required action provider that handles common actions
pub struct DefaultRequiredActionProvider {
    // Configuration would be stored here
}

impl Default for DefaultRequiredActionProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultRequiredActionProvider {
    /// Create a new default required action provider
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl RequiredActionProvider for DefaultRequiredActionProvider {
    fn get_id(&self) -> &str {
        "default"
    }

    fn get_display_name(&self) -> &str {
        "Default Required Action Provider"
    }

    fn is_configurable(&self) -> bool {
        true
    }

    fn get_config_properties(&self) -> Vec<RequiredActionConfigProperty> {
        vec![RequiredActionConfigProperty {
            name: "action_type".to_string(),
            label: "Action Type".to_string(),
            help_text: Some("Type of required action to perform".to_string()),
            property_type: RequiredActionPropertyType::Select {
                options: vec![
                    "UPDATE_PASSWORD".to_string(),
                    "VERIFY_EMAIL".to_string(),
                    "UPDATE_PROFILE".to_string(),
                    "CONFIGURE_TOTP".to_string(),
                    "UPDATE_USER_LOCALE".to_string(),
                ],
            },
            default_value: Some("UPDATE_PASSWORD".to_string()),
            required: true,
            secret: false,
        }]
    }

    async fn evaluate_triggers(&self, _context: &RequiredActionContext) -> Result<bool> {
        // Default implementation - always return false (no triggers)
        // Real implementations would check user state, realm settings, etc.
        Ok(false)
    }

    async fn execute(&self, context: &RequiredActionContext) -> Result<RequiredActionResult> {
        // Default implementation - mark as success
        // Real implementations would perform the actual required action
        tracing::info!(
            "Executing default required action for user: {}",
            context.user.username
        );
        Ok(RequiredActionResult::Success)
    }

    async fn process_action_response(
        &self,
        _context: &RequiredActionContext,
        _response_data: HashMap<String, String>,
    ) -> Result<RequiredActionResult> {
        // Default implementation - mark as success
        Ok(RequiredActionResult::Success)
    }

    async fn is_action_complete(&self, _context: &RequiredActionContext) -> Result<bool> {
        // Default implementation - always complete
        Ok(true)
    }
}

impl Provider for DefaultRequiredActionProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Update password required action provider
pub struct UpdatePasswordRequiredActionProvider;

impl Default for UpdatePasswordRequiredActionProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl UpdatePasswordRequiredActionProvider {
    /// Create a new update password required action provider
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequiredActionProvider for UpdatePasswordRequiredActionProvider {
    fn get_id(&self) -> &str {
        "UPDATE_PASSWORD"
    }

    fn get_display_name(&self) -> &str {
        "Update Password"
    }

    fn is_configurable(&self) -> bool {
        false
    }

    fn get_config_properties(&self) -> Vec<RequiredActionConfigProperty> {
        vec![]
    }

    async fn evaluate_triggers(&self, context: &RequiredActionContext) -> Result<bool> {
        // Check if user needs to update password (e.g., temporary password, expired password)
        // This would typically check user attributes or realm policies
        Ok(context
            .context_data
            .get("force_password_update")
            .map(|v| v == "true")
            .unwrap_or(false))
    }

    async fn execute(&self, _context: &RequiredActionContext) -> Result<RequiredActionResult> {
        // Return challenge to show password update form
        Ok(RequiredActionResult::Challenge {
            challenge_type: "form".to_string(),
            challenge_data: HashMap::from([
                ("form_type".to_string(), "UPDATE_PASSWORD".to_string()),
                (
                    "message".to_string(),
                    "Please update your password to continue.".to_string(),
                ),
            ]),
        })
    }

    async fn process_action_response(
        &self,
        context: &RequiredActionContext,
        response_data: HashMap<String, String>,
    ) -> Result<RequiredActionResult> {
        // Process password update form submission
        let new_password = response_data
            .get("password")
            .ok_or_else(|| Error::ValidationError {
                message: "Password is required".to_string(),
            })?;

        let confirm_password =
            response_data
                .get("confirm_password")
                .ok_or_else(|| Error::ValidationError {
                    message: "Password confirmation is required".to_string(),
                })?;

        if new_password != confirm_password {
            return Ok(RequiredActionResult::Challenge {
                challenge_type: "form".to_string(),
                challenge_data: HashMap::from([
                    ("form_type".to_string(), "UPDATE_PASSWORD".to_string()),
                    ("error".to_string(), "Passwords do not match".to_string()),
                ]),
            });
        }

        // Here you would typically update the user's password
        tracing::info!("Password updated for user: {}", context.user.username);

        Ok(RequiredActionResult::Success)
    }

    async fn is_action_complete(&self, _context: &RequiredActionContext) -> Result<bool> {
        // Check if password has been updated recently
        // This would typically check user attributes
        Ok(false) // For now, assume not complete
    }
}

impl Provider for UpdatePasswordRequiredActionProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Email verification required action provider
pub struct VerifyEmailRequiredActionProvider;

impl Default for VerifyEmailRequiredActionProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyEmailRequiredActionProvider {
    /// Create a new email verification required action provider
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequiredActionProvider for VerifyEmailRequiredActionProvider {
    fn get_id(&self) -> &str {
        "VERIFY_EMAIL"
    }

    fn get_display_name(&self) -> &str {
        "Verify Email"
    }

    fn is_configurable(&self) -> bool {
        false
    }

    fn get_config_properties(&self) -> Vec<RequiredActionConfigProperty> {
        vec![]
    }

    async fn evaluate_triggers(&self, context: &RequiredActionContext) -> Result<bool> {
        // Check if user's email is not verified
        Ok(!context.user.email_verified)
    }

    async fn execute(&self, context: &RequiredActionContext) -> Result<RequiredActionResult> {
        // Send verification email and return challenge
        tracing::info!(
            "Sending email verification for user: {}",
            context.user.username
        );

        Ok(RequiredActionResult::Challenge {
            challenge_type: "redirect".to_string(),
            challenge_data: HashMap::from([
                (
                    "redirect_url".to_string(),
                    "/auth/realms/master/login-actions/verify-email".to_string(),
                ),
                (
                    "message".to_string(),
                    "Please check your email and click the verification link.".to_string(),
                ),
            ]),
        })
    }

    async fn process_action_response(
        &self,
        _context: &RequiredActionContext,
        _response_data: HashMap<String, String>,
    ) -> Result<RequiredActionResult> {
        // Email verification is typically handled via email link, not form submission
        Ok(RequiredActionResult::Success)
    }

    async fn is_action_complete(&self, context: &RequiredActionContext) -> Result<bool> {
        Ok(context.user.email_verified)
    }
}

impl Provider for VerifyEmailRequiredActionProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// TOTP setup required action provider
pub struct ConfigureTotpRequiredActionProvider;

impl Default for ConfigureTotpRequiredActionProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigureTotpRequiredActionProvider {
    /// Create a new TOTP setup required action provider
    pub fn new() -> Self {
        Self
    }
}

impl Provider for ConfigureTotpRequiredActionProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl RequiredActionProvider for ConfigureTotpRequiredActionProvider {
    fn get_id(&self) -> &str {
        "CONFIGURE_TOTP"
    }

    fn get_display_name(&self) -> &str {
        "Configure TOTP"
    }

    fn is_configurable(&self) -> bool {
        false
    }

    fn get_config_properties(&self) -> Vec<RequiredActionConfigProperty> {
        vec![]
    }

    async fn evaluate_triggers(&self, context: &RequiredActionContext) -> Result<bool> {
        // Check if TOTP is required but not configured
        Ok(context
            .context_data
            .get("require_totp")
            .map(|v| v == "true")
            .unwrap_or(false))
    }

    async fn execute(&self, _context: &RequiredActionContext) -> Result<RequiredActionResult> {
        // Return challenge to show TOTP setup form
        Ok(RequiredActionResult::Challenge {
            challenge_type: "form".to_string(),
            challenge_data: HashMap::from([
                ("form_type".to_string(), "CONFIGURE_TOTP".to_string()),
                (
                    "message".to_string(),
                    "Set up two-factor authentication using an authenticator app.".to_string(),
                ),
            ]),
        })
    }

    async fn process_action_response(
        &self,
        context: &RequiredActionContext,
        response_data: HashMap<String, String>,
    ) -> Result<RequiredActionResult> {
        // Process TOTP setup form submission
        let _totp_code = response_data
            .get("totp_code")
            .ok_or_else(|| Error::ValidationError {
                message: "TOTP code is required".to_string(),
            })?;

        // Here you would validate the TOTP code and save the TOTP secret
        tracing::info!("TOTP configured for user: {}", context.user.username);

        Ok(RequiredActionResult::Success)
    }

    async fn is_action_complete(&self, _context: &RequiredActionContext) -> Result<bool> {
        // Check if TOTP is configured for the user
        Ok(false) // For now, assume not complete
    }
}

/// Required Actions SPI implementation
pub struct RequiredActionSpi;

impl crate::spi::Spi for RequiredActionSpi {
    fn get_name(&self) -> &'static str {
        "required-action"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "RequiredActionProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "RequiredActionProviderFactory"
    }
}
