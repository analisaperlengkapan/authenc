use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

use authenc_core::error::{AuthencError as Error, Result};
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use authenc_crypto::utils::crypto::password::{hash_password, verify_password};

/// OTP/TOTP Credential Provider Implementation
pub mod otp;
pub mod webauthn;

/// Credential input for authentication attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInput {
    /// Optional unique identifier for the credential
    pub credential_id: Option<String>,
    /// Type of credential (e.g., "password", "otp")
    pub credential_type: String,
    /// Challenge response data for authentication
    pub challenge_response: String,
}

impl CredentialInput {
    /// Creates a new credential input with the specified type and response
    pub fn new(credential_type: String, challenge_response: String) -> Self {
        Self {
            credential_id: None,
            credential_type,
            challenge_response,
        }
    }

    /// Gets the credential identifier if present
    pub fn get_credential_id(&self) -> Option<&str> {
        self.credential_id.as_deref()
    }

    /// Gets the credential type
    pub fn get_type(&self) -> &str {
        &self.credential_type
    }

    /// Gets the challenge response data
    pub fn get_challenge_response(&self) -> &str {
        &self.challenge_response
    }
}

/// Credential input updater for managing credential updates
#[async_trait]
pub trait CredentialInputUpdater: Send + Sync {
    /// Check if this updater supports the given credential type
    fn supports_credential_type(&self, credential_type: &str) -> bool;

    /// Update credential with input
    async fn update_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        input: &CredentialInput,
    ) -> Result<bool>;

    /// Disable a credential type for a user
    async fn disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<()>;

    /// Get disableable credential types for a user
    async fn get_disableable_credential_types(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<String>>;

    /// Get credentials managed by this updater
    async fn get_credentials(&self, realm_id: &str, user_id: &str) -> Result<Vec<CredentialModel>>;
}

/// Credential input validator for validating authentication attempts
#[async_trait]
pub trait CredentialInputValidator: Send + Sync {
    /// Check if this validator supports the given credential type
    fn supports_credential_type(&self, credential_type: &str) -> bool;

    /// Check if credential type is configured for user
    async fn is_configured_for(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<bool>;

    /// Validate credential input
    async fn is_valid(
        &self,
        realm_id: &str,
        user_id: &str,
        input: &CredentialInput,
    ) -> Result<bool>;
}

/// Credential model representing a user credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialModel {
    /// Unique identifier for the credential
    pub id: String,
    /// Type of credential (e.g., "password", "otp")
    pub credential_type: String,
    /// User identifier this credential belongs to
    pub user_id: String,
    /// Realm identifier this credential belongs to
    pub realm_id: String,
    /// Creation timestamp in milliseconds
    pub created_date: i64,
    /// User-defined label for the credential
    pub user_label: Option<String>,
    /// Secret data (encrypted/hashed)
    pub secret_data: Option<String>,
    /// Credential-specific data
    pub credential_data: Option<String>,
    /// Priority order for credential usage
    pub priority: i32,
    /// Federation link if credential is from external provider
    pub federation_link: Option<String>,
    /// Additional configuration parameters
    pub config: HashMap<String, String>,
}

impl CredentialModel {
    /// Creates a new credential model with the specified type, user, and realm
    pub fn new(credential_type: String, user_id: String, realm_id: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            credential_type,
            user_id,
            realm_id,
            created_date: chrono::Utc::now().timestamp_millis(),
            user_label: None,
            secret_data: None,
            credential_data: None,
            priority: 0,
            federation_link: None,
            config: HashMap::new(),
        }
    }

    /// Gets the credential type
    pub fn get_type(&self) -> &str {
        &self.credential_type
    }

    /// Gets the federation link if present
    pub fn get_federation_link(&self) -> Option<&str> {
        self.federation_link.as_deref()
    }

    /// Sets the federation link
    pub fn set_federation_link(&mut self, federation_link: Option<String>) {
        self.federation_link = federation_link;
    }
}

/// Credential type metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTypeMetadata {
    /// The credential type identifier
    pub credential_type: String,
    /// Display name for the credential type
    pub display_name: String,
    /// Help text describing the credential type
    pub help_text: Option<String>,
    /// Help text for credential creation
    pub create_help_text: Option<String>,
    /// Category classification of the credential type
    pub category: CredentialTypeCategory,
    /// CSS classes for display icon
    pub display_icon_classes: Option<String>,
    /// Configuration properties for this credential type
    pub properties: Vec<CredentialTypeProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Categories for credential types
pub enum CredentialTypeCategory {
    /// Basic authentication credentials
    Basic,
    /// Two-factor authentication credentials
    TwoFactor,
    /// Passwordless authentication credentials
    Passwordless,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Property definition for credential type configuration
pub struct CredentialTypeProperty {
    /// Property name/identifier
    pub name: String,
    /// Display label for the property
    pub label: String,
    /// Help text describing the property
    pub help_text: Option<String>,
    /// Whether this property is required
    pub required: bool,
    /// Whether this property contains secret data
    pub secret: bool,
    /// Whether this property is read-only
    pub read_only: bool,
    /// Default value for the property
    pub default_value: Option<String>,
}

/// Credential metadata for presentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// The underlying credential model
    pub user_credential_model: Option<CredentialModel>,
    /// Additional metadata information
    pub info: HashMap<String, String>,
}
/// Context for credential type metadata
#[derive(Debug, Clone)]
pub struct CredentialTypeMetadataContext {
    /// Realm identifier
    pub realm_id: String,
    /// User identifier if applicable
    pub user_id: Option<String>,
}

/// Credential provider trait
#[async_trait]
pub trait CredentialProvider: Provider + Send + Sync {
    /// Get the credential type this provider handles
    fn get_type(&self) -> &str;

    /// Create a new credential for a user
    async fn create_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: CredentialModel,
    ) -> Result<CredentialModel>;

    /// Delete a credential
    async fn delete_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool>;

    /// Get credential from model
    fn get_credential_from_model(&self, model: &CredentialModel) -> Option<CredentialModel>;

    /// Get credential for presentation (with additional metadata)
    fn get_credential_for_presentation_from_model(
        &self,
        model: &CredentialModel,
    ) -> Option<CredentialModel> {
        let mut credential = self.get_credential_from_model(model)?;
        // Add federation link if present
        if let Some(federation_link) = &model.federation_link {
            credential.federation_link = Some(federation_link.clone());
        }
        Some(credential)
    }

    /// Get default credential for user
    async fn get_default_credential(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<CredentialModel>>;

    /// Get credential type metadata
    fn get_credential_type_metadata(
        &self,
        context: &CredentialTypeMetadataContext,
    ) -> CredentialTypeMetadata;

    /// Get credential metadata for presentation
    fn get_credential_metadata(
        &self,
        credential: &CredentialModel,
        _type_metadata: &CredentialTypeMetadata,
    ) -> CredentialMetadata {
        CredentialMetadata {
            user_credential_model: Some(credential.clone()),
            info: HashMap::new(),
        }
    }

    /// Check if provider supports credential type
    fn supports_credential_type(&self, credential: &CredentialModel) -> bool {
        self.supports_credential_type_str(&credential.credential_type)
    }

    /// Check if provider supports credential type by string
    fn supports_credential_type_str(&self, credential_type: &str) -> bool {
        self.get_type() == credential_type
    }
}

/// Default credential provider implementation
pub struct DefaultCredentialProvider;

#[async_trait]
impl CredentialProvider for DefaultCredentialProvider {
    fn get_type(&self) -> &str {
        "default"
    }

    async fn create_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _credential: CredentialModel,
    ) -> Result<CredentialModel> {
        Err(Error::validation(
            "Credential creation not implemented".to_string(),
        ))
    }

    async fn delete_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _credential_id: &str,
    ) -> Result<bool> {
        Err(Error::validation(
            "Credential deletion not implemented".to_string(),
        ))
    }

    fn get_credential_from_model(&self, _model: &CredentialModel) -> Option<CredentialModel> {
        None
    }

    async fn get_default_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
    ) -> Result<Option<CredentialModel>> {
        Ok(None)
    }

    fn get_credential_type_metadata(
        &self,
        _context: &CredentialTypeMetadataContext,
    ) -> CredentialTypeMetadata {
        CredentialTypeMetadata {
            credential_type: "default".to_string(),
            display_name: "Default Credential".to_string(),
            help_text: Some("Default credential provider".to_string()),
            create_help_text: None,
            category: CredentialTypeCategory::Basic,
            display_icon_classes: None,
            properties: vec![],
        }
    }
}

impl Provider for DefaultCredentialProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Password credential provider for secure password hashing and verification
pub struct PasswordCredentialProvider;

#[async_trait]
impl CredentialProvider for PasswordCredentialProvider {
    fn get_type(&self) -> &str {
        "password"
    }

    async fn create_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        mut credential: CredentialModel,
    ) -> Result<CredentialModel> {
        // Ensure the credential type is password
        if credential.credential_type != "password" {
            return Err(Error::validation(
                "Invalid credential type for password provider".to_string(),
            ));
        }

        // Hash the password if provided in secret_data
        if let Some(password) = &credential.secret_data {
            let hashed_password = hash_password(password)
                .await
                .map_err(|e| Error::validation(format!("Failed to hash password: {}", e)))?;
            credential.secret_data = Some(hashed_password);
        } else {
            return Err(Error::validation(
                "Password is required for password credential".to_string(),
            ));
        }

        // Set creation timestamp
        credential.created_date = chrono::Utc::now().timestamp_millis();
        credential.user_id = user_id.to_string();
        credential.realm_id = realm_id.to_string();

        Ok(credential)
    }

    async fn delete_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _credential_id: &str,
    ) -> Result<bool> {
        // In a real implementation, this would delete from database
        // For now, return true as placeholder
        Ok(true)
    }

    fn get_credential_from_model(&self, model: &CredentialModel) -> Option<CredentialModel> {
        if model.credential_type == "password" {
            Some(model.clone())
        } else {
            None
        }
    }

    async fn get_default_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
    ) -> Result<Option<CredentialModel>> {
        // In a real implementation, this would fetch from database
        // For now, return None as placeholder
        Ok(None)
    }

    fn get_credential_type_metadata(
        &self,
        _context: &CredentialTypeMetadataContext,
    ) -> CredentialTypeMetadata {
        CredentialTypeMetadata {
            credential_type: "password".to_string(),
            display_name: "Password".to_string(),
            help_text: Some("Enter your password for authentication".to_string()),
            create_help_text: Some(
                "Choose a strong password with at least 8 characters".to_string(),
            ),
            category: CredentialTypeCategory::Basic,
            display_icon_classes: Some("fa fa-key".to_string()),
            properties: vec![CredentialTypeProperty {
                name: "password".to_string(),
                label: "Password".to_string(),
                help_text: Some("Your login password".to_string()),
                required: true,
                secret: true,
                read_only: false,
                default_value: None,
            }],
        }
    }
}

impl PasswordCredentialProvider {
    /// Verify a password against a stored credential
    pub async fn verify_password(
        &self,
        credential: &CredentialModel,
        password: &str,
    ) -> Result<bool> {
        if credential.credential_type != "password" {
            return Ok(false);
        }

        if let Some(stored_hash) = &credential.secret_data {
            verify_password(stored_hash, password)
                .await
                .map_err(|e| Error::validation(format!("Password verification failed: {}", e)))
        } else {
            Ok(false)
        }
    }
}

impl Provider for PasswordCredentialProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Password credential provider factory
pub struct PasswordCredentialProviderFactory;

impl Default for PasswordCredentialProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordCredentialProviderFactory {
    /// Creates a new password credential provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn CredentialProvider> for PasswordCredentialProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn CredentialProvider>, SpiError> {
        Ok(Box::new(PasswordCredentialProvider))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "password"
    }
}

impl CredentialProviderFactory for PasswordCredentialProviderFactory {
    fn create_credential_provider(&self) -> Box<dyn CredentialProvider + Send + Sync> {
        Box::new(PasswordCredentialProvider)
    }
}

/// OTP (One-Time Password) credential provider for TOTP/HOTP
pub struct OTPCredentialProvider;

#[async_trait]
impl CredentialProvider for OTPCredentialProvider {
    fn get_type(&self) -> &str {
        "otp"
    }

    async fn create_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        mut credential: CredentialModel,
    ) -> Result<CredentialModel> {
        // Ensure the credential type is otp
        if credential.credential_type != "otp" {
            return Err(Error::validation(
                "Invalid credential type for OTP provider".to_string(),
            ));
        }

        // For OTP, we store the secret key in credential_data
        // In a real implementation, this would generate a TOTP secret
        if credential.credential_data.is_none() {
            // Generate a random secret key for TOTP
            use rand::Rng;
            let secret: String = (0..32)
                .map(|_| format!("{:02x}", rand::thread_rng().r#gen::<u8>()))
                .collect();
            credential.credential_data = Some(secret);
        }

        // Set creation timestamp
        credential.created_date = chrono::Utc::now().timestamp_millis();
        credential.user_id = user_id.to_string();
        credential.realm_id = realm_id.to_string();

        Ok(credential)
    }

    async fn delete_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _credential_id: &str,
    ) -> Result<bool> {
        // In a real implementation, this would delete from database
        Ok(true)
    }

    fn get_credential_from_model(&self, model: &CredentialModel) -> Option<CredentialModel> {
        if model.credential_type == "otp" {
            Some(model.clone())
        } else {
            None
        }
    }

    async fn get_default_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
    ) -> Result<Option<CredentialModel>> {
        // In a real implementation, this would fetch from database
        Ok(None)
    }

    fn get_credential_type_metadata(
        &self,
        _context: &CredentialTypeMetadataContext,
    ) -> CredentialTypeMetadata {
        CredentialTypeMetadata {
            credential_type: "otp".to_string(),
            display_name: "Authenticator Application".to_string(),
            help_text: Some("Use an authenticator app to generate verification codes".to_string()),
            create_help_text: Some("Scan the QR code with your authenticator app".to_string()),
            category: CredentialTypeCategory::TwoFactor,
            display_icon_classes: Some("fa fa-mobile".to_string()),
            properties: vec![CredentialTypeProperty {
                name: "secret".to_string(),
                label: "Secret Key".to_string(),
                help_text: Some("The secret key for TOTP generation".to_string()),
                required: true,
                secret: true,
                read_only: true,
                default_value: None,
            }],
        }
    }
}

impl OTPCredentialProvider {
    /// Verify an OTP code against a stored credential
    pub async fn verify_otp(&self, credential: &CredentialModel, code: &str) -> Result<bool> {
        if credential.credential_type != "otp" {
            return Ok(false);
        }

        if let Some(_secret) = &credential.credential_data {
            // In a real implementation, this would validate TOTP/HOTP codes
            // For now, just check if the code is 6 digits
            if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
                // Simple validation - in production, use proper TOTP library
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Generate a TOTP URI for QR code display
    pub fn generate_totp_uri(
        &self,
        credential: &CredentialModel,
        issuer: &str,
        account_name: &str,
    ) -> Option<String> {
        if credential.credential_type != "otp" {
            return None;
        }

        credential.credential_data.as_ref().map(|secret| {
            format!(
                "otpauth://totp/{}:{}?secret={}&issuer={}",
                issuer, account_name, secret, issuer
            )
        })
    }
}

impl Provider for OTPCredentialProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// OTP credential provider factory
pub struct OTPCredentialProviderFactory;

impl Default for OTPCredentialProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl OTPCredentialProviderFactory {
    /// Creates a new OTP credential provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn CredentialProvider> for OTPCredentialProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn CredentialProvider>, SpiError> {
        Ok(Box::new(OTPCredentialProvider))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "otp"
    }
}

impl CredentialProviderFactory for OTPCredentialProviderFactory {
    fn create_credential_provider(&self) -> Box<dyn CredentialProvider + Send + Sync> {
        Box::new(OTPCredentialProvider)
    }
}

/// Credential provider factory
#[async_trait]
pub trait CredentialProviderFactory: ProviderFactory<dyn CredentialProvider> {
    /// Create a credential provider instance
    fn create_credential_provider(&self) -> Box<dyn CredentialProvider + Send + Sync>;
}

/// Default credential provider factory
pub struct DefaultCredentialProviderFactory;

impl Default for DefaultCredentialProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProviderFactory {
    /// Creates a new default credential provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn CredentialProvider> for DefaultCredentialProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn CredentialProvider>, SpiError> {
        Ok(Box::new(DefaultCredentialProvider))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-credential"
    }
}

impl CredentialProviderFactory for DefaultCredentialProviderFactory {
    fn create_credential_provider(&self) -> Box<dyn CredentialProvider + Send + Sync> {
        Box::new(DefaultCredentialProvider)
    }
}

/// Credential SPI implementation
pub struct CredentialSpi;

impl Spi for CredentialSpi {
    fn get_name(&self) -> &'static str {
        "credential"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "CredentialProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "CredentialProviderFactory"
    }
}
