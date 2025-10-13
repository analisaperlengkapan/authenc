//! Service Provider Interface (SPI) architecture for Authenc
//!
//! This module provides a pluggable component framework that enables pluggable components
//! and enterprise extensibility, similar to Keycloak's SPI system.

// Core SPI traits and interfaces
/// Admin console SPI for managing administrative interfaces
pub mod admin_console;
/// Authentication SPI for handling user authentication flows
pub mod authenticator;
/// Component SPI for managing pluggable components
pub mod component;
/// Credential SPI for managing user credentials
pub mod credential;
/// Events SPI for handling audit and event logging
pub mod events;
/// Hostname SPI for managing hostname resolution
pub mod hostname;
/// Keys SPI for cryptographic key management
pub mod keys;
/// LDAP federation SPI for external directory integration
pub mod ldap_federation;
/// Locale SPI for internationalization support
pub mod locale;
/// Migration SPI for database schema migrations
pub mod migration;
/// Organization SPI for multi-tenant organization management
pub mod organization;
/// Policy SPI for password and security policies
pub mod policy;
/// Protocol mappers SPI for token claim mapping
pub mod protocol_mappers;
/// Required actions SPI for user registration flows
pub mod required_actions;
/// Rich authorization SPI for fine-grained access control
pub mod rich_authorization;
/// Sessions SPI for session management
pub mod sessions;
/// Social login SPI for OAuth/OIDC social providers
pub mod social;
/// Storage SPI for data persistence
pub mod storage;
/// Theme SPI for UI theming
pub mod theme;
/// User profile SPI for user attribute management
pub mod userprofile;
/// Validation SPI for input validation
pub mod validation;

// Re-export commonly used SPI items
pub use admin_console::{
    AdminConsoleConfig, AdminConsoleFeature, AdminConsoleProvider, AdminConsoleSpi,
    DefaultAdminConsoleProviderFactory,
};
pub use authenticator::{
    AuthenticationContext, AuthenticationFlowType, AuthenticationResult, Authenticator,
    AuthenticatorConfig, AuthenticatorProvider, AuthenticatorSpi, AuthenticatorType,
    DefaultAuthenticatorProviderFactory,
};
pub use component::{
    ComponentFactory, ComponentFactoryProvider, ComponentModel, ComponentSpi,
    ComponentValidationException, SubComponentFactory,
};
pub use credential::{
    CredentialMetadata, CredentialModel, CredentialProvider, CredentialProviderFactory,
    CredentialSpi, CredentialTypeMetadata,
};
pub use events::{AdminEvent, Event, EventProvider, EventProviderFactory, EventType, EventsSpi};
pub use hostname::{
    DefaultHostnameProviderFactory, HostnameConfig, HostnameProvider, HostnameResolution,
    HostnameSpi,
};
pub use keys::{
    KeyManager, KeyMetadata, KeyMetadataTrait, KeyProvider, KeyStatus, KeysSpi, RsaKeyMetadata,
    SecretKeyMetadata,
};
pub use ldap_federation::{
    LdapFederationConfig, LdapFederationProvider, LdapFederationProviderFactory, LdapFederationSpi,
};
pub use locale::{LocaleProvider, LocaleProviderFactory, LocaleSpi};
pub use migration::{
    DefaultMigrationProviderFactory, MigrationModel, MigrationProvider, MigrationSpi,
    MigrationStatus, MigrationType,
};
pub use organization::{
    DefaultOrganizationProviderFactory, OrganizationMemberModel, OrganizationModel,
    OrganizationProvider, OrganizationRole, OrganizationSpi,
};
pub use policy::{
    PasswordPolicyConfigException, PasswordPolicyManager, PasswordPolicyProvider, PolicyError,
    PolicySpi,
};
pub use protocol_mappers::{
    DefaultProtocolMapperProviderFactory, ProtocolMapper, ProtocolMapperConfig,
    ProtocolMapperContext, ProtocolMapperProvider, ProtocolMapperSpi, ProtocolMapperType,
};
pub use required_actions::{
    DefaultRequiredActionProviderFactory, RequiredActionConfigProperty, RequiredActionContext,
    RequiredActionPropertyType, RequiredActionProvider, RequiredActionProviderFactory,
    RequiredActionResult, RequiredActionSpi,
};
pub use rich_authorization::{
    AuthorizationAction, AuthorizationAdvice, AuthorizationDecision, AuthorizationObligation,
    AuthorizationResource, AuthorizationSubject, DefaultRichAuthorizationProviderFactory,
    RichAuthorizationProvider, RichAuthorizationRequest, RichAuthorizationSpi,
};
pub use sessions::{
    DefaultSessionProviderFactory, SessionProvider, SessionProviderFactory, SessionProviderType,
    SessionQueryContext, SessionSpi,
};
pub use social::{
    OAuth2Token, SocialProvider, SocialProviderConfig, SocialProviderFactory, SocialProviderSpi,
    SocialProviderType, SocialUserProfile,
};
pub use storage::{
    DefaultStorageProviderFactory, StorageProvider, StorageProviderFactory, StorageProviderType,
    StorageQueryContext, StorageSpi,
};
pub use theme::{ThemeProvider, ThemeProviderFactory, ThemeSpi, ThemeType};
pub use userprofile::{
    UserProfileContext, UserProfileProvider, UserProfileProviderFactory, UserProfileSpi,
};
pub use validation::{
    ValidationContext, ValidationResult, ValidationSpi, ValidatorProvider, ValidatorProviderFactory,
};

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Core SPI trait that all service provider interfaces must implement
#[async_trait]
pub trait Spi: Send + Sync {
    /// Get the name of this SPI
    fn get_name(&self) -> &'static str;

    /// Check if this SPI is internal (not user-configurable)
    fn is_internal(&self) -> bool {
        false
    }

    /// Get the provider class type
    fn get_provider_class(&self) -> &'static str;

    /// Get the provider factory class type
    fn get_provider_factory_class(&self) -> &'static str;
}

/// Core provider trait that all providers must implement
#[async_trait]
pub trait Provider: Send + Sync {
    /// Close the provider and release resources
    fn close(&mut self) {}

    /// Get the provider as Any for downcasting
    fn as_any(&self) -> &dyn Any;

    /// Get the provider as Any mut for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Provider factory trait for creating provider instances
pub trait ProviderFactory<T: Provider + ?Sized>: Send + Sync {
    /// Create a new provider instance
    fn create(&self, config: &ProviderConfig) -> Result<Box<T>, SpiError>;

    /// Initialize the factory
    fn init(&mut self, config: &ProviderConfig) -> Result<(), SpiError> {
        Ok(())
    }

    /// Close the factory and release resources
    fn close(&mut self) {}

    /// Get the factory ID
    fn get_id(&self) -> &'static str;

    /// Get the provider name
    fn get_name(&self) -> &'static str {
        self.get_id()
    }

    /// Get the provider priority (higher = preferred)
    fn get_priority(&self) -> i32 {
        0
    }

    /// Check if this provider is internal
    fn is_internal(&self) -> bool {
        false
    }

    /// Get supported configuration properties
    fn get_config_properties(&self) -> Vec<ConfigProperty> {
        Vec::new()
    }
}

/// Configuration for providers
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Provider-specific configuration
    pub properties: HashMap<String, String>,
    /// Global configuration reference
    pub global_config: Option<Arc<dyn Any + Send + Sync>>,
}

impl ProviderConfig {
    /// Create a new provider config
    pub fn new() -> Self {
        Self {
            properties: HashMap::new(),
            global_config: None,
        }
    }

    /// Set a configuration property
    pub fn set_property(&mut self, key: String, value: String) {
        self.properties.insert(key, value);
    }

    /// Get a configuration property
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }

    /// Set global configuration
    pub fn set_global_config<T: Send + Sync + 'static>(mut self, config: T) -> Self {
        self.global_config = Some(Arc::new(config));
        self
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration property metadata
#[derive(Debug, Clone)]
pub struct ConfigProperty {
    /// Property name
    pub name: String,
    /// Property label
    pub label: String,
    /// Property type
    pub property_type: ConfigPropertyType,
    /// Default value
    pub default_value: Option<String>,
    /// Help text
    pub help_text: Option<String>,
    /// Whether the property is required
    pub required: bool,
    /// Whether the property is secret (should be masked)
    pub secret: bool,
}

/// Configuration property types
#[derive(Debug, Clone)]
pub enum ConfigPropertyType {
    /// String configuration property
    String,
    /// Integer configuration property
    Integer,
    /// Boolean configuration property
    Boolean,
    /// List configuration property
    List,
    /// Password configuration property (masked)
    Password,
    /// File configuration property
    File,
    /// Multiline string configuration property
    MultilineString,
}

/// SPI-related errors
#[derive(Debug, thiserror::Error)]
pub enum SpiError {
    /// Provider implementation not found
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    /// Provider initialization failed
    #[error("Provider initialization failed: {0}")]
    InitializationFailed(String),

    /// Configuration error occurred
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Provider factory error occurred
    #[error("Provider factory error: {0}")]
    FactoryError(String),

    /// SPI not registered in the system
    #[error("SPI not registered: {0}")]
    SpiNotRegistered(String),
}

/// Provider registry for managing SPI implementations
pub struct ProviderRegistry {
    providers: HashMap<String, Vec<Box<dyn Any + Send + Sync>>>,
    factories: HashMap<String, Vec<Box<dyn Any + Send + Sync>>>,
}

impl ProviderRegistry {
    /// Create a new provider registry
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            factories: HashMap::new(),
        }
    }

    /// Register a provider factory
    pub fn register_factory<T: ProviderFactory<U> + 'static, U: Provider + ?Sized + 'static>(
        &mut self,
        spi_name: &str,
        factory: T,
    ) {
        self.factories
            .entry(spi_name.to_string())
            .or_default()
            .push(Box::new(factory));
    }

    /// Get all factories for an SPI
    pub fn get_factories<T: ProviderFactory<U> + 'static, U: Provider + ?Sized + 'static>(
        &self,
        spi_name: &str,
    ) -> Result<Vec<&T>, SpiError> {
        self.factories
            .get(spi_name)
            .ok_or_else(|| SpiError::SpiNotRegistered(spi_name.to_string()))?
            .iter()
            .map(|f| {
                f.downcast_ref::<T>()
                    .ok_or_else(|| SpiError::FactoryError("Type mismatch".to_string()))
            })
            .collect()
    }

    /// Register a provider instance
    pub fn register_provider<T: Provider + 'static>(&mut self, spi_name: &str, provider: T) {
        self.providers
            .entry(spi_name.to_string())
            .or_default()
            .push(Box::new(provider));
    }

    /// Get all providers for an SPI
    pub fn get_providers<T: Provider + 'static>(
        &self,
        spi_name: &str,
    ) -> Result<Vec<&T>, SpiError> {
        self.providers
            .get(spi_name)
            .ok_or_else(|| SpiError::SpiNotRegistered(spi_name.to_string()))?
            .iter()
            .map(|p| {
                p.downcast_ref::<T>()
                    .ok_or_else(|| SpiError::ProviderNotFound("Type mismatch".to_string()))
            })
            .collect()
    }

    /// Get the first provider for an SPI (by priority)
    pub fn get_provider<T: Provider + 'static>(&self, spi_name: &str) -> Result<&T, SpiError> {
        let providers = self.get_providers::<T>(spi_name)?;
        providers
            .first()
            .copied()
            .ok_or_else(|| SpiError::ProviderNotFound(spi_name.to_string()))
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// SPI manager for coordinating all SPIs
pub struct SpiManager {
    registry: ProviderRegistry,
    spis: HashMap<String, Box<dyn Spi>>,
}

impl SpiManager {
    /// Create a new SPI manager
    pub fn new() -> Self {
        Self {
            registry: ProviderRegistry::new(),
            spis: HashMap::new(),
        }
    }

    /// Register an SPI
    pub fn register_spi(&mut self, spi: Box<dyn Spi>) {
        let name = spi.get_name().to_string();
        self.spis.insert(name, spi);
    }

    /// Get an SPI by name
    pub fn get_spi(&self, name: &str) -> Option<&dyn Spi> {
        self.spis.get(name).map(|s| s.as_ref())
    }

    /// Get the provider registry
    pub fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }

    /// Get the provider registry mutably
    pub fn registry_mut(&mut self) -> &mut ProviderRegistry {
        &mut self.registry
    }

    /// Initialize all registered SPIs
    pub async fn init(&mut self, config: &ProviderConfig) -> Result<(), SpiError> {
        for spi in self.spis.values_mut() {
            // SPI initialization logic would go here
            // For now, this is a placeholder
        }
        Ok(())
    }

    /// Close all providers and release resources
    pub async fn close(&mut self) -> Result<(), SpiError> {
        // Close all providers
        Ok(())
    }
}

impl Default for SpiManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock provider for testing
    struct MockProvider;

    #[async_trait]
    impl Provider for MockProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    // Mock factory for testing
    struct MockFactory;

    #[async_trait]
    impl ProviderFactory<MockProvider> for MockFactory {
        fn create(&self, _config: &ProviderConfig) -> Result<Box<MockProvider>, SpiError> {
            Ok(Box::new(MockProvider))
        }

        fn get_id(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_provider_registry() {
        let mut registry = ProviderRegistry::new();
        let factory = MockFactory;

        registry.register_factory("test", factory);

        let factories = registry
            .get_factories::<MockFactory, MockProvider>("test")
            .unwrap();
        assert_eq!(factories.len(), 1);
        assert_eq!(factories[0].get_id(), "mock");
    }

    #[tokio::test]
    async fn test_spi_manager() {
        let mut manager = SpiManager::new();

        // Test registry access
        let registry = manager.registry();
        assert!(
            registry
                .get_factories::<MockFactory, MockProvider>("nonexistent")
                .is_err()
        );
    }
}
