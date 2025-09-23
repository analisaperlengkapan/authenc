//! Service Provider Interface (SPI) architecture for Authenc
//!
//! This module provides the core SPI framework that enables pluggable components
//! and enterprise extensibility, similar to Keycloak's SPI system.

// Core SPI traits and interfaces
pub mod admin_console;
pub mod authenticator;
pub mod credential;
pub mod events;
pub mod ldap_federation;
pub mod locale;
pub mod protocol_mappers;
pub mod required_actions;
pub mod sessions;
pub mod social;
pub mod storage;
pub mod theme;
pub mod userprofile;
pub mod validation;

// Re-export commonly used SPI items
pub use admin_console::{AdminConsoleProvider, DefaultAdminConsoleProviderFactory, AdminConsoleSpi, AdminConsoleConfig, AdminConsoleFeature};
pub use authenticator::{Authenticator, AuthenticatorProvider, AuthenticatorSpi, AuthenticatorConfig, AuthenticatorType, AuthenticationContext, AuthenticationResult, AuthenticationFlowType, DefaultAuthenticatorProviderFactory};
pub use credential::{CredentialProvider, CredentialProviderFactory, CredentialSpi, CredentialModel, CredentialTypeMetadata, CredentialMetadata};
pub use events::{EventProvider, EventProviderFactory, EventsSpi, EventType, Event, AdminEvent};
pub use ldap_federation::{LdapFederationProvider, LdapFederationProviderFactory, LdapFederationSpi, LdapFederationConfig};
pub use locale::{LocaleProvider, LocaleProviderFactory, LocaleSpi};
pub use protocol_mappers::{ProtocolMapper, ProtocolMapperProvider, ProtocolMapperSpi, ProtocolMapperConfig, ProtocolMapperType, ProtocolMapperContext, DefaultProtocolMapperProviderFactory};
pub use required_actions::{RequiredActionProvider, RequiredActionProviderFactory, RequiredActionSpi, RequiredActionContext, RequiredActionResult, RequiredActionConfigProperty, RequiredActionPropertyType, DefaultRequiredActionProviderFactory};
pub use sessions::{SessionProvider, SessionProviderFactory, SessionSpi, SessionProviderType, SessionQueryContext, DefaultSessionProviderFactory};
pub use social::{SocialProvider, SocialProviderFactory, SocialProviderSpi, SocialProviderConfig, SocialProviderType, SocialUserProfile, OAuth2Token};
pub use storage::{StorageProvider, StorageProviderFactory, StorageSpi, StorageProviderType, StorageQueryContext, DefaultStorageProviderFactory};
pub use theme::{ThemeProvider, ThemeProviderFactory, ThemeSpi, ThemeType};
pub use userprofile::{UserProfileProvider, UserProfileProviderFactory, UserProfileSpi, UserProfileContext};
pub use validation::{ValidatorProvider, ValidatorProviderFactory, ValidationSpi, ValidationContext, ValidationResult};

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
    async fn close(&mut self) {}

    /// Get the provider as Any for downcasting
    fn as_any(&self) -> &dyn Any;

    /// Get the provider as Any mut for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Provider factory trait for creating provider instances
#[async_trait]
pub trait ProviderFactory<T: Provider + ?Sized>: Send + Sync {
    /// Create a new provider instance
    async fn create(&self, config: &ProviderConfig) -> Result<Box<T>, SpiError>;

    /// Initialize the factory
    async fn init(&mut self, config: &ProviderConfig) -> Result<(), SpiError> {
        Ok(())
    }

    /// Close the factory and release resources
    async fn close(&mut self) {}

    /// Get the provider ID
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
    String,
    Integer,
    Boolean,
    List,
    Password,
    File,
    MultilineString,
}

/// SPI-related errors
#[derive(Debug, thiserror::Error)]
pub enum SpiError {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Provider initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Provider factory error: {0}")]
    FactoryError(String),

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
            .or_insert_with(Vec::new)
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
    pub fn register_provider<T: Provider + 'static>(
        &mut self,
        spi_name: &str,
        provider: T,
    ) {
        self.providers
            .entry(spi_name.to_string())
            .or_insert_with(Vec::new)
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
    pub fn get_provider<T: Provider + 'static>(
        &self,
        spi_name: &str,
    ) -> Result<&T, SpiError> {
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
        async fn create(&self, _config: &ProviderConfig) -> Result<Box<MockProvider>, SpiError> {
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

        let factories = registry.get_factories::<MockFactory, MockProvider>("test").unwrap();
        assert_eq!(factories.len(), 1);
        assert_eq!(factories[0].get_id(), "mock");
    }

    #[tokio::test]
    async fn test_spi_manager() {
        let mut manager = SpiManager::new();

        // Test registry access
        let registry = manager.registry();
        assert!(registry.get_factories::<MockFactory, MockProvider>("nonexistent").is_err());
    }
}
