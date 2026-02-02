//! Admin Console Service Provider Interface
//!
//! Provides comprehensive admin console functionality for enterprise identity management.

use crate::spi::{Provider, ProviderConfig, Spi, SpiError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

/// Admin Console SPI implementation
pub struct AdminConsoleSpi;

impl Spi for AdminConsoleSpi {
    fn get_name(&self) -> &'static str {
        "admin-console"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.adminconsole.AdminConsoleProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.adminconsole.AdminConsoleProviderFactory"
    }
}

/// Admin console provider trait
#[async_trait]
pub trait AdminConsoleProvider: Provider {
    /// Get the admin console base URL
    fn get_base_url(&self) -> &str;

    /// Get admin console configuration
    fn get_config(&self) -> &AdminConsoleConfig;

    /// Check if admin console is enabled
    fn is_enabled(&self) -> bool;

    /// Get supported admin console features
    fn get_supported_features(&self) -> Vec<AdminConsoleFeature>;

    /// Get admin console theme
    fn get_theme(&self) -> &str {
        "authenc"
    }

    /// Get admin console locale
    fn get_locale(&self) -> &str {
        "en"
    }
}

/// Admin console configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConsoleConfig {
    /// Whether admin console is enabled
    pub enabled: bool,
    /// Base URL for admin console
    pub base_url: String,
    /// Admin console theme
    pub theme: String,
    /// Default locale
    pub locale: String,
    /// Supported features
    pub features: Vec<String>,
    /// Custom configuration properties
    pub properties: HashMap<String, String>,
}

impl Default for AdminConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: "/admin".to_string(),
            theme: "authenc".to_string(),
            locale: "en".to_string(),
            features: vec![
                "users".to_string(),
                "groups".to_string(),
                "roles".to_string(),
                "clients".to_string(),
                "identity-providers".to_string(),
                "realm-settings".to_string(),
                "events".to_string(),
            ],
            properties: HashMap::new(),
        }
    }
}

/// Admin console features
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminConsoleFeature {
    /// Users management feature
    Users,
    /// Groups management feature
    Groups,
    /// Roles management feature
    Roles,
    /// Clients management feature
    Clients,
    /// Identity providers management feature
    IdentityProviders,
    /// Realm settings management feature
    RealmSettings,
    /// Events management feature
    Events,
    /// Sessions management feature
    Sessions,
    /// Authentication management feature
    Authentication,
    /// Authorization management feature
    Authorization,
    /// Account management feature
    Account,
    /// Extensions management feature
    Extensions,
}

/// Default admin console provider implementation
pub struct DefaultAdminConsoleProvider {
    config: AdminConsoleConfig,
}

impl DefaultAdminConsoleProvider {
    /// Create a new default admin console provider
    pub fn new(config: AdminConsoleConfig) -> Self {
        Self { config }
    }
}

impl Provider for DefaultAdminConsoleProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl AdminConsoleProvider for DefaultAdminConsoleProvider {
    fn get_base_url(&self) -> &str {
        &self.config.base_url
    }

    fn get_config(&self) -> &AdminConsoleConfig {
        &self.config
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn get_supported_features(&self) -> Vec<AdminConsoleFeature> {
        self.config
            .features
            .iter()
            .filter_map(|f| match f.as_str() {
                "users" => Some(AdminConsoleFeature::Users),
                "groups" => Some(AdminConsoleFeature::Groups),
                "roles" => Some(AdminConsoleFeature::Roles),
                "clients" => Some(AdminConsoleFeature::Clients),
                "identity-providers" => Some(AdminConsoleFeature::IdentityProviders),
                "realm-settings" => Some(AdminConsoleFeature::RealmSettings),
                "events" => Some(AdminConsoleFeature::Events),
                "sessions" => Some(AdminConsoleFeature::Sessions),
                "authentication" => Some(AdminConsoleFeature::Authentication),
                "authorization" => Some(AdminConsoleFeature::Authorization),
                "account" => Some(AdminConsoleFeature::Account),
                "extensions" => Some(AdminConsoleFeature::Extensions),
                _ => None,
            })
            .collect()
    }

    fn get_theme(&self) -> &str {
        &self.config.theme
    }

    fn get_locale(&self) -> &str {
        &self.config.locale
    }
}

/// Admin console provider factory
pub struct DefaultAdminConsoleProviderFactory;

impl Default for DefaultAdminConsoleProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultAdminConsoleProviderFactory {
    /// Create a new default admin console provider factory
    pub fn new() -> Self {
        Self
    }
}

impl crate::spi::ProviderFactory<dyn AdminConsoleProvider> for DefaultAdminConsoleProviderFactory {
    fn create(&self, config: &ProviderConfig) -> Result<Box<dyn AdminConsoleProvider>, SpiError> {
        let console_config = if let Some(global_config) = &config.global_config {
            // Try to extract admin console config from global config
            if let Some(_app_config) = global_config.downcast_ref::<crate::config::AppConfig>() {
                AdminConsoleConfig {
                    enabled: true,
                    base_url: "/admin".to_string(),
                    theme: "authenc".to_string(),
                    locale: "en".to_string(), // Default locale
                    features: vec![
                        "users".to_string(),
                        "groups".to_string(),
                        "roles".to_string(),
                        "clients".to_string(),
                        "identity-providers".to_string(),
                        "realm-settings".to_string(),
                        "events".to_string(),
                    ],
                    properties: config.properties.clone(),
                }
            } else {
                AdminConsoleConfig::default()
            }
        } else {
            AdminConsoleConfig::default()
        };

        Ok(Box::new(DefaultAdminConsoleProvider::new(console_config)))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spi::ProviderFactory;

    #[test]
    fn test_default_admin_console_provider() {
        let config = AdminConsoleConfig::default();
        let provider = DefaultAdminConsoleProvider::new(config);

        assert_eq!(provider.get_base_url(), "/admin");
        assert!(provider.is_enabled());
        assert_eq!(provider.get_theme(), "authenc");
        assert_eq!(provider.get_locale(), "en");

        let features = provider.get_supported_features();
        assert!(features.contains(&AdminConsoleFeature::Users));
        assert!(features.contains(&AdminConsoleFeature::Groups));
        assert!(features.contains(&AdminConsoleFeature::Roles));
    }

    #[test]
    fn test_admin_console_config() {
        let config = AdminConsoleConfig::default();
        assert!(config.enabled);
        assert_eq!(config.base_url, "/admin");
        assert_eq!(config.theme, "authenc");
        assert_eq!(config.locale, "en");
        assert!(config.features.contains(&"users".to_string()));
    }

    #[tokio::test]
    async fn test_default_admin_console_factory() {
        let factory = DefaultAdminConsoleProviderFactory::new();
        let config = ProviderConfig::new();

        let provider = factory.create(&config).unwrap();
        assert_eq!(provider.get_base_url(), "/admin");
        assert!(provider.is_enabled());
    }
}
