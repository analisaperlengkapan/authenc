//! Theme Service Provider Interface
//!
//! Provides theming capabilities for login, account, and admin consoles.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;

/// Theme SPI implementation
pub struct ThemeSpi;

impl Spi for ThemeSpi {
    fn get_name(&self) -> &'static str {
        "theme"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "org.keycloak.theme.ThemeProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "org.keycloak.theme.ThemeProviderFactory"
    }
}

/// Theme types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeType {
    Login,
    Account,
    Admin,
    Email,
    Welcome,
    Common,
}

impl ThemeType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ThemeType::Login => "login",
            ThemeType::Account => "account",
            ThemeType::Admin => "admin",
            ThemeType::Email => "email",
            ThemeType::Welcome => "welcome",
            ThemeType::Common => "common",
        }
    }
}

/// Theme provider interface
#[async_trait]
pub trait ThemeProvider: Provider {
    /// Get the theme name
    fn get_theme_name(&self) -> &str;

    /// Get theme resources for a specific type and locale
    async fn get_theme_resources(
        &self,
        theme_type: ThemeType,
        locale: Option<&str>,
    ) -> Result<Vec<ThemeResource>, ThemeError>;

    /// Get a specific theme resource
    async fn get_theme_resource(
        &self,
        theme_type: ThemeType,
        path: &str,
        locale: Option<&str>,
    ) -> Result<Option<ThemeResource>, ThemeError>;

    /// Check if theme has a specific resource
    async fn has_theme_resource(
        &self,
        theme_type: ThemeType,
        path: &str,
        locale: Option<&str>,
    ) -> Result<bool, ThemeError>;

    /// Get available locales for a theme type
    async fn get_theme_locales(&self, theme_type: ThemeType) -> Result<Vec<String>, ThemeError>;
}

/// Theme resource representation
#[derive(Debug, Clone)]
pub struct ThemeResource {
    /// Resource path
    pub path: String,
    /// Resource content
    pub content: Vec<u8>,
    /// Content type (MIME type)
    pub content_type: String,
    /// Last modified timestamp
    pub last_modified: Option<i64>,
}

/// Theme provider factory
#[async_trait]
pub trait ThemeProviderFactory: ProviderFactory<dyn ThemeProvider> {
    /// Get the theme name
    fn get_theme_name(&self) -> &str;

    /// Get supported theme types
    fn get_theme_types(&self) -> Vec<ThemeType>;

    /// Check if theme is external (loaded from external source)
    fn is_external(&self) -> bool {
        false
    }
}

/// Theme-related errors
#[derive(Debug, thiserror::Error)]
pub enum ThemeError {
    #[error("Theme not found: {0}")]
    ThemeNotFound(String),

    #[error("Theme resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Theme loading error: {0}")]
    LoadingError(String),

    #[error("Invalid theme configuration: {0}")]
    ConfigurationError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Default theme provider implementation
pub struct DefaultThemeProvider {
    name: String,
    resources: HashMap<String, ThemeResource>,
}

impl DefaultThemeProvider {
    /// Create a new default theme provider
    pub fn new(name: String) -> Self {
        Self {
            name,
            resources: HashMap::new(),
        }
    }

    /// Add a theme resource
    pub fn add_resource(&mut self, path: String, resource: ThemeResource) {
        self.resources.insert(path, resource);
    }
}

#[async_trait]
impl ThemeProvider for DefaultThemeProvider {
    fn get_theme_name(&self) -> &str {
        &self.name
    }

    async fn get_theme_resources(
        &self,
        theme_type: ThemeType,
        _locale: Option<&str>,
    ) -> Result<Vec<ThemeResource>, ThemeError> {
        // Filter resources by theme type prefix
        let prefix = format!("{}/", theme_type.as_str());
        let resources = self
            .resources
            .iter()
            .filter(|(path, _)| path.starts_with(&prefix))
            .map(|(_, resource)| resource.clone())
            .collect();

        Ok(resources)
    }

    async fn get_theme_resource(
        &self,
        theme_type: ThemeType,
        path: &str,
        _locale: Option<&str>,
    ) -> Result<Option<ThemeResource>, ThemeError> {
        let full_path = format!("{}/{}", theme_type.as_str(), path);
        Ok(self.resources.get(&full_path).cloned())
    }

    async fn has_theme_resource(
        &self,
        theme_type: ThemeType,
        path: &str,
        _locale: Option<&str>,
    ) -> Result<bool, ThemeError> {
        let full_path = format!("{}/{}", theme_type.as_str(), path);
        Ok(self.resources.contains_key(&full_path))
    }

    async fn get_theme_locales(&self, _theme_type: ThemeType) -> Result<Vec<String>, ThemeError> {
        // Default implementation returns English only
        Ok(vec!["en".to_string()])
    }
}

impl Provider for DefaultThemeProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Default theme provider factory
pub struct DefaultThemeProviderFactory {
    theme_name: String,
}

impl DefaultThemeProviderFactory {
    /// Create a new default theme provider factory
    pub fn new(theme_name: String) -> Self {
        Self { theme_name }
    }
}

#[async_trait]
impl ProviderFactory<dyn ThemeProvider> for DefaultThemeProviderFactory {
    async fn create(
        &self,
        _config: &ProviderConfig,
    ) -> Result<Box<dyn ThemeProvider>, SpiError> {
        let mut provider = DefaultThemeProvider::new(self.theme_name.clone());

        // Add some basic theme resources
        provider.add_resource(
            "login/login.ftl".to_string(),
            ThemeResource {
                path: "login/login.ftl".to_string(),
                content: include_bytes!("../../templates/login.ftl").to_vec(),
                content_type: "text/html".to_string(),
                last_modified: None,
            },
        );

        provider.add_resource(
            "common/keycloak.ftl".to_string(),
            ThemeResource {
                path: "common/keycloak.ftl".to_string(),
                content: include_bytes!("../../templates/keycloak.ftl").to_vec(),
                content_type: "text/html".to_string(),
                last_modified: None,
            },
        );

        Ok(Box::new(provider))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }

    fn get_name(&self) -> &'static str {
        self.get_id()
    }
}

impl ThemeProviderFactory for DefaultThemeProviderFactory {
    fn get_theme_name(&self) -> &str {
        &self.theme_name
    }

    fn get_theme_types(&self) -> Vec<ThemeType> {
        vec![
            ThemeType::Login,
            ThemeType::Account,
            ThemeType::Admin,
            ThemeType::Email,
            ThemeType::Common,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_theme_provider() {
        let mut provider = DefaultThemeProvider::new("test-theme".to_string());

        provider.add_resource(
            "login/test.ftl".to_string(),
            ThemeResource {
                path: "login/test.ftl".to_string(),
                content: b"<html>Test</html>".to_vec(),
                content_type: "text/html".to_string(),
                last_modified: None,
            },
        );

        assert_eq!(provider.get_theme_name(), "test-theme");

        let resources = provider
            .get_theme_resources(ThemeType::Login, None)
            .await
            .unwrap();
        assert_eq!(resources.len(), 1);

        let resource = provider
            .get_theme_resource(ThemeType::Login, "test.ftl", None)
            .await
            .unwrap();
        assert!(resource.is_some());

        let has_resource = provider
            .has_theme_resource(ThemeType::Login, "test.ftl", None)
            .await
            .unwrap();
        assert!(has_resource);
    }

    #[tokio::test]
    async fn test_default_theme_factory() {
        let factory = DefaultThemeProviderFactory::new("test-theme".to_string());

        assert_eq!(factory.get_id(), "default");
        assert_eq!(factory.get_theme_name(), "test-theme");

        let theme_types = factory.get_theme_types();
        assert!(theme_types.contains(&ThemeType::Login));
        assert!(theme_types.contains(&ThemeType::Account));
    }
}
