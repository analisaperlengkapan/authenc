use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

use authenc_core::error::Result;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Hostname SPI for dynamic URL management and hostname resolution
/// This SPI enables flexible hostname configuration for multi-tenant deployments
pub struct HostnameSpi;

impl Default for HostnameSpi {
    fn default() -> Self {
        Self::new()
    }
}

impl HostnameSpi {
    /// Creates a new hostname SPI instance
    pub fn new() -> Self {
        Self
    }
}

impl Spi for HostnameSpi {
    fn get_name(&self) -> &'static str {
        "hostname"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.protocol.hostname.HostnameProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.protocol.hostname.HostnameProviderFactory"
    }
}

/// Hostname configuration for dynamic URL management
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostnameConfig {
    /// The hostname to use for URLs
    pub hostname: Option<String>,
    /// Whether to use the request hostname
    pub use_request_hostname: bool,
    /// The frontend URL to use
    pub frontend_url: Option<String>,
    /// Whether hostname is required
    pub hostname_required: bool,
    /// The admin URL to use
    pub admin_url: Option<String>,
}

/// Represents a hostname resolution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostnameResolution {
    /// The resolved hostname
    pub hostname: String,
    /// The resolved frontend URL
    pub frontend_url: Option<String>,
    /// The resolved admin URL
    pub admin_url: Option<String>,
    /// Whether this is a fixed hostname
    pub fixed: bool,
}

/// Hostname provider trait for dynamic hostname resolution
#[async_trait]
pub trait HostnameProvider: Send + Sync {
    /// Get the hostname for the given request context
    async fn get_hostname(&self, request_uri: &str) -> Result<Option<String>>;

    /// Get the frontend URL for the given request context
    async fn get_frontend_url(&self, request_uri: &str) -> Result<Option<String>>;

    /// Get the admin URL for the given request context
    async fn get_admin_url(&self, request_uri: &str) -> Result<Option<String>>;

    /// Resolve hostname configuration for the given request
    async fn resolve_hostname(&self, request_uri: &str) -> Result<HostnameResolution>;

    /// Check if hostname is required
    async fn is_hostname_required(&self) -> Result<bool>;
}

/// Default hostname provider implementation
pub struct DefaultHostnameProvider {
    config: HostnameConfig,
}

impl Default for DefaultHostnameProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultHostnameProvider {
    /// Creates a new default hostname provider with default configuration
    pub fn new() -> Self {
        Self {
            config: HostnameConfig::default(),
        }
    }

    /// Creates a new default hostname provider with custom configuration
    pub fn with_config(config: HostnameConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl HostnameProvider for DefaultHostnameProvider {
    async fn get_hostname(&self, _request_uri: &str) -> Result<Option<String>> {
        // Default implementation returns configured hostname or None
        Ok(self.config.hostname.clone())
    }

    async fn get_frontend_url(&self, _request_uri: &str) -> Result<Option<String>> {
        // Default implementation returns configured frontend URL or None
        Ok(self.config.frontend_url.clone())
    }

    async fn get_admin_url(&self, _request_uri: &str) -> Result<Option<String>> {
        // Default implementation returns configured admin URL or None
        Ok(self.config.admin_url.clone())
    }

    async fn resolve_hostname(&self, request_uri: &str) -> Result<HostnameResolution> {
        let hostname = if self.config.use_request_hostname {
            // Extract hostname from request URI
            if let Some(host) = extract_hostname_from_uri(request_uri) {
                Some(host)
            } else {
                self.config.hostname.clone()
            }
        } else {
            self.config.hostname.clone()
        };

        let hostname = hostname.unwrap_or_else(|| "localhost".to_string());

        Ok(HostnameResolution {
            hostname,
            frontend_url: self.config.frontend_url.clone(),
            admin_url: self.config.admin_url.clone(),
            fixed: !self.config.use_request_hostname,
        })
    }

    async fn is_hostname_required(&self) -> Result<bool> {
        Ok(self.config.hostname_required)
    }
}

impl Provider for DefaultHostnameProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Factory for creating HostnameProvider instances
pub struct DefaultHostnameProviderFactory;

impl Default for DefaultHostnameProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultHostnameProviderFactory {
    /// Creates a new default hostname provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<DefaultHostnameProvider> for DefaultHostnameProviderFactory {
    fn get_id(&self) -> &'static str {
        "default-hostname"
    }

    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<DefaultHostnameProvider>, SpiError> {
        let provider = DefaultHostnameProvider::new();
        Ok(Box::new(provider))
    }
}

/// Extract hostname from URI string
pub fn extract_hostname_from_uri(uri: &str) -> Option<String> {
    if let Some(scheme_end) = uri.find("://") {
        let after_scheme = &uri[scheme_end + 3..];
        if let Some(host_end) = after_scheme.find(':').or_else(|| after_scheme.find('/')) {
            Some(after_scheme[..host_end].to_string())
        } else {
            Some(after_scheme.to_string())
        }
    } else {
        None
    }
}
