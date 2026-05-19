use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use authenc_core::error::Result;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, SpiError};

/// Rich Authorization Request (RAR) SPI for advanced authorization features
/// This SPI enables rich authorization requests as defined in RFC 9396
pub struct RichAuthorizationSpi;

impl Default for RichAuthorizationSpi {
    fn default() -> Self {
        Self::new()
    }
}

impl RichAuthorizationSpi {
    /// Create a new rich authorization SPI instance
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl crate::spi::Spi for RichAuthorizationSpi {
    fn get_name(&self) -> &'static str {
        "rich-authorization"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.authorization.policy.provider.rar.RichAuthorizationProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.authorization.policy.provider.rar.RichAuthorizationProviderFactory"
    }
}

/// Rich Authorization Request as defined in RFC 9396
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichAuthorizationRequest {
    /// The subject of the authorization request
    pub subject: AuthorizationSubject,
    /// The resource being accessed
    pub resource: AuthorizationResource,
    /// The action being performed
    pub action: AuthorizationAction,
    /// Additional context for the authorization decision
    pub context: HashMap<String, serde_json::Value>,
    /// Timestamp of the request
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Subject in an authorization request
pub struct AuthorizationSubject {
    /// Subject identifier
    pub id: String,
    /// Subject attributes
    pub attributes: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Resource in an authorization request
pub struct AuthorizationResource {
    /// Resource identifier
    pub id: String,
    /// Resource type
    pub resource_type: String,
    /// Resource attributes
    pub attributes: HashMap<String, Vec<String>>,
    /// Resource scopes
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Action in an authorization request
pub struct AuthorizationAction {
    /// Action identifier
    pub id: String,
    /// Action attributes
    pub attributes: HashMap<String, Vec<String>>,
}

/// Authorization decision result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Whether the request is permitted
    pub permitted: bool,
    /// Obligations that must be fulfilled
    pub obligations: Vec<AuthorizationObligation>,
    /// Advice for the authorization decision
    pub advice: Vec<AuthorizationAdvice>,
    /// Additional context
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Obligation that must be fulfilled for authorization
pub struct AuthorizationObligation {
    /// Obligation identifier
    pub id: String,
    /// Obligation parameters
    pub parameters: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Advice for authorization decisions
pub struct AuthorizationAdvice {
    /// Advice identifier
    pub id: String,
    /// Advice parameters
    pub parameters: HashMap<String, Vec<String>>,
}

/// Provider interface for Rich Authorization Request processing
#[async_trait]
pub trait RichAuthorizationProvider: Provider + Send + Sync {
    /// Evaluate a rich authorization request
    async fn evaluate(&self, request: &RichAuthorizationRequest) -> Result<AuthorizationDecision>;

    /// Get supported resource types
    fn get_supported_resource_types(&self) -> Vec<String>;

    /// Check if the provider supports a specific resource type
    fn supports_resource_type(&self, resource_type: &str) -> bool {
        self.get_supported_resource_types()
            .contains(&resource_type.to_string())
    }
}

/// Default implementation of RichAuthorizationProvider
pub struct DefaultRichAuthorizationProvider;

impl Default for DefaultRichAuthorizationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultRichAuthorizationProvider {
    /// Creates a new default rich authorization provider
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RichAuthorizationProvider for DefaultRichAuthorizationProvider {
    async fn evaluate(&self, _request: &RichAuthorizationRequest) -> Result<AuthorizationDecision> {
        // Default implementation returns denied decision
        Ok(AuthorizationDecision {
            permitted: false,
            obligations: vec![],
            advice: vec![],
            context: HashMap::new(),
        })
    }

    fn get_supported_resource_types(&self) -> Vec<String> {
        vec!["default".to_string()]
    }
}

impl Provider for DefaultRichAuthorizationProvider {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Factory for creating RichAuthorizationProvider instances
pub struct DefaultRichAuthorizationProviderFactory;

impl Default for DefaultRichAuthorizationProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultRichAuthorizationProviderFactory {
    /// Creates a new default rich authorization provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<DefaultRichAuthorizationProvider> for DefaultRichAuthorizationProviderFactory {
    fn get_id(&self) -> &'static str {
        "default-rich-authorization"
    }

    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<DefaultRichAuthorizationProvider>, SpiError> {
        let provider = DefaultRichAuthorizationProvider::new();
        Ok(Box::new(provider))
    }
}
