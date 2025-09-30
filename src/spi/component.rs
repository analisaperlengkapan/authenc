use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

use crate::error::Result;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Component model representing a configurable component instance
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentModel {
    /// Unique identifier for the component
    pub id: String,
    /// Display name of the component
    pub name: String,
    /// Provider identifier that implements this component
    pub provider_id: String,
    /// Type of provider (e.g., "protocol-mapper", "authenticator")
    pub provider_type: String,
    /// Parent component ID if this is a sub-component
    pub parent_id: Option<String>,
    /// Sub-type classification for the component
    pub sub_type: Option<String>,
    /// Configuration properties as key-value pairs
    pub config: HashMap<String, Vec<String>>,
    /// Additional metadata notes for the component
    #[serde(skip)]
    pub notes: HashMap<String, serde_json::Value>,
}

impl ComponentModel {
    /// Creates a new component model with the specified provider information
    pub fn new(provider_id: String, provider_type: String, name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            provider_id,
            provider_type,
            parent_id: None,
            sub_type: None,
            config: HashMap::new(),
            notes: HashMap::new(),
        }
    }

    /// Gets the component's unique identifier
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Gets the component's display name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Gets the provider identifier
    pub fn get_provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Gets the provider type
    pub fn get_provider_type(&self) -> &str {
        &self.provider_type
    }

    /// Gets the parent component ID if any
    pub fn get_parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }

    /// Sets the parent component ID
    pub fn set_parent_id(&mut self, parent_id: Option<String>) {
        self.parent_id = parent_id;
    }

    /// Gets the component's sub-type if any
    pub fn get_sub_type(&self) -> Option<&str> {
        self.sub_type.as_deref()
    }

    /// Sets the component's sub-type
    pub fn set_sub_type(&mut self, sub_type: Option<String>) {
        self.sub_type = sub_type;
    }

    /// Gets the component's configuration properties
    pub fn get_config(&self) -> &HashMap<String, Vec<String>> {
        &self.config
    }

    /// Gets a specific configuration value by key
    pub fn get_config_value(&self, key: &str) -> Option<&Vec<String>> {
        self.config.get(key)
    }

    /// Gets the first configuration value for a key
    pub fn get_first_config_value(&self, key: &str) -> Option<&str> {
        self.config.get(key)?.first().map(|s| s.as_str())
    }

    /// Sets a single configuration value
    pub fn put_config_value(&mut self, key: String, value: String) {
        self.config.insert(key, vec![value]);
    }

    /// Sets multiple configuration values for a key
    pub fn put_config_values(&mut self, key: String, values: Vec<String>) {
        self.config.insert(key, values);
    }

    /// Gets a note value by key
    pub fn get_note(&self, key: &str) -> Option<&serde_json::Value> {
        self.notes.get(key)
    }

    /// Sets a note value
    pub fn put_note(&mut self, key: String, value: serde_json::Value) {
        self.notes.insert(key, value);
    }

    /// Removes a note by key
    pub fn remove_note(&mut self, key: &str) -> bool {
        self.notes.remove(key).is_some()
    }
}

/// Component validation exception
#[derive(Debug, Clone)]
pub struct ComponentValidationException {
    /// Error message describing the validation failure
    pub message: String,
}

impl ComponentValidationException {
    /// Creates a new component validation exception with the given message
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for ComponentValidationException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Component validation error: {}", self.message)
    }
}

impl std::error::Error for ComponentValidationException {}

/// Configuration property for providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfigProperty {
    /// Property name
    pub name: String,
    /// Display label
    pub label: String,
    /// Help text
    pub help_text: Option<String>,
    /// Property type (string, boolean, etc.)
    pub property_type: String,
    /// Default value
    pub default_value: Option<String>,
    /// Whether the property is required
    pub required: bool,
    /// Whether the property contains secret data
    pub secret: bool,
}

/// Component factory trait for creating configurable components
#[async_trait]
pub trait ComponentFactory<CreatedType, ProviderType: Provider + ?Sized>:
    ProviderFactory<ProviderType> + Send + Sync
{
    /// Create a component instance
    async fn create_component(&self, model: &ComponentModel) -> Result<CreatedType>;

    /// Validate component configuration
    async fn validate_configuration(&self, model: &ComponentModel) -> Result<()> {
        Ok(())
    }

    /// Called after a component is created
    async fn on_create(&self, _model: &ComponentModel) -> Result<()> {
        Ok(())
    }

    /// Called after the component is updated
    async fn on_update(
        &self,
        _old_model: &ComponentModel,
        _new_model: &ComponentModel,
    ) -> Result<()> {
        Ok(())
    }

    /// Called before the component is removed
    async fn pre_remove(&self, _model: &ComponentModel) -> Result<()> {
        Ok(())
    }

    /// Get common provider config properties
    fn get_common_provider_config_properties(&self) -> Vec<ProviderConfigProperty> {
        vec![]
    }

    /// Get type metadata
    fn get_type_metadata(&self) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }
}

/// Sub-component factory for hierarchical components
#[async_trait]
pub trait SubComponentFactory<CreatedType, ProviderType: Provider + ?Sized>:
    ComponentFactory<CreatedType, ProviderType>
{
    /// Get the component type this factory handles
    fn get_component_type(&self) -> &str;
}

/// Component factory provider for managing component factories
#[async_trait]
pub trait ComponentFactoryProvider: Provider + Send + Sync {
    /// Get component factory by provider type
    fn get_component_factory(&self, provider_type: &str) -> Option<&dyn Any>;

    /// Get all component factories
    fn get_component_factories(&self) -> Vec<&dyn Any>;

    /// Register a component factory
    fn register_component_factory(
        &mut self,
        provider_type: String,
        factory: Box<dyn Any + Send + Sync>,
    );

    /// Unregister a component factory
    fn unregister_component_factory(&mut self, provider_type: &str);
}

/// Default component factory provider implementation
pub struct DefaultComponentFactoryProvider {
    factories: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl Default for DefaultComponentFactoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultComponentFactoryProvider {
    /// Creates a new default component factory provider
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }
}

#[async_trait]
impl ComponentFactoryProvider for DefaultComponentFactoryProvider {
    fn get_component_factory(&self, provider_type: &str) -> Option<&dyn Any> {
        self.factories
            .get(provider_type)
            .map(|f| f.as_ref() as &dyn Any)
    }

    fn get_component_factories(&self) -> Vec<&dyn Any> {
        self.factories
            .values()
            .map(|f| f.as_ref() as &dyn Any)
            .collect()
    }

    fn register_component_factory(
        &mut self,
        provider_type: String,
        factory: Box<dyn Any + Send + Sync>,
    ) {
        self.factories.insert(provider_type, factory);
    }

    fn unregister_component_factory(&mut self, provider_type: &str) {
        self.factories.remove(provider_type);
    }
}

impl Provider for DefaultComponentFactoryProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Component factory provider factory
pub struct DefaultComponentFactoryProviderFactory;

impl Default for DefaultComponentFactoryProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultComponentFactoryProviderFactory {
    /// Creates a new default component factory provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn ComponentFactoryProvider> for DefaultComponentFactoryProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn ComponentFactoryProvider>, SpiError> {
        Ok(Box::new(DefaultComponentFactoryProvider::new()))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-component-factory"
    }
}

/// Component SPI implementation
pub struct ComponentSpi;

impl Spi for ComponentSpi {
    fn get_name(&self) -> &'static str {
        "component"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "ComponentFactoryProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "ComponentFactoryProviderFactory"
    }
}
