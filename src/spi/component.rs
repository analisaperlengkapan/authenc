use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

use crate::error::{Result, AuthencError as Error};
use crate::spi::{Provider, ProviderFactory, Spi, ProviderConfig, SpiError};

/// Component model representing a configurable component instance
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentModel {
    pub id: String,
    pub name: String,
    pub provider_id: String,
    pub provider_type: String,
    pub parent_id: Option<String>,
    pub sub_type: Option<String>,
    pub config: HashMap<String, Vec<String>>,
    #[serde(skip)]
    pub notes: HashMap<String, serde_json::Value>,
}

impl ComponentModel {
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

    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn get_provider_type(&self) -> &str {
        &self.provider_type
    }

    pub fn get_parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }

    pub fn set_parent_id(&mut self, parent_id: Option<String>) {
        self.parent_id = parent_id;
    }

    pub fn get_sub_type(&self) -> Option<&str> {
        self.sub_type.as_deref()
    }

    pub fn set_sub_type(&mut self, sub_type: Option<String>) {
        self.sub_type = sub_type;
    }

    pub fn get_config(&self) -> &HashMap<String, Vec<String>> {
        &self.config
    }

    pub fn get_config_value(&self, key: &str) -> Option<&Vec<String>> {
        self.config.get(key)
    }

    pub fn get_first_config_value(&self, key: &str) -> Option<&str> {
        self.config.get(key)?.first().map(|s| s.as_str())
    }

    pub fn put_config_value(&mut self, key: String, value: String) {
        self.config.insert(key, vec![value]);
    }

    pub fn put_config_values(&mut self, key: String, values: Vec<String>) {
        self.config.insert(key, values);
    }

    pub fn get_note(&self, key: &str) -> Option<&serde_json::Value> {
        self.notes.get(key)
    }

    pub fn put_note(&mut self, key: String, value: serde_json::Value) {
        self.notes.insert(key, value);
    }

    pub fn remove_note(&mut self, key: &str) -> bool {
        self.notes.remove(key).is_some()
    }
}

/// Component validation exception
#[derive(Debug, Clone)]
pub struct ComponentValidationException {
    pub message: String,
}

impl ComponentValidationException {
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
pub trait ComponentFactory<CreatedType, ProviderType: Provider + ?Sized>: ProviderFactory<ProviderType> + Send + Sync {
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
    async fn on_update(&self, _old_model: &ComponentModel, _new_model: &ComponentModel) -> Result<()> {
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
pub trait SubComponentFactory<CreatedType, ProviderType: Provider + ?Sized>: ComponentFactory<CreatedType, ProviderType> {
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
    fn register_component_factory(&mut self, provider_type: String, factory: Box<dyn Any + Send + Sync>);

    /// Unregister a component factory
    fn unregister_component_factory(&mut self, provider_type: &str);
}

/// Default component factory provider implementation
pub struct DefaultComponentFactoryProvider {
    factories: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl DefaultComponentFactoryProvider {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }
}

#[async_trait]
impl ComponentFactoryProvider for DefaultComponentFactoryProvider {
    fn get_component_factory(&self, provider_type: &str) -> Option<&dyn Any> {
        self.factories.get(provider_type).map(|f| f.as_ref() as &dyn Any)
    }

    fn get_component_factories(&self) -> Vec<&dyn Any> {
        self.factories.values().map(|f| f.as_ref() as &dyn Any).collect()
    }

    fn register_component_factory(&mut self, provider_type: String, factory: Box<dyn Any + Send + Sync>) {
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

impl DefaultComponentFactoryProviderFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderFactory<dyn ComponentFactoryProvider> for DefaultComponentFactoryProviderFactory {
    async fn create(&self, _config: &ProviderConfig) -> std::result::Result<Box<dyn ComponentFactoryProvider>, SpiError> {
        Ok(Box::new(DefaultComponentFactoryProvider::new()))
    }

    async fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
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
