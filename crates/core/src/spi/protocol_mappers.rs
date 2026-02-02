use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use authenc_api::error::{AuthencError as Error, Result};
use authenc_api::models::user::User;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Protocol mapper types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMapperType {
    /// Maps user properties to token claims
    UserProperty,
    /// Maps user roles to token claims
    UserRole,
    /// Maps user groups to token claims
    UserGroup,
    /// Maps user attributes to token claims
    UserAttribute,
    /// Maps hardcoded values to token claims
    HardcodedClaim,
    /// Maps user realm roles to token claims
    UserRealmRole,
    /// Maps user client roles to token claims
    UserClientRole,
    /// Custom script-based mapping
    Script,
}

/// Protocol mapper configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMapperConfig {
    /// Unique identifier for the mapper
    pub id: String,
    /// Display name
    pub name: String,
    /// Protocol mapper type
    pub mapper_type: ProtocolMapperType,
    /// Protocol this mapper applies to (openid-connect, saml, etc.)
    pub protocol: String,
    /// Claim name in the token
    pub claim_name: String,
    /// Claim value type (String, long, int, boolean, JSON)
    pub claim_value_type: String,
    /// User attribute name (for user attribute mappers)
    pub user_attribute: Option<String>,
    /// JSON type label for complex claims
    pub json_type_label: Option<String>,
    /// Whether this claim should be included in access tokens
    pub include_in_access_token: bool,
    /// Whether this claim should be included in identity tokens
    pub include_in_identity_token: bool,
    /// Whether this claim should be included in user info
    pub include_in_userinfo: bool,
    /// Whether this claim should be included in tokens by default
    pub include_in_tokens: bool,
    /// Additional configuration properties
    pub config: HashMap<String, String>,
}

/// Protocol mapper evaluation context
#[derive(Debug, Clone)]
pub struct ProtocolMapperContext {
    /// The user being mapped
    pub user: Arc<User>,
    /// The client ID
    pub client_id: String,
    /// The realm ID
    pub realm_id: String,
    /// Protocol-specific context
    pub protocol_context: HashMap<String, String>,
    /// Current token claims being built
    pub claims: HashMap<String, serde_json::Value>,
}

/// Protocol mapper trait
#[async_trait]
pub trait ProtocolMapper: Provider + Send + Sync {
    /// Get the protocol mapper configuration
    fn get_config(&self) -> &ProtocolMapperConfig;

    /// Evaluate the mapper and return claims to add to the token
    async fn evaluate(
        &self,
        context: &ProtocolMapperContext,
    ) -> Result<HashMap<String, serde_json::Value>>;

    /// Get the mapper type
    fn get_mapper_type(&self) -> ProtocolMapperType;

    /// Get the protocol this mapper applies to
    fn get_protocol(&self) -> &str;

    /// Check if this mapper should be applied for the given context
    fn applies_to(&self, context: &ProtocolMapperContext) -> bool;
}

/// Protocol mapper provider trait
#[async_trait]
pub trait ProtocolMapperProvider: Provider + Send + Sync {
    /// Get all available protocol mappers
    async fn get_protocol_mappers(&self) -> Result<Vec<Box<dyn ProtocolMapper + Send + Sync>>>;

    /// Get protocol mapper by ID
    async fn get_protocol_mapper(
        &self,
        mapper_id: &str,
    ) -> Result<Option<Box<dyn ProtocolMapper + Send + Sync>>>;

    /// Create a new protocol mapper
    async fn create_protocol_mapper(
        &self,
        config: ProtocolMapperConfig,
    ) -> Result<Box<dyn ProtocolMapper + Send + Sync>>;

    /// Update an existing protocol mapper
    async fn update_protocol_mapper(
        &self,
        mapper_id: &str,
        config: ProtocolMapperConfig,
    ) -> Result<Box<dyn ProtocolMapper + Send + Sync>>;

    /// Delete a protocol mapper
    async fn delete_protocol_mapper(&self, mapper_id: &str) -> Result<()>;

    /// Get protocol mappers for a specific protocol
    async fn get_protocol_mappers_by_protocol(
        &self,
        protocol: &str,
    ) -> Result<Vec<Box<dyn ProtocolMapper + Send + Sync>>>;
}

/// Default user property protocol mapper
pub struct UserPropertyProtocolMapper {
    config: ProtocolMapperConfig,
}

impl UserPropertyProtocolMapper {
    /// Create a new user property protocol mapper with the given configuration
    pub fn new(config: ProtocolMapperConfig) -> Self {
        Self { config }
    }
}

impl Provider for UserPropertyProtocolMapper {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl ProtocolMapper for UserPropertyProtocolMapper {
    fn get_config(&self) -> &ProtocolMapperConfig {
        &self.config
    }

    async fn evaluate(
        &self,
        context: &ProtocolMapperContext,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut claims = HashMap::new();

        // Map user properties based on configuration
        match self.config.user_attribute.as_deref() {
            Some("username") => {
                claims.insert(
                    self.config.claim_name.clone(),
                    serde_json::Value::String(context.user.username.clone()),
                );
            }
            Some("email") => {
                claims.insert(
                    self.config.claim_name.clone(),
                    serde_json::Value::String(context.user.email.clone()),
                );
            }
            Some("firstName") => {
                if let Some(first_name) = &context.user.first_name {
                    claims.insert(
                        self.config.claim_name.clone(),
                        serde_json::Value::String(first_name.clone()),
                    );
                }
            }
            Some("lastName") => {
                if let Some(last_name) = &context.user.last_name {
                    claims.insert(
                        self.config.claim_name.clone(),
                        serde_json::Value::String(last_name.clone()),
                    );
                }
            }
            Some("name") => {
                let full_name = format!(
                    "{} {}",
                    context.user.first_name.as_deref().unwrap_or(""),
                    context.user.last_name.as_deref().unwrap_or("")
                )
                .trim()
                .to_string();
                if !full_name.is_empty() {
                    claims.insert(
                        self.config.claim_name.clone(),
                        serde_json::Value::String(full_name),
                    );
                }
            }
            _ => {
                // For custom attributes, we could look them up from user attributes
                // For now, we'll skip unknown attributes
            }
        }

        Ok(claims)
    }

    fn get_mapper_type(&self) -> ProtocolMapperType {
        ProtocolMapperType::UserProperty
    }

    fn get_protocol(&self) -> &str {
        &self.config.protocol
    }

    fn applies_to(&self, _context: &ProtocolMapperContext) -> bool {
        // Apply to all contexts for now
        true
    }
}

/// Default user role protocol mapper
pub struct UserRoleProtocolMapper {
    config: ProtocolMapperConfig,
}

impl UserRoleProtocolMapper {
    /// Create a new user role protocol mapper with the given configuration
    pub fn new(config: ProtocolMapperConfig) -> Self {
        Self { config }
    }
}

impl Provider for UserRoleProtocolMapper {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl ProtocolMapper for UserRoleProtocolMapper {
    fn get_config(&self) -> &ProtocolMapperConfig {
        &self.config
    }

    async fn evaluate(
        &self,
        _context: &ProtocolMapperContext,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut claims = HashMap::new();

        // For now, we'll add a placeholder role claim
        // In a real implementation, this would fetch user roles from the role store
        let roles = vec!["user"]; // Placeholder

        claims.insert(self.config.claim_name.clone(), serde_json::json!(roles));

        Ok(claims)
    }

    fn get_mapper_type(&self) -> ProtocolMapperType {
        ProtocolMapperType::UserRole
    }

    fn get_protocol(&self) -> &str {
        &self.config.protocol
    }

    fn applies_to(&self, _context: &ProtocolMapperContext) -> bool {
        true
    }
}

/// Default protocol mapper provider
pub struct DefaultProtocolMapperProvider;

impl Default for DefaultProtocolMapperProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultProtocolMapperProvider {
    /// Create a new default protocol mapper provider
    pub fn new() -> Self {
        Self
    }
}

impl Provider for DefaultProtocolMapperProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl ProtocolMapperProvider for DefaultProtocolMapperProvider {
    async fn get_protocol_mappers(&self) -> Result<Vec<Box<dyn ProtocolMapper + Send + Sync>>> {
        // Return default mappers
        let mut mappers: Vec<Box<dyn ProtocolMapper + Send + Sync>> = Vec::new();

        // Add default user property mapper for username
        let username_config = ProtocolMapperConfig {
            id: "username-mapper".to_string(),
            name: "username".to_string(),
            mapper_type: ProtocolMapperType::UserProperty,
            protocol: "openid-connect".to_string(),
            claim_name: "preferred_username".to_string(),
            claim_value_type: "String".to_string(),
            user_attribute: Some("username".to_string()),
            json_type_label: None,
            include_in_access_token: true,
            include_in_identity_token: true,
            include_in_userinfo: true,
            include_in_tokens: true,
            config: HashMap::new(),
        };
        mappers.push(Box::new(UserPropertyProtocolMapper::new(username_config)));

        // Add default user property mapper for email
        let email_config = ProtocolMapperConfig {
            id: "email-mapper".to_string(),
            name: "email".to_string(),
            mapper_type: ProtocolMapperType::UserProperty,
            protocol: "openid-connect".to_string(),
            claim_name: "email".to_string(),
            claim_value_type: "String".to_string(),
            user_attribute: Some("email".to_string()),
            json_type_label: None,
            include_in_access_token: true,
            include_in_identity_token: true,
            include_in_userinfo: true,
            include_in_tokens: true,
            config: HashMap::new(),
        };
        mappers.push(Box::new(UserPropertyProtocolMapper::new(email_config)));

        Ok(mappers)
    }

    async fn get_protocol_mapper(
        &self,
        mapper_id: &str,
    ) -> Result<Option<Box<dyn ProtocolMapper + Send + Sync>>> {
        let mappers = self.get_protocol_mappers().await?;
        Ok(mappers.into_iter().find(|m| m.get_config().id == mapper_id))
    }

    async fn create_protocol_mapper(
        &self,
        config: ProtocolMapperConfig,
    ) -> Result<Box<dyn ProtocolMapper + Send + Sync>> {
        match config.mapper_type {
            ProtocolMapperType::UserProperty => {
                Ok(Box::new(UserPropertyProtocolMapper::new(config)))
            }
            ProtocolMapperType::UserRole => Ok(Box::new(UserRoleProtocolMapper::new(config))),
            _ => Err(Error::internal("Unsupported protocol mapper type")),
        }
    }

    async fn update_protocol_mapper(
        &self,
        _mapper_id: &str,
        config: ProtocolMapperConfig,
    ) -> Result<Box<dyn ProtocolMapper + Send + Sync>> {
        // For now, just create a new mapper with updated config
        self.create_protocol_mapper(config).await
    }

    async fn delete_protocol_mapper(&self, _mapper_id: &str) -> Result<()> {
        // In a real implementation, this would remove the mapper from storage
        Ok(())
    }

    async fn get_protocol_mappers_by_protocol(
        &self,
        protocol: &str,
    ) -> Result<Vec<Box<dyn ProtocolMapper + Send + Sync>>> {
        let all_mappers = self.get_protocol_mappers().await?;
        Ok(all_mappers
            .into_iter()
            .filter(|m| m.get_protocol() == protocol)
            .collect())
    }
}

/// Protocol mapper provider factory
pub struct DefaultProtocolMapperProviderFactory;

impl Default for DefaultProtocolMapperProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultProtocolMapperProviderFactory {
    /// Create a new default protocol mapper provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn ProtocolMapperProvider> for DefaultProtocolMapperProviderFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn ProtocolMapperProvider>, SpiError> {
        Ok(Box::new(DefaultProtocolMapperProvider::new()))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-protocol-mapper"
    }
}

/// Protocol mapper SPI implementation
pub struct ProtocolMapperSpi;

impl Spi for ProtocolMapperSpi {
    fn get_name(&self) -> &'static str {
        "protocol-mapper"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "ProtocolMapperProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "ProtocolMapperProviderFactory"
    }
}
