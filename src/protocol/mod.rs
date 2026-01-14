//! Protocol Mapper Extensions for Authenc
//!
//! Provides extensible claim/attribute mapping for OIDC and SAML protocols.
//! Supports user attributes, roles, groups, and hardcoded values.

use async_trait::async_trait;
use serde_json::{Value as JsonValue, json};
use std::collections::HashMap;
use uuid::Uuid;

/// Protocol types supported
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// OpenID Connect protocol
    OIDC,
    /// Security Assertion Markup Language protocol
    SAML,
}

impl Protocol {
    /// Convert protocol to string representation
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::OIDC => "oidc",
            Protocol::SAML => "saml",
        }
    }
}

/// Mapper context containing user and session data
#[derive(Debug, Clone)]
pub struct MapperContext {
    /// Unique user identifier
    pub user_id: Uuid,
    /// Username of the authenticated user
    pub username: String,
    /// Email address of the user
    pub email: Option<String>,
    /// First name of the user
    pub first_name: Option<String>,
    /// Last name of the user
    pub last_name: Option<String>,
    /// Additional user attributes
    pub attributes: HashMap<String, JsonValue>,
    /// Roles assigned to the user
    pub roles: Vec<String>,
    /// Groups the user belongs to
    pub groups: Vec<String>,
    /// Client identifier for the request
    pub client_id: Option<String>,
    /// Realm identifier
    pub realm: String,
}

/// Protocol mapper trait for extensible claim/attribute mapping
#[async_trait]
pub trait ProtocolMapper: Send + Sync {
    /// Get mapper name
    fn name(&self) -> &str;

    /// Get mapper type
    fn mapper_type(&self) -> &str;

    /// Get supported protocol
    fn protocol(&self) -> Protocol;

    /// Apply mapping to context and return claims/attributes
    async fn map(&self, context: &MapperContext)
    -> Result<HashMap<String, JsonValue>, MapperError>;

    /// Validate mapper configuration
    fn validate_config(&self, config: &JsonValue) -> Result<(), MapperError>;
}

/// Mapper error types
#[derive(Debug, Clone)]
pub enum MapperError {
    /// Invalid mapper configuration
    InvalidConfiguration(String),
    /// Required attribute is missing
    MissingAttribute(String),
    /// Mapping operation failed
    MappingFailed(String),
}

impl std::fmt::Display for MapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapperError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            MapperError::MissingAttribute(msg) => write!(f, "Missing attribute: {}", msg),
            MapperError::MappingFailed(msg) => write!(f, "Mapping failed: {}", msg),
        }
    }
}

impl std::error::Error for MapperError {}

/// User attribute mapper - maps user attributes to claims
pub struct UserAttributeMapper {
    name: String,
    protocol: Protocol,
    user_attribute: String,
    claim_name: String,
    claim_type: String, // String, int, boolean, JSON
}

impl UserAttributeMapper {
    /// Create a new user attribute mapper
    pub fn new(
        name: String,
        protocol: Protocol,
        user_attribute: String,
        claim_name: String,
        claim_type: String,
    ) -> Self {
        Self {
            name,
            protocol,
            user_attribute,
            claim_name,
            claim_type,
        }
    }

    fn convert_value(&self, value: &JsonValue) -> JsonValue {
        match self.claim_type.as_str() {
            "int" | "integer" => {
                if let Some(s) = value.as_str() {
                    s.parse::<i64>().map(|v| json!(v)).unwrap_or(json!(0))
                } else {
                    value.clone()
                }
            }
            "boolean" | "bool" => {
                if let Some(s) = value.as_str() {
                    json!(s.eq_ignore_ascii_case("true") || s == "1")
                } else {
                    value.as_bool().map(|v| json!(v)).unwrap_or(json!(false))
                }
            }
            "json" => {
                if let Some(s) = value.as_str() {
                    serde_json::from_str(s).unwrap_or_else(|_| value.clone())
                } else {
                    value.clone()
                }
            }
            _ => value.clone(), // String or default
        }
    }
}

#[async_trait]
impl ProtocolMapper for UserAttributeMapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn mapper_type(&self) -> &str {
        "user-attribute"
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }

    async fn map(
        &self,
        context: &MapperContext,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut result = HashMap::new();

        if let Some(value) = context.attributes.get(&self.user_attribute) {
            result.insert(self.claim_name.clone(), self.convert_value(value));
        }

        Ok(result)
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), MapperError> {
        if config.get("user_attribute").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "user_attribute is required".to_string(),
            ));
        }
        if config.get("claim_name").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "claim_name is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// User property mapper - maps built-in user properties to claims
pub struct UserPropertyMapper {
    name: String,
    protocol: Protocol,
    property: String, // username, email, firstName, lastName
    claim_name: String,
}

impl UserPropertyMapper {
    /// Create a new user property mapper
    pub fn new(name: String, protocol: Protocol, property: String, claim_name: String) -> Self {
        Self {
            name,
            protocol,
            property,
            claim_name,
        }
    }
}

#[async_trait]
impl ProtocolMapper for UserPropertyMapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn mapper_type(&self) -> &str {
        "user-property"
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }

    async fn map(
        &self,
        context: &MapperContext,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut result = HashMap::new();

        let value = match self.property.as_str() {
            "username" => Some(json!(context.username)),
            "email" => context.email.as_ref().map(|e| json!(e)),
            "firstName" | "first_name" => context.first_name.as_ref().map(|f| json!(f)),
            "lastName" | "last_name" => context.last_name.as_ref().map(|l| json!(l)),
            _ => None,
        };

        if let Some(v) = value {
            result.insert(self.claim_name.clone(), v);
        }

        Ok(result)
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), MapperError> {
        if config.get("property").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "property is required".to_string(),
            ));
        }
        if config.get("claim_name").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "claim_name is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// Role list mapper - maps user roles to claims
pub struct RoleListMapper {
    name: String,
    protocol: Protocol,
    claim_name: String,
    prefix: Option<String>,
}

impl RoleListMapper {
    /// Create a new role list mapper
    pub fn new(
        name: String,
        protocol: Protocol,
        claim_name: String,
        prefix: Option<String>,
    ) -> Self {
        Self {
            name,
            protocol,
            claim_name,
            prefix,
        }
    }
}

#[async_trait]
impl ProtocolMapper for RoleListMapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn mapper_type(&self) -> &str {
        "role-list"
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }

    async fn map(
        &self,
        context: &MapperContext,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut result = HashMap::new();

        let roles: Vec<String> = if let Some(ref prefix) = self.prefix {
            context
                .roles
                .iter()
                .map(|r| format!("{}{}", prefix, r))
                .collect()
        } else {
            context.roles.clone()
        };

        result.insert(self.claim_name.clone(), json!(roles));
        Ok(result)
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), MapperError> {
        if config.get("claim_name").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "claim_name is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// Hardcoded claim mapper - adds hardcoded values to claims
pub struct HardcodedClaimMapper {
    name: String,
    protocol: Protocol,
    claim_name: String,
    claim_value: JsonValue,
}

impl HardcodedClaimMapper {
    /// Create a new hardcoded claim mapper
    pub fn new(
        name: String,
        protocol: Protocol,
        claim_name: String,
        claim_value: JsonValue,
    ) -> Self {
        Self {
            name,
            protocol,
            claim_name,
            claim_value,
        }
    }
}

#[async_trait]
impl ProtocolMapper for HardcodedClaimMapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn mapper_type(&self) -> &str {
        "hardcoded-claim"
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }

    async fn map(
        &self,
        _context: &MapperContext,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut result = HashMap::new();
        result.insert(self.claim_name.clone(), self.claim_value.clone());
        Ok(result)
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), MapperError> {
        if config.get("claim_name").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "claim_name is required".to_string(),
            ));
        }
        if config.get("claim_value").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "claim_value is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// Group membership mapper - maps user groups to claims
pub struct GroupMembershipMapper {
    name: String,
    protocol: Protocol,
    claim_name: String,
    full_path: bool,
}

impl GroupMembershipMapper {
    /// Create a new group membership mapper
    pub fn new(name: String, protocol: Protocol, claim_name: String, full_path: bool) -> Self {
        Self {
            name,
            protocol,
            claim_name,
            full_path,
        }
    }
}

#[async_trait]
impl ProtocolMapper for GroupMembershipMapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn mapper_type(&self) -> &str {
        "group-membership"
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }

    async fn map(
        &self,
        context: &MapperContext,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut result = HashMap::new();

        let groups = if self.full_path {
            context.groups.clone()
        } else {
            context
                .groups
                .iter()
                .map(|g| g.split('/').next_back().unwrap_or(g).to_string())
                .collect()
        };

        result.insert(self.claim_name.clone(), json!(groups));
        Ok(result)
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), MapperError> {
        if config.get("claim_name").is_none() {
            return Err(MapperError::InvalidConfiguration(
                "claim_name is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// Audience mapper - adds audience to tokens
pub struct AudienceMapper {
    name: String,
    protocol: Protocol,
    included_client_audience: Option<String>,
    included_custom_audience: Option<String>,
}

impl AudienceMapper {
    /// Create a new audience mapper
    pub fn new(
        name: String,
        protocol: Protocol,
        included_client_audience: Option<String>,
        included_custom_audience: Option<String>,
    ) -> Self {
        Self {
            name,
            protocol,
            included_client_audience,
            included_custom_audience,
        }
    }
}

#[async_trait]
impl ProtocolMapper for AudienceMapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn mapper_type(&self) -> &str {
        "audience"
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }

    async fn map(
        &self,
        context: &MapperContext,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut result = HashMap::new();
        let mut audiences = Vec::new();

        if let Some(ref client) = self.included_client_audience {
            audiences.push(client.clone());
        }

        if let Some(ref custom) = self.included_custom_audience {
            audiences.push(custom.clone());
        }

        // Include current client as audience
        if let Some(ref client_id) = context.client_id
            && !audiences.contains(client_id) {
                audiences.push(client_id.clone());
            }

        if !audiences.is_empty() {
            result.insert("aud".to_string(), json!(audiences));
        }

        Ok(result)
    }

    fn validate_config(&self, _config: &JsonValue) -> Result<(), MapperError> {
        // Audience mapper has optional configuration
        Ok(())
    }
}

/// Mapper registry for managing protocol mappers
pub struct MapperRegistry {
    mappers: Vec<Box<dyn ProtocolMapper>>,
}

impl MapperRegistry {
    /// Create a new mapper registry
    pub fn new() -> Self {
        Self {
            mappers: Vec::new(),
        }
    }

    /// Register a protocol mapper
    pub fn register(&mut self, mapper: Box<dyn ProtocolMapper>) {
        self.mappers.push(mapper);
    }

    /// Apply all registered mappers for the given protocol
    pub async fn apply_mappers(
        &self,
        context: &MapperContext,
        protocol: &Protocol,
    ) -> Result<HashMap<String, JsonValue>, MapperError> {
        let mut all_claims = HashMap::new();

        for mapper in &self.mappers {
            if &mapper.protocol() == protocol {
                let claims = mapper.map(context).await?;
                all_claims.extend(claims);
            }
        }

        Ok(all_claims)
    }
}

impl Default for MapperRegistry {
    fn default() -> Self {
        Self::new()
    }
}
