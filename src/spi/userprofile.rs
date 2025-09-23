//! User Profile Service Provider Interface
//!
//! Provides user profile management and validation capabilities.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

/// User Profile SPI implementation
pub struct UserProfileSpi;

impl Spi for UserProfileSpi {
    fn get_name(&self) -> &'static str {
        "userProfile"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "org.keycloak.userprofile.UserProfileProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "org.keycloak.userprofile.UserProfileProviderFactory"
    }
}

/// User profile attribute descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileAttribute {
    /// Attribute name
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Attribute type
    pub attribute_type: AttributeType,
    /// Whether the attribute is required
    pub required: bool,
    /// Whether the attribute is read-only
    pub read_only: bool,
    /// Validation rules
    pub validations: Vec<AttributeValidation>,
    /// Group name for UI organization
    pub group: Option<String>,
    /// Display order within group
    pub display_order: Option<i32>,
    /// Annotations for additional metadata
    pub annotations: HashMap<String, String>,
}

/// Attribute types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttributeType {
    Text,
    Email,
    Url,
    Number,
    Date,
    Select,
    Multiselect,
    Boolean,
    File,
}

/// Attribute validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeValidation {
    /// Validator name
    pub validator: String,
    /// Validation configuration
    pub config: HashMap<String, String>,
}

/// User profile context
#[derive(Debug, Clone)]
pub enum UserProfileContext {
    /// User registration
    Registration,
    /// User profile update
    UpdateProfile,
    /// Identity brokering
    IdpReview,
    /// Account management
    Account,
    /// Admin console
    UserApi,
}

/// User profile provider interface
#[async_trait]
pub trait UserProfileProvider: Provider {
    /// Get user profile attributes for a context
    async fn get_profile_attributes(
        &self,
        context: UserProfileContext,
    ) -> Result<Vec<UserProfileAttribute>, UserProfileError>;

    /// Validate user profile attributes
    async fn validate_user_profile(
        &self,
        context: UserProfileContext,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<UserProfileValidationResult, UserProfileError>;

    /// Create user profile metadata
    async fn create_user_profile_metadata(
        &self,
        context: UserProfileContext,
    ) -> Result<UserProfileMetadata, UserProfileError>;
}

/// User profile validation result
#[derive(Debug, Clone)]
pub struct UserProfileValidationResult {
    /// Whether validation passed
    pub is_valid: bool,
    /// Validation errors by attribute
    pub errors: HashMap<String, Vec<String>>,
}

/// User profile metadata
#[derive(Debug, Clone)]
pub struct UserProfileMetadata {
    /// Profile attributes
    pub attributes: Vec<UserProfileAttribute>,
    /// Profile groups
    pub groups: Vec<UserProfileGroup>,
}

/// User profile group for UI organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileGroup {
    /// Group name
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Display order
    pub display_order: Option<i32>,
    /// Annotations
    pub annotations: HashMap<String, String>,
}

/// User profile provider factory
#[async_trait]
pub trait UserProfileProviderFactory: ProviderFactory<dyn UserProfileProvider> {
    /// Get the provider priority
    fn get_priority(&self) -> i32 {
        0
    }
}

/// User profile errors
#[derive(Debug, thiserror::Error)]
pub enum UserProfileError {
    #[error("User profile validation failed: {0}")]
    ValidationFailed(String),

    #[error("Attribute not found: {0}")]
    AttributeNotFound(String),

    #[error("Invalid attribute value: {0}")]
    InvalidAttributeValue(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Profile context not supported: {0:?}")]
    UnsupportedContext(UserProfileContext),
}

/// Default user profile provider implementation
pub struct DefaultUserProfileProvider {
    attributes: Vec<UserProfileAttribute>,
}

impl DefaultUserProfileProvider {
    /// Create a new default user profile provider
    pub fn new() -> Self {
        let mut attributes = Vec::new();

        // Add default attributes
        attributes.push(UserProfileAttribute {
            name: "username".to_string(),
            display_name: Some("Username".to_string()),
            attribute_type: AttributeType::Text,
            required: true,
            read_only: false,
            validations: vec![AttributeValidation {
                validator: "length".to_string(),
                config: {
                    let mut config = HashMap::new();
                    config.insert("min".to_string(), "3".to_string());
                    config.insert("max".to_string(), "255".to_string());
                    config
                },
            }],
            group: Some("basic".to_string()),
            display_order: Some(1),
            annotations: HashMap::new(),
        });

        attributes.push(UserProfileAttribute {
            name: "email".to_string(),
            display_name: Some("Email".to_string()),
            attribute_type: AttributeType::Email,
            required: true,
            read_only: false,
            validations: vec![AttributeValidation {
                validator: "email".to_string(),
                config: HashMap::new(),
            }],
            group: Some("basic".to_string()),
            display_order: Some(2),
            annotations: HashMap::new(),
        });

        attributes.push(UserProfileAttribute {
            name: "firstName".to_string(),
            display_name: Some("First Name".to_string()),
            attribute_type: AttributeType::Text,
            required: false,
            read_only: false,
            validations: vec![AttributeValidation {
                validator: "length".to_string(),
                config: {
                    let mut config = HashMap::new();
                    config.insert("max".to_string(), "255".to_string());
                    config
                },
            }],
            group: Some("personal".to_string()),
            display_order: Some(1),
            annotations: HashMap::new(),
        });

        attributes.push(UserProfileAttribute {
            name: "lastName".to_string(),
            display_name: Some("Last Name".to_string()),
            attribute_type: AttributeType::Text,
            required: false,
            read_only: false,
            validations: vec![AttributeValidation {
                validator: "length".to_string(),
                config: {
                    let mut config = HashMap::new();
                    config.insert("max".to_string(), "255".to_string());
                    config
                },
            }],
            group: Some("personal".to_string()),
            display_order: Some(2),
            annotations: HashMap::new(),
        });

        Self { attributes }
    }
}

#[async_trait]
impl UserProfileProvider for DefaultUserProfileProvider {
    async fn get_profile_attributes(
        &self,
        _context: UserProfileContext,
    ) -> Result<Vec<UserProfileAttribute>, UserProfileError> {
        Ok(self.attributes.clone())
    }

    async fn validate_user_profile(
        &self,
        _context: UserProfileContext,
        attributes: &HashMap<String, Vec<String>>,
    ) -> Result<UserProfileValidationResult, UserProfileError> {
        let mut errors = HashMap::new();

        // Basic validation logic
        for attr in &self.attributes {
            if attr.required {
                if let Some(values) = attributes.get(&attr.name) {
                    if values.is_empty() || values.iter().all(|v| v.trim().is_empty()) {
                        errors.insert(
                            attr.name.clone(),
                            vec![format!("{} is required", attr.display_name.as_ref().unwrap_or(&attr.name))],
                        );
                    }
                } else {
                    errors.insert(
                        attr.name.clone(),
                        vec![format!("{} is required", attr.display_name.as_ref().unwrap_or(&attr.name))],
                    );
                }
            }

            // Run attribute-specific validations
            if let Some(values) = attributes.get(&attr.name) {
                for validation in &attr.validations {
                    match validation.validator.as_str() {
                        "length" => {
                            if let Some(min_str) = validation.config.get("min") {
                                if let Ok(min) = min_str.parse::<usize>() {
                                    for value in values {
                                        if value.len() < min {
                                            errors.entry(attr.name.clone())
                                                .or_insert_with(Vec::new)
                                                .push(format!("Minimum length is {}", min));
                                        }
                                    }
                                }
                            }
                            if let Some(max_str) = validation.config.get("max") {
                                if let Ok(max) = max_str.parse::<usize>() {
                                    for value in values {
                                        if value.len() > max {
                                            errors.entry(attr.name.clone())
                                                .or_insert_with(Vec::new)
                                                .push(format!("Maximum length is {}", max));
                                        }
                                    }
                                }
                            }
                        }
                        "email" => {
                            for value in values {
                                if !value.contains('@') {
                                    errors.entry(attr.name.clone())
                                        .or_insert_with(Vec::new)
                                        .push("Invalid email format".to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(UserProfileValidationResult {
            is_valid: errors.is_empty(),
            errors,
        })
    }

    async fn create_user_profile_metadata(
        &self,
        _context: UserProfileContext,
    ) -> Result<UserProfileMetadata, UserProfileError> {
        let groups = vec![
            UserProfileGroup {
                name: "basic".to_string(),
                display_name: Some("Basic Information".to_string()),
                display_order: Some(1),
                annotations: HashMap::new(),
            },
            UserProfileGroup {
                name: "personal".to_string(),
                display_name: Some("Personal Information".to_string()),
                display_order: Some(2),
                annotations: HashMap::new(),
            },
        ];

        Ok(UserProfileMetadata {
            attributes: self.attributes.clone(),
            groups,
        })
    }
}

impl Provider for DefaultUserProfileProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Default user profile provider factory
pub struct DefaultUserProfileProviderFactory;

impl DefaultUserProfileProviderFactory {
    /// Create a new default user profile provider factory
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderFactory<dyn UserProfileProvider> for DefaultUserProfileProviderFactory {
    async fn create(
        &self,
        _config: &ProviderConfig,
    ) -> Result<Box<dyn UserProfileProvider>, SpiError> {
        Ok(Box::new(DefaultUserProfileProvider::new()))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

impl UserProfileProviderFactory for DefaultUserProfileProviderFactory {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_user_profile_provider() {
        let provider = DefaultUserProfileProvider::new();

        let attributes = provider
            .get_profile_attributes(UserProfileContext::Registration)
            .await
            .unwrap();

        assert!(!attributes.is_empty());
        assert!(attributes.iter().any(|a| a.name == "username"));
        assert!(attributes.iter().any(|a| a.name == "email"));
    }

    #[tokio::test]
    async fn test_user_profile_validation() {
        let provider = DefaultUserProfileProvider::new();

        // Test valid profile
        let mut valid_attributes = HashMap::new();
        valid_attributes.insert("username".to_string(), vec!["testuser".to_string()]);
        valid_attributes.insert("email".to_string(), vec!["test@example.com".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &valid_attributes)
            .await
            .unwrap();

        assert!(result.is_valid);
        assert!(result.errors.is_empty());

        // Test invalid profile (missing required fields)
        let invalid_attributes = HashMap::new();
        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &invalid_attributes)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.errors.contains_key("username"));
        assert!(result.errors.contains_key("email"));
    }

    #[tokio::test]
    async fn test_user_profile_metadata() {
        let provider = DefaultUserProfileProvider::new();

        let metadata = provider
            .create_user_profile_metadata(UserProfileContext::Registration)
            .await
            .unwrap();

        assert!(!metadata.attributes.is_empty());
        assert!(!metadata.groups.is_empty());
    }
}
