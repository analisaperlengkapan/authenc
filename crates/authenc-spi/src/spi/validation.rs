//! Validation Service Provider Interface
//!
//! Provides comprehensive validation framework with built-in validators.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

/// Validation SPI implementation
pub struct ValidationSpi;

impl Spi for ValidationSpi {
    fn get_name(&self) -> &'static str {
        "validation"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.validate.ValidatorProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.validate.ValidatorProviderFactory"
    }
}

/// Validation context
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// Validator configuration
    pub config: HashMap<String, String>,
    /// Additional context data
    pub attributes: HashMap<String, String>,
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation passed
    pub is_valid: bool,
    /// Error message if validation failed
    pub error_message: Option<String>,
}

/// Validator provider interface
pub trait ValidatorProvider: Provider {
    /// Validate a single value
    fn validate_value(
        &self,
        value: String,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError>;

    /// Validate multiple values
    fn validate_values(
        &self,
        values: Vec<String>,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError>;

    /// Get validator ID
    fn get_id(&self) -> &'static str;

    /// Get validator display name
    fn get_display_name(&self) -> &'static str {
        self.get_id()
    }

    /// Check if validator is configurable
    fn is_configurable(&self) -> bool {
        false
    }

    /// Get configuration properties
    fn get_config_properties(&self) -> Vec<ValidatorConfigProperty> {
        Vec::new()
    }
}

/// Validator configuration property
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfigProperty {
    /// Property name
    pub name: String,
    /// Property label
    pub label: String,
    /// Property type
    pub property_type: ValidatorPropertyType,
    /// Default value
    pub default_value: Option<String>,
    /// Help text
    pub help_text: Option<String>,
}

/// Validator property types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidatorPropertyType {
    /// String property type
    String,
    /// Integer property type
    Integer,
    /// Boolean property type
    Boolean,
}

/// Validator provider factory
pub trait ValidatorProviderFactory: ProviderFactory<dyn ValidatorProvider> {
    /// Get validator ID
    fn get_id(&self) -> &'static str;
}

/// Validation errors
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// Validation configuration error
    #[error("Validation configuration error: {0}")]
    ConfigurationError(String),

    /// Validator not found
    #[error("Validator not found: {0}")]
    ValidatorNotFound(String),

    /// Validation failed
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Built-in validators
pub mod validators {
    use super::*;

    /// Email validator
    pub struct EmailValidator;

    impl ValidatorProvider for EmailValidator {
        fn validate_value(
            &self,
            value: String,
            _context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            // Simple email validation regex
            let email_regex = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
                .map_err(|e| ValidationError::ConfigurationError(e.to_string()))?;

            let is_valid = email_regex.is_match(value.trim());

            Ok(ValidationResult {
                is_valid,
                error_message: if is_valid {
                    None
                } else {
                    Some("Invalid email format".to_string())
                },
            })
        }

        fn validate_values(
            &self,
            values: Vec<String>,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            for value in values {
                let result = self.validate_value(value, context.clone())?;
                if !result.is_valid {
                    return Ok(result);
                }
            }
            Ok(ValidationResult {
                is_valid: true,
                error_message: None,
            })
        }

        fn get_id(&self) -> &'static str {
            "email"
        }

        fn get_display_name(&self) -> &'static str {
            "Email"
        }
    }

    impl Provider for EmailValidator {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// Length validator
    pub struct LengthValidator;

    impl ValidatorProvider for LengthValidator {
        fn validate_value(
            &self,
            value: String,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            let min = context
                .config
                .get("min")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            let max = context
                .config
                .get("max")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(usize::MAX);

            let len = value.len();

            let is_valid = len >= min && len <= max;

            let error_message = if !is_valid {
                if len < min {
                    Some(format!("Value must be at least {} characters long", min))
                } else {
                    Some(format!("Value must be at most {} characters long", max))
                }
            } else {
                None
            };

            Ok(ValidationResult {
                is_valid,
                error_message,
            })
        }

        fn validate_values(
            &self,
            values: Vec<String>,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            for value in values {
                let result = self.validate_value(value, context.clone())?;
                if !result.is_valid {
                    return Ok(result);
                }
            }
            Ok(ValidationResult {
                is_valid: true,
                error_message: None,
            })
        }

        fn get_id(&self) -> &'static str {
            "length"
        }

        fn get_display_name(&self) -> &'static str {
            "Length"
        }

        fn is_configurable(&self) -> bool {
            true
        }

        fn get_config_properties(&self) -> Vec<ValidatorConfigProperty> {
            vec![
                ValidatorConfigProperty {
                    name: "min".to_string(),
                    label: "Minimum Length".to_string(),
                    property_type: ValidatorPropertyType::Integer,
                    default_value: Some("0".to_string()),
                    help_text: Some("Minimum number of characters".to_string()),
                },
                ValidatorConfigProperty {
                    name: "max".to_string(),
                    label: "Maximum Length".to_string(),
                    property_type: ValidatorPropertyType::Integer,
                    default_value: None,
                    help_text: Some("Maximum number of characters".to_string()),
                },
            ]
        }
    }

    impl Provider for LengthValidator {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// Pattern validator (regex)
    pub struct PatternValidator;

    impl ValidatorProvider for PatternValidator {
        fn validate_value(
            &self,
            value: String,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            let pattern = context.config.get("pattern").ok_or_else(|| {
                ValidationError::ConfigurationError("Pattern is required".to_string())
            })?;

            let regex = Regex::new(pattern).map_err(|e| {
                ValidationError::ConfigurationError(format!("Invalid regex pattern: {}", e))
            })?;

            let is_valid = regex.is_match(&value);

            Ok(ValidationResult {
                is_valid,
                error_message: if is_valid {
                    None
                } else {
                    Some("Value does not match required pattern".to_string())
                },
            })
        }

        fn validate_values(
            &self,
            values: Vec<String>,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            for value in values {
                let result = self.validate_value(value, context.clone())?;
                if !result.is_valid {
                    return Ok(result);
                }
            }
            Ok(ValidationResult {
                is_valid: true,
                error_message: None,
            })
        }

        fn get_id(&self) -> &'static str {
            "pattern"
        }

        fn get_display_name(&self) -> &'static str {
            "Pattern"
        }

        fn is_configurable(&self) -> bool {
            true
        }

        fn get_config_properties(&self) -> Vec<ValidatorConfigProperty> {
            vec![ValidatorConfigProperty {
                name: "pattern".to_string(),
                label: "Regular Expression".to_string(),
                property_type: ValidatorPropertyType::String,
                default_value: None,
                help_text: Some("Regular expression pattern to match".to_string()),
            }]
        }
    }

    impl Provider for PatternValidator {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// URI validator
    pub struct UriValidator;

    impl ValidatorProvider for UriValidator {
        fn validate_value(
            &self,
            value: String,
            _context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            let is_valid = url::Url::parse(&value).is_ok();

            Ok(ValidationResult {
                is_valid,
                error_message: if is_valid {
                    None
                } else {
                    Some("Invalid URI format".to_string())
                },
            })
        }

        fn validate_values(
            &self,
            values: Vec<String>,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            for value in values {
                let result = self.validate_value(value, context.clone())?;
                if !result.is_valid {
                    return Ok(result);
                }
            }
            Ok(ValidationResult {
                is_valid: true,
                error_message: None,
            })
        }

        fn get_id(&self) -> &'static str {
            "uri"
        }

        fn get_display_name(&self) -> &'static str {
            "URI"
        }
    }

    impl Provider for UriValidator {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// Not blank validator
    pub struct NotBlankValidator;

    impl ValidatorProvider for NotBlankValidator {
        fn validate_value(
            &self,
            value: String,
            _context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            let is_valid = !value.trim().is_empty();

            Ok(ValidationResult {
                is_valid,
                error_message: if is_valid {
                    None
                } else {
                    Some("Value cannot be blank".to_string())
                },
            })
        }

        fn validate_values(
            &self,
            values: Vec<String>,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            for value in values {
                let result = self.validate_value(value, context.clone())?;
                if !result.is_valid {
                    return Ok(result);
                }
            }
            Ok(ValidationResult {
                is_valid: true,
                error_message: None,
            })
        }

        fn get_id(&self) -> &'static str {
            "notBlank"
        }

        fn get_display_name(&self) -> &'static str {
            "Not Blank"
        }
    }

    impl Provider for NotBlankValidator {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    /// Not empty validator
    pub struct NotEmptyValidator;

    impl ValidatorProvider for NotEmptyValidator {
        fn validate_value(
            &self,
            value: String,
            _context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            let is_valid = !value.is_empty();

            Ok(ValidationResult {
                is_valid,
                error_message: if is_valid {
                    None
                } else {
                    Some("Value cannot be empty".to_string())
                },
            })
        }

        fn validate_values(
            &self,
            values: Vec<String>,
            context: ValidationContext,
        ) -> Result<ValidationResult, ValidationError> {
            for value in values {
                let result = self.validate_value(value, context.clone())?;
                if !result.is_valid {
                    return Ok(result);
                }
            }
            Ok(ValidationResult {
                is_valid: true,
                error_message: None,
            })
        }

        fn get_id(&self) -> &'static str {
            "notEmpty"
        }

        fn get_display_name(&self) -> &'static str {
            "Not Empty"
        }
    }

    impl Provider for NotEmptyValidator {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }
}

/// Default validation provider factory
pub struct DefaultValidationProviderFactory;

impl Default for DefaultValidationProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultValidationProviderFactory {
    /// Create a new default validation provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn ValidatorProvider> for DefaultValidationProviderFactory {
    fn create(&self, _config: &ProviderConfig) -> Result<Box<dyn ValidatorProvider>, SpiError> {
        // Return a composite validator that includes all built-in validators
        Ok(Box::new(CompositeValidatorProvider::new()))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

impl ValidatorProviderFactory for DefaultValidationProviderFactory {
    fn get_id(&self) -> &'static str {
        "default"
    }
}

/// Composite validator provider that includes all built-in validators
pub struct CompositeValidatorProvider {
    validators: HashMap<String, Box<dyn ValidatorProvider>>,
}

impl Default for CompositeValidatorProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositeValidatorProvider {
    /// Create a new composite validator provider
    pub fn new() -> Self {
        let mut validators = HashMap::new();

        validators.insert(
            "email".to_string(),
            Box::new(validators::EmailValidator) as Box<dyn ValidatorProvider>,
        );
        validators.insert(
            "length".to_string(),
            Box::new(validators::LengthValidator) as Box<dyn ValidatorProvider>,
        );
        validators.insert(
            "pattern".to_string(),
            Box::new(validators::PatternValidator) as Box<dyn ValidatorProvider>,
        );
        validators.insert(
            "uri".to_string(),
            Box::new(validators::UriValidator) as Box<dyn ValidatorProvider>,
        );
        validators.insert(
            "notBlank".to_string(),
            Box::new(validators::NotBlankValidator) as Box<dyn ValidatorProvider>,
        );
        validators.insert(
            "notEmpty".to_string(),
            Box::new(validators::NotEmptyValidator) as Box<dyn ValidatorProvider>,
        );

        Self { validators }
    }

    /// Get a validator by ID
    pub fn get_validator(&self, id: &str) -> Option<&dyn ValidatorProvider> {
        self.validators.get(id).map(|v| v.as_ref())
    }
}

impl ValidatorProvider for CompositeValidatorProvider {
    fn validate_value(
        &self,
        _value: String,
        _context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        // This is a composite provider, validation should be done by individual validators
        Err(ValidationError::ValidationFailed(
            "Use individual validators for validation".to_string(),
        ))
    }

    fn validate_values(
        &self,
        _values: Vec<String>,
        _context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        Err(ValidationError::ValidationFailed(
            "Use individual validators for validation".to_string(),
        ))
    }

    fn get_id(&self) -> &'static str {
        "composite"
    }

    fn get_display_name(&self) -> &'static str {
        "Composite Validator"
    }
}

impl Provider for CompositeValidatorProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validator() {
        let validator = validators::EmailValidator;
        let context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        let result = validator
            .validate_value("test@example.com".to_string(), context.clone())
            .unwrap();
        assert!(result.is_valid);

        let result = validator
            .validate_value("invalid-email".to_string(), context.clone())
            .unwrap();
        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_length_validator() {
        let validator = validators::LengthValidator;
        let mut context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        context.config.insert("min".to_string(), "3".to_string());
        context.config.insert("max".to_string(), "10".to_string());

        let result = validator
            .validate_value("test".to_string(), context.clone())
            .unwrap();
        assert!(result.is_valid);

        let result = validator
            .validate_value("hi".to_string(), context.clone())
            .unwrap();
        assert!(!result.is_valid);

        let result = validator
            .validate_value("thisisaverylongstring".to_string(), context.clone())
            .unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_pattern_validator() {
        let validator = validators::PatternValidator;
        let mut context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        context
            .config
            .insert("pattern".to_string(), r"^\d{3}-\d{2}-\d{4}$".to_string());

        let result = validator
            .validate_value("123-45-6789".to_string(), context.clone())
            .unwrap();
        assert!(result.is_valid);

        let result = validator
            .validate_value("invalid".to_string(), context.clone())
            .unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_composite_validator_provider() {
        let provider = CompositeValidatorProvider::new();

        assert!(provider.get_validator("email").is_some());
        assert!(provider.get_validator("length").is_some());
        assert!(provider.get_validator("nonexistent").is_none());
    }
}
