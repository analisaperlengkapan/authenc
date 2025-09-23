use std::collections::HashMap;

use authenc::spi::validation::{
    ValidatorProvider, ValidatorProviderFactory, CompositeValidatorProvider,
    DefaultValidationProviderFactory, ValidationContext, ValidationResult,
    ValidationError, ValidatorConfigProperty, ValidatorPropertyType,
};
use authenc::spi::ProviderFactory;

/// Mock validation provider for testing custom scenarios
#[derive(Debug)]
struct MockValidatorProvider {
    validators: std::collections::HashMap<String, ValidatorConfigProperty>,
}

impl MockValidatorProvider {
    fn new() -> Self {
        let mut validators = std::collections::HashMap::new();

        // Add a custom validator for testing
        validators.insert(
            "custom_length".to_string(),
            ValidatorConfigProperty {
                name: "custom_length".to_string(),
                label: "Custom Length".to_string(),
                property_type: ValidatorPropertyType::String,
                default_value: None,
                help_text: Some("Custom length validator".to_string()),
            },
        );

        Self { validators }
    }
}

#[async_trait::async_trait]
impl ValidatorProvider for MockValidatorProvider {
    async fn validate_value(
        &self,
        value: &str,
        context: &ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        if let Some(config) = context.config.get("min") {
            if let Ok(min) = config.parse::<usize>() {
                if value.len() < min {
                    return Ok(ValidationResult {
                        is_valid: false,
                        error_message: Some(format!("Value too short, minimum length is {}", min)),
                    });
                }
            }
        }

        if let Some(config) = context.config.get("max") {
            if let Ok(max) = config.parse::<usize>() {
                if value.len() > max {
                    return Ok(ValidationResult {
                        is_valid: false,
                        error_message: Some(format!("Value too long, maximum length is {}", max)),
                    });
                }
            }
        }

        Ok(ValidationResult {
            is_valid: true,
            error_message: None,
        })
    }

    fn get_id(&self) -> &'static str {
        "mock"
    }

    fn get_config_properties(&self) -> Vec<ValidatorConfigProperty> {
        self.validators.values().cloned().collect()
    }
}

impl authenc::spi::Provider for MockValidatorProvider {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_validation_provider() {
        let provider = MockValidatorProvider::new();

        // Test custom length validator - valid
        let context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("min".to_string(), "3".to_string());
                config.insert("max".to_string(), "10".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = provider
            .validate_value("valid", &context)
            .await
            .unwrap();

        assert!(result.is_valid);

        // Test custom length validator - too short
        let result = provider
            .validate_value("x", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.error_message.is_some());

        // Test custom length validator - too long
        let result = provider
            .validate_value("thisiswaytoolong", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_default_validation_provider_validators() {
        let provider = CompositeValidatorProvider::new();

        // Test that the provider has validators
        assert!(provider.get_validator("email").is_some());
        assert!(provider.get_validator("length").is_some());
        assert!(provider.get_validator("pattern").is_some());
    }

    #[tokio::test]
    async fn test_validation_length_validator() {
        let provider = CompositeValidatorProvider::new();
        let length_validator = provider.get_validator("length").unwrap();

        // Test valid length
        let context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("min".to_string(), "3".to_string());
                config.insert("max".to_string(), "10".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = length_validator
            .validate_value("valid", &context)
            .await
            .unwrap();

        assert!(result.is_valid);

        // Test too short
        let result = length_validator
            .validate_value("x", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.error_message.is_some());

        // Test too long
        let result = length_validator
            .validate_value("thisiswaytoolong", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_validation_email_validator() {
        let provider = CompositeValidatorProvider::new();
        let email_validator = provider.get_validator("email").unwrap();

        // Test valid email
        let context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        let result = email_validator
            .validate_value("test@example.com", &context)
            .await
            .unwrap();

        assert!(result.is_valid);

        // Test invalid email
        let result = email_validator
            .validate_value("invalid-email", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_validation_pattern_validator() {
        let provider = CompositeValidatorProvider::new();
        let pattern_validator = provider.get_validator("pattern").unwrap();

        // Test valid pattern
        let context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("pattern".to_string(), r"^\d{3}-\d{2}-\d{4}$".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = pattern_validator
            .validate_value("123-45-6789", &context)
            .await
            .unwrap();

        assert!(result.is_valid);

        // Test invalid pattern
        let result = pattern_validator
            .validate_value("invalid", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_validation_contexts() {
        let provider = CompositeValidatorProvider::new();
        let length_validator = provider.get_validator("length").unwrap();

        // Test different contexts work
        let context1 = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("min".to_string(), "1".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = length_validator
            .validate_value("test", &context1)
            .await
            .unwrap();

        assert!(result.is_valid);

        let context2 = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("min".to_string(), "10".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = length_validator
            .validate_value("test", &context2)
            .await
            .unwrap();

        assert!(!result.is_valid);
    }

    #[tokio::test]
    async fn test_validation_error_types() {
        let provider = CompositeValidatorProvider::new();
        let pattern_validator = provider.get_validator("pattern").unwrap();

        // Test configuration error (missing pattern)
        let context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        let result = pattern_validator
            .validate_value("test", &context)
            .await;

        assert!(matches!(result, Err(ValidationError::ConfigurationError(_))));

        // Test invalid regex pattern
        let context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("pattern".to_string(), "[invalid".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = pattern_validator
            .validate_value("test", &context)
            .await;

        assert!(matches!(result, Err(ValidationError::ConfigurationError(_))));
    }

    #[tokio::test]
    async fn test_validation_provider_factory() {
        let mut factory = DefaultValidationProviderFactory::new();

        // Test factory creation
        let config = authenc::spi::ProviderConfig::default();
        let provider = factory.create(&config).await.unwrap();

        // Test factory priority
        assert_eq!(factory.get_priority(), 0);

        // Test factory ID
        assert_eq!(ValidatorProviderFactory::get_id(&factory), "default");
    }

    #[tokio::test]
    async fn test_validator_config_retrieval() {
        let provider = CompositeValidatorProvider::new();
        let length_validator = provider.get_validator("length").unwrap();

        // Test getting config properties for known validator
        let config_props = length_validator.get_config_properties();
        assert!(!config_props.is_empty());

        let min_prop = config_props.iter().find(|p| p.name == "min").unwrap();
        assert_eq!(min_prop.property_type, ValidatorPropertyType::Integer);
        assert_eq!(min_prop.default_value, Some("0".to_string()));

        // Test getting config properties for non-configurable validator
        let email_validator = provider.get_validator("email").unwrap();
        let config_props = email_validator.get_config_properties();
        assert!(config_props.is_empty());
    }

    #[tokio::test]
    async fn test_validation_numeric_constraints() {
        let provider = CompositeValidatorProvider::new();

        // Test integer validation if available (notBlank validator uses string validation)
        let not_blank_validator = provider.get_validator("notBlank").unwrap();

        let context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        // Test valid non-blank
        let result = not_blank_validator
            .validate_value("not blank", &context)
            .await
            .unwrap();

        assert!(result.is_valid);

        // Test blank (should fail)
        let result = not_blank_validator
            .validate_value("", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);

        // Test whitespace only (should fail)
        let result = not_blank_validator
            .validate_value("   ", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
    }

    #[tokio::test]
    async fn test_validation_edge_cases() {
        let provider = CompositeValidatorProvider::new();
        let length_validator = provider.get_validator("length").unwrap();

        // Test empty string
        let context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("min".to_string(), "1".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = length_validator
            .validate_value("", &context)
            .await
            .unwrap();

        assert!(!result.is_valid);

        // Test very long string
        let long_string = "a".repeat(10000);
        let context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("max".to_string(), "100".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let result = length_validator
            .validate_value(&long_string, &context)
            .await
            .unwrap();

        assert!(!result.is_valid);
    }

    #[tokio::test]
    async fn test_validation_provider_multiple_validators() {
        let provider = CompositeValidatorProvider::new();

        // Test multiple validators on same value
        let length_context = ValidationContext {
            config: {
                let mut config = HashMap::new();
                config.insert("min".to_string(), "5".to_string());
                config.insert("max".to_string(), "50".to_string());
                config
            },
            attributes: HashMap::new(),
        };

        let email_context = ValidationContext {
            config: HashMap::new(),
            attributes: HashMap::new(),
        };

        let length_validator = provider.get_validator("length").unwrap();
        let email_validator = provider.get_validator("email").unwrap();

        let test_value = "validemail@test.com";

        // First validate length
        let result = length_validator
            .validate_value(test_value, &length_context)
            .await
            .unwrap();

        assert!(result.is_valid);

        // Then validate email format
        let result = email_validator
            .validate_value(test_value, &email_context)
            .await
            .unwrap();

        assert!(result.is_valid);
    }
}
