use std::collections::HashMap;

use authenc::spi::userprofile::{
    UserProfileProvider, UserProfileProviderFactory, DefaultUserProfileProvider,
    DefaultUserProfileProviderFactory, UserProfileAttribute, AttributeType,
    AttributeValidation, UserProfileContext, UserProfileValidationResult,
    UserProfileMetadata, UserProfileGroup, UserProfileError,
};
use authenc::spi::ProviderFactory;

/// Mock user profile provider for testing custom scenarios
#[derive(Debug)]
struct MockUserProfileProvider {
    attributes: Vec<UserProfileAttribute>,
}

impl MockUserProfileProvider {
    fn new() -> Self {
        let mut attributes = Vec::new();

        // Add a custom attribute for testing
        attributes.push(UserProfileAttribute {
            name: "custom_field".to_string(),
            display_name: Some("Custom Field".to_string()),
            attribute_type: AttributeType::Text,
            required: false,
            read_only: false,
            validations: vec![AttributeValidation {
                validator: "length".to_string(),
                config: {
                    let mut config = HashMap::new();
                    config.insert("max".to_string(), "100".to_string());
                    config
                },
            }],
            group: Some("custom".to_string()),
            display_order: Some(1),
            annotations: HashMap::new(),
        });

        Self { attributes }
    }
}

#[async_trait::async_trait]
impl UserProfileProvider for MockUserProfileProvider {
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
        let groups = vec![UserProfileGroup {
            name: "custom".to_string(),
            display_name: Some("Custom Fields".to_string()),
            display_order: Some(1),
            annotations: HashMap::new(),
        }];

        Ok(UserProfileMetadata {
            attributes: self.attributes.clone(),
            groups,
        })
    }
}

impl authenc::spi::Provider for MockUserProfileProvider {
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
    async fn test_default_user_profile_provider_attributes() {
        let provider = DefaultUserProfileProvider::new();

        // Test getting attributes for different contexts
        let registration_attrs = provider
            .get_profile_attributes(UserProfileContext::Registration)
            .await
            .unwrap();

        let update_attrs = provider
            .get_profile_attributes(UserProfileContext::UpdateProfile)
            .await
            .unwrap();

        let account_attrs = provider
            .get_profile_attributes(UserProfileContext::Account)
            .await
            .unwrap();

        // All contexts should return the same attributes for default provider
        assert_eq!(registration_attrs.len(), update_attrs.len());
        assert_eq!(update_attrs.len(), account_attrs.len());

        // Check that required attributes are present
        assert!(registration_attrs.iter().any(|a| a.name == "username"));
        assert!(registration_attrs.iter().any(|a| a.name == "email"));
        assert!(registration_attrs.iter().any(|a| a.name == "firstName"));
        assert!(registration_attrs.iter().any(|a| a.name == "lastName"));

        // Verify username attribute properties
        let username_attr = registration_attrs.iter().find(|a| a.name == "username").unwrap();
        assert_eq!(username_attr.attribute_type, AttributeType::Text);
        assert!(username_attr.required);
        assert!(!username_attr.read_only);
        assert_eq!(username_attr.group, Some("basic".to_string()));
        assert_eq!(username_attr.display_order, Some(1));

        // Verify email attribute properties
        let email_attr = registration_attrs.iter().find(|a| a.name == "email").unwrap();
        assert_eq!(email_attr.attribute_type, AttributeType::Email);
        assert!(email_attr.required);
        assert!(!email_attr.read_only);
        assert_eq!(email_attr.group, Some("basic".to_string()));
        assert_eq!(email_attr.display_order, Some(2));
    }

    #[tokio::test]
    async fn test_user_profile_validation_success() {
        let provider = DefaultUserProfileProvider::new();

        // Test valid profile with all required fields
        let mut valid_attributes = HashMap::new();
        valid_attributes.insert("username".to_string(), vec!["testuser".to_string()]);
        valid_attributes.insert("email".to_string(), vec!["test@example.com".to_string()]);
        valid_attributes.insert("firstName".to_string(), vec!["John".to_string()]);
        valid_attributes.insert("lastName".to_string(), vec!["Doe".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &valid_attributes)
            .await
            .unwrap();

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_user_profile_validation_missing_required() {
        let provider = DefaultUserProfileProvider::new();

        // Test missing required fields
        let mut invalid_attributes = HashMap::new();
        invalid_attributes.insert("firstName".to_string(), vec!["John".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &invalid_attributes)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.errors.contains_key("username"));
        assert!(result.errors.contains_key("email"));
        assert!(!result.errors.contains_key("firstName")); // Not required
        assert!(!result.errors.contains_key("lastName")); // Not required
    }

    #[tokio::test]
    async fn test_user_profile_validation_length_constraints() {
        let provider = DefaultUserProfileProvider::new();

        // Test username too short
        let mut invalid_attributes = HashMap::new();
        invalid_attributes.insert("username".to_string(), vec!["ab".to_string()]); // Less than min 3
        invalid_attributes.insert("email".to_string(), vec!["test@example.com".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &invalid_attributes)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.errors.contains_key("username"));
        assert!(result.errors["username"].iter().any(|e| e.contains("Minimum length")));

        // Test valid length
        invalid_attributes.insert("username".to_string(), vec!["abc".to_string()]); // Exactly min 3

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &invalid_attributes)
            .await
            .unwrap();

        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_user_profile_validation_email_format() {
        let provider = DefaultUserProfileProvider::new();

        // Test invalid email
        let mut invalid_attributes = HashMap::new();
        invalid_attributes.insert("username".to_string(), vec!["testuser".to_string()]);
        invalid_attributes.insert("email".to_string(), vec!["invalid-email".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &invalid_attributes)
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.errors.contains_key("email"));
        assert!(result.errors["email"].iter().any(|e| e.contains("Invalid email format")));

        // Test valid email
        invalid_attributes.insert("email".to_string(), vec!["valid@example.com".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &invalid_attributes)
            .await
            .unwrap();

        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_user_profile_metadata() {
        let provider = DefaultUserProfileProvider::new();

        let metadata = provider
            .create_user_profile_metadata(UserProfileContext::Registration)
            .await
            .unwrap();

        // Check attributes
        assert!(!metadata.attributes.is_empty());
        assert_eq!(metadata.attributes.len(), 4); // username, email, firstName, lastName

        // Check groups
        assert!(!metadata.groups.is_empty());
        assert_eq!(metadata.groups.len(), 2); // basic and personal

        // Verify group properties
        let basic_group = metadata.groups.iter().find(|g| g.name == "basic").unwrap();
        assert_eq!(basic_group.display_name, Some("Basic Information".to_string()));
        assert_eq!(basic_group.display_order, Some(1));

        let personal_group = metadata.groups.iter().find(|g| g.name == "personal").unwrap();
        assert_eq!(personal_group.display_name, Some("Personal Information".to_string()));
        assert_eq!(personal_group.display_order, Some(2));
    }

    #[tokio::test]
    async fn test_mock_user_profile_provider() {
        let provider = MockUserProfileProvider::new();

        // Test getting attributes
        let attributes = provider
            .get_profile_attributes(UserProfileContext::Registration)
            .await
            .unwrap();

        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].name, "custom_field");
        assert_eq!(attributes[0].attribute_type, AttributeType::Text);
        assert!(!attributes[0].required);

        // Test validation with optional field
        let empty_attributes = HashMap::new();
        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &empty_attributes)
            .await
            .unwrap();

        assert!(result.is_valid); // No required fields in mock

        // Test metadata
        let metadata = provider
            .create_user_profile_metadata(UserProfileContext::Registration)
            .await
            .unwrap();

        assert_eq!(metadata.attributes.len(), 1);
        assert_eq!(metadata.groups.len(), 1);
        assert_eq!(metadata.groups[0].name, "custom");
    }

    #[tokio::test]
    async fn test_user_profile_provider_factory() {
        let factory = DefaultUserProfileProviderFactory::new();

        // Test factory ID
        assert_eq!(factory.get_id(), "default");

        // Test provider creation
        let config = authenc::spi::ProviderConfig {
            properties: HashMap::new(),
            global_config: None,
        };

        let provider = factory.create(&config).await.unwrap();

        // Test that the provider works
        let attributes = provider
            .get_profile_attributes(UserProfileContext::Registration)
            .await
            .unwrap();

        assert!(!attributes.is_empty());

        // Test factory priority
        assert_eq!(UserProfileProviderFactory::get_priority(&factory), 0);
    }

    #[tokio::test]
    async fn test_attribute_types() {
        // Test that all attribute types are properly defined
        let _text: AttributeType = AttributeType::Text;
        let _email: AttributeType = AttributeType::Email;
        let _url: AttributeType = AttributeType::Url;
        let _number: AttributeType = AttributeType::Number;
        let _date: AttributeType = AttributeType::Date;
        let _select: AttributeType = AttributeType::Select;
        let _multiselect: AttributeType = AttributeType::Multiselect;
        let _boolean: AttributeType = AttributeType::Boolean;
        let _file: AttributeType = AttributeType::File;
    }

    #[tokio::test]
    async fn test_user_profile_contexts() {
        // Test that all contexts are properly defined
        let _registration: UserProfileContext = UserProfileContext::Registration;
        let _update_profile: UserProfileContext = UserProfileContext::UpdateProfile;
        let _idp_review: UserProfileContext = UserProfileContext::IdpReview;
        let _account: UserProfileContext = UserProfileContext::Account;
        let _user_api: UserProfileContext = UserProfileContext::UserApi;
    }

    #[tokio::test]
    async fn test_user_profile_validation_multiple_values() {
        let provider = DefaultUserProfileProvider::new();

        // Test validation with multiple values for an attribute
        let mut attributes = HashMap::new();
        attributes.insert("username".to_string(), vec!["testuser".to_string()]);
        attributes.insert("email".to_string(), vec!["test@example.com".to_string(), "another@example.com".to_string()]);

        let result = provider
            .validate_user_profile(UserProfileContext::Registration, &attributes)
            .await
            .unwrap();

        // Should still be valid as email validation doesn't check for uniqueness
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_user_profile_attribute_validation_config() {
        let provider = DefaultUserProfileProvider::new();

        let attributes = provider
            .get_profile_attributes(UserProfileContext::Registration)
            .await
            .unwrap();

        // Check username validation config
        let username_attr = attributes.iter().find(|a| a.name == "username").unwrap();
        assert!(!username_attr.validations.is_empty());

        let length_validation = username_attr.validations.iter()
            .find(|v| v.validator == "length")
            .unwrap();

        assert_eq!(length_validation.config.get("min"), Some(&"3".to_string()));
        assert_eq!(length_validation.config.get("max"), Some(&"255".to_string()));

        // Check email validation config
        let email_attr = attributes.iter().find(|a| a.name == "email").unwrap();
        let email_validation = email_attr.validations.iter()
            .find(|v| v.validator == "email")
            .unwrap();

        assert!(email_validation.config.is_empty()); // Email validator doesn't need config
    }

    #[tokio::test]
    async fn test_user_profile_error_types() {
        // Test that error types are properly defined
        let validation_error = UserProfileError::ValidationFailed("test".to_string());
        let attribute_error = UserProfileError::AttributeNotFound("test".to_string());
        let value_error = UserProfileError::InvalidAttributeValue("test".to_string());
        let config_error = UserProfileError::ConfigurationError("test".to_string());
        let context_error = UserProfileError::UnsupportedContext(UserProfileContext::Registration);

        // Test error messages
        assert!(validation_error.to_string().contains("validation failed"));
        assert!(attribute_error.to_string().contains("not found"));
        assert!(value_error.to_string().contains("Invalid attribute value"));
        assert!(config_error.to_string().contains("Configuration error"));
        assert!(context_error.to_string().contains("not supported"));
    }
}
