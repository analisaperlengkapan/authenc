use std::collections::HashMap;
use std::sync::Arc;

use authenc::models::user::User;
use authenc::spi::authenticator::{
    AuthenticationContext, AuthenticationFlowType, Authenticator, AuthenticatorConfig,
    AuthenticatorProvider, AuthenticatorType, DefaultAuthenticatorProvider,
    DefaultAuthenticatorProviderFactory, OTPAuthenticator, UsernamePasswordAuthenticator,
};
use authenc::spi::ProviderFactory;
use uuid::Uuid;

/// Mock user for testing
fn create_mock_user() -> Arc<User> {
    Arc::new(User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        email_verified: false,
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        phone_number: Some("+1234567890".to_string()),
        phone_verified: false,
        password_hash: None,
        totp_secret: None,
        totp_backup_codes: None,
        webauthn_enabled: false,
        account_locked: false,
        account_locked_until: None,
        failed_login_attempts: 0,
        last_login_at: None,
        last_failed_login_at: None,
        password_changed_at: None,
        password_expires_at: None,
        require_password_change: false,
        realm_id: Some(Uuid::new_v4()),
        organization_id: None,
        attributes: None,
        enabled: true,
        federated: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deleted_at: None,
        login_count: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_username_password_authenticator() {
        let config = AuthenticatorConfig {
            id: "test-username-password".to_string(),
            name: "Test Username Password".to_string(),
            authenticator_type: AuthenticatorType::UsernamePassword,
            priority: 10,
            required: true,
            enabled: true,
            config: HashMap::new(),
        };

        let authenticator = UsernamePasswordAuthenticator::new(config.clone());

        // Test configuration
        assert_eq!(authenticator.get_config().id, "test-username-password");
        assert_eq!(
            authenticator.get_authenticator_type(),
            AuthenticatorType::UsernamePassword
        );

        // Test successful authentication
        let mut context = AuthenticationContext {
            realm_id: "test-realm".to_string(),
            client_id: "test-client".to_string(),
            user: Some(create_mock_user()),
            flow_type: AuthenticationFlowType::Browser,
            parameters: HashMap::from([
                ("username".to_string(), "testuser".to_string()),
                ("password".to_string(), "password123".to_string()),
            ]),
            session_data: HashMap::new(),
            current_step: None,
        };

        let result = authenticator.authenticate(&context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.authenticator_type,
            AuthenticatorType::UsernamePassword
        );
        assert!(result.error_message.is_none());

        // Test failed authentication (missing password)
        context.parameters.remove("password");
        let result = authenticator.authenticate(&context).await.unwrap();
        assert!(!result.success);
        assert_eq!(
            result.error_message,
            Some("Username and password required".to_string())
        );

        // Test is_configured_for
        assert!(authenticator.is_configured_for(&context));
    }

    #[tokio::test]
    async fn test_otp_authenticator() {
        let config = AuthenticatorConfig {
            id: "test-otp".to_string(),
            name: "Test OTP".to_string(),
            authenticator_type: AuthenticatorType::OTP,
            priority: 20,
            required: false,
            enabled: true,
            config: HashMap::new(),
        };

        let authenticator = OTPAuthenticator::new(config.clone());

        // Test configuration
        assert_eq!(authenticator.get_config().id, "test-otp");
        assert_eq!(
            authenticator.get_authenticator_type(),
            AuthenticatorType::OTP
        );

        // Test successful authentication
        let context = AuthenticationContext {
            realm_id: "test-realm".to_string(),
            client_id: "test-client".to_string(),
            user: Some(create_mock_user()),
            flow_type: AuthenticationFlowType::Browser,
            parameters: HashMap::from([("otp".to_string(), "123456".to_string())]),
            session_data: HashMap::new(),
            current_step: None,
        };

        let result = authenticator.authenticate(&context).await.unwrap();
        assert!(result.success);
        assert_eq!(result.authenticator_type, AuthenticatorType::OTP);
        assert!(result.error_message.is_none());

        // Test failed authentication (missing OTP)
        let mut context_no_otp_params = context.parameters.clone();
        context_no_otp_params.remove("otp");
        let context_no_otp = AuthenticationContext {
            parameters: context_no_otp_params,
            ..context.clone()
        };

        let result = authenticator.authenticate(&context_no_otp).await.unwrap();
        assert!(!result.success);
        assert_eq!(result.error_message, Some("OTP code required".to_string()));

        // Test is_configured_for
        assert!(authenticator.is_configured_for(&context));
    }

    #[tokio::test]
    async fn test_default_authenticator_provider() {
        let provider = DefaultAuthenticatorProvider::new();

        // Test get_authenticators
        let authenticators = provider.get_authenticators().await.unwrap();
        assert_eq!(authenticators.len(), 2); // UsernamePassword and OTP

        // Check first authenticator (UsernamePassword)
        let username_auth = &authenticators[0];
        assert_eq!(
            username_auth.get_config().authenticator_type,
            AuthenticatorType::UsernamePassword
        );
        assert_eq!(username_auth.get_config().id, "username-password");

        // Check second authenticator (OTP)
        let otp_auth = &authenticators[1];
        assert_eq!(
            otp_auth.get_config().authenticator_type,
            AuthenticatorType::OTP
        );
        assert_eq!(otp_auth.get_config().id, "otp");

        // Test get_authenticator by ID
        let found_auth = provider
            .get_authenticator("username-password")
            .await
            .unwrap();
        assert!(found_auth.is_some());
        assert_eq!(found_auth.unwrap().get_config().id, "username-password");

        let not_found = provider.get_authenticator("nonexistent").await.unwrap();
        assert!(not_found.is_none());

        // Test get_authenticators_for_flow
        let browser_auths = provider
            .get_authenticators_for_flow(AuthenticationFlowType::Browser)
            .await
            .unwrap();
        assert_eq!(browser_auths.len(), 2);

        let direct_grant_auths = provider
            .get_authenticators_for_flow(AuthenticationFlowType::DirectGrant)
            .await
            .unwrap();
        assert_eq!(direct_grant_auths.len(), 2);

        // Test create_authentication_context
        let context = provider.create_authentication_context(
            "test-realm",
            "test-client",
            AuthenticationFlowType::Browser,
            HashMap::from([("username".to_string(), "testuser".to_string())]),
        );

        assert_eq!(context.realm_id, "test-realm");
        assert_eq!(context.client_id, "test-client");
        assert_eq!(context.flow_type, AuthenticationFlowType::Browser);
        assert_eq!(
            context.parameters.get("username"),
            Some(&"testuser".to_string())
        );
    }

    #[tokio::test]
    async fn test_authenticator_provider_factory() {
        let factory = DefaultAuthenticatorProviderFactory::new();

        // Test factory ID
        assert_eq!(factory.get_id(), "default-authenticator");

        // Test provider creation
        let config = authenc::spi::ProviderConfig {
            properties: HashMap::new(),
            global_config: None,
        };

        let provider = factory.create(&config).unwrap();
        // Note: Provider trait doesn't have get_id(), that's on ProviderFactory
        // We can test that the provider was created successfully

        // Test init
        let mut factory = DefaultAuthenticatorProviderFactory::new();
        factory.init(&config).unwrap(); // Should not panic
    }

    #[tokio::test]
    async fn test_authentication_flow_integration() {
        let provider = DefaultAuthenticatorProvider::new();

        // Create authentication context for browser flow
        let mut context = provider.create_authentication_context(
            "test-realm",
            "test-client",
            AuthenticationFlowType::Browser,
            HashMap::from([
                ("username".to_string(), "testuser".to_string()),
                ("password".to_string(), "password123".to_string()),
            ]),
        );

        // Get authenticators for this flow
        let authenticators = provider
            .get_authenticators_for_flow(AuthenticationFlowType::Browser)
            .await
            .unwrap();

        // Test authentication with username/password authenticator
        let username_auth = authenticators
            .iter()
            .find(|a| a.get_authenticator_type() == AuthenticatorType::UsernamePassword)
            .unwrap();

        let result = username_auth.authenticate(&context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.authenticator_type,
            AuthenticatorType::UsernamePassword
        );

        // Test with OTP authenticator (add OTP parameter)
        context
            .parameters
            .insert("otp".to_string(), "123456".to_string());
        let otp_auth = authenticators
            .iter()
            .find(|a| a.get_authenticator_type() == AuthenticatorType::OTP)
            .unwrap();

        let result = otp_auth.authenticate(&context).await.unwrap();
        assert!(result.success);
        assert_eq!(result.authenticator_type, AuthenticatorType::OTP);
    }

    #[tokio::test]
    async fn test_authenticator_config_validation() {
        // Test authenticator configuration
        let config = AuthenticatorConfig {
            id: "test-auth".to_string(),
            name: "Test Authenticator".to_string(),
            authenticator_type: AuthenticatorType::UsernamePassword,
            priority: 5,
            required: true,
            enabled: true,
            config: HashMap::from([
                ("max_attempts".to_string(), "3".to_string()),
                ("lockout_duration".to_string(), "300".to_string()),
            ]),
        };

        let authenticator = UsernamePasswordAuthenticator::new(config.clone());

        // Verify configuration is stored correctly
        let stored_config = authenticator.get_config();
        assert_eq!(stored_config.id, "test-auth");
        assert_eq!(stored_config.name, "Test Authenticator");
        assert_eq!(stored_config.priority, 5);
        assert!(stored_config.required);
        assert!(stored_config.enabled);
        assert_eq!(
            stored_config.config.get("max_attempts"),
            Some(&"3".to_string())
        );
        assert_eq!(
            stored_config.config.get("lockout_duration"),
            Some(&"300".to_string())
        );
    }

    #[tokio::test]
    async fn test_authenticator_types() {
        // Test all authenticator types are properly defined
        assert_eq!(
            AuthenticatorType::UsernamePassword,
            AuthenticatorType::UsernamePassword
        );
        assert_eq!(AuthenticatorType::OTP, AuthenticatorType::OTP);
        assert_eq!(AuthenticatorType::WebAuthn, AuthenticatorType::WebAuthn);
        assert_eq!(
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::RecoveryCode
        );
        assert_eq!(AuthenticatorType::Social, AuthenticatorType::Social);
        assert_eq!(
            AuthenticatorType::Custom("test".to_string()),
            AuthenticatorType::Custom("test".to_string())
        );
    }

    #[tokio::test]
    async fn test_authentication_flow_types() {
        // Test all flow types are properly defined
        assert_eq!(
            AuthenticationFlowType::Browser,
            AuthenticationFlowType::Browser
        );
        assert_eq!(
            AuthenticationFlowType::DirectGrant,
            AuthenticationFlowType::DirectGrant
        );
        assert_eq!(
            AuthenticationFlowType::Client,
            AuthenticationFlowType::Client
        );
        assert_eq!(
            AuthenticationFlowType::Registration,
            AuthenticationFlowType::Registration
        );
        assert_eq!(
            AuthenticationFlowType::ResetCredentials,
            AuthenticationFlowType::ResetCredentials
        );
        assert_eq!(
            AuthenticationFlowType::Custom("test".to_string()),
            AuthenticationFlowType::Custom("test".to_string())
        );
    }
}
