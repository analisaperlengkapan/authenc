#[cfg(test)]
mod tests {
    use super::*;
    use authenc::models::User;
    use authenc::models::user::*;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn test_user_creation() {
        let realm_id = Uuid::new_v4();
        let password_hash = Some("hashed_password".to_string());
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            password_hash.clone(),
            Some(realm_id),
        );

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, password_hash);
        assert_eq!(user.realm_id, Some(realm_id));
        assert!(user.enabled);
        assert!(!user.federated);
        assert_eq!(user.failed_login_attempts, 0);
        assert_eq!(user.login_count, 0);
        assert!(user.created_at <= Utc::now());
        assert!(user.updated_at <= Utc::now());
    }

    #[test]
    fn test_user_is_active() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        // Active user
        assert!(user.is_active());

        // Disabled user
        user.enabled = false;
        assert!(!user.is_active());

        // Soft deleted user
        user.enabled = true;
        user.deleted_at = Some(Utc::now());
        assert!(!user.is_active());

        // Locked user
        user.deleted_at = None;
        user.account_locked = true;
        assert!(!user.is_active());
    }

    #[test]
    fn test_user_is_locked() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        // Not locked
        assert!(!user.is_locked());

        // Permanently locked
        user.account_locked = true;
        assert!(user.is_locked());

        // Temporarily locked but expired
        let past_time = Utc::now() - Duration::hours(1);
        user.account_locked_until = Some(past_time);
        assert!(!user.is_locked());

        // Temporarily locked and still active
        let future_time = Utc::now() + Duration::hours(1);
        user.account_locked_until = Some(future_time);
        assert!(user.is_locked());
    }

    #[test]
    fn test_user_delete() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        let original_updated_at = user.updated_at;
        user.delete();

        assert!(user.deleted_at.is_some());
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_update() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        let original_updated_at = user.updated_at;

        let update_request = UpdateUserRequest {
            username: Some("newusername".to_string()),
            email: Some("newemail@example.com".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            phone_number: Some("+1234567890".to_string()),
            enabled: Some(false),
            email_verified: Some(true),
            phone_verified: Some(true),
            require_password_change: Some(true),
            attributes: Some(json!({"custom_field": "value"})),
        };

        user.update(update_request);

        assert_eq!(user.username, "newusername");
        assert_eq!(user.email, "newemail@example.com");
        assert_eq!(user.first_name, Some("John".to_string()));
        assert_eq!(user.last_name, Some("Doe".to_string()));
        assert_eq!(user.phone_number, Some("+1234567890".to_string()));
        assert!(!user.enabled);
        assert!(user.email_verified);
        assert!(user.phone_verified);
        assert!(user.require_password_change);
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_record_login() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        user.failed_login_attempts = 3;
        user.account_locked = true;
        user.account_locked_until = Some(Utc::now() + Duration::hours(1));

        let original_updated_at = user.updated_at;
        user.record_login();

        assert!(user.last_login_at.is_some());
        assert_eq!(user.failed_login_attempts, 0);
        assert!(!user.account_locked);
        assert!(user.account_locked_until.is_none());
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_record_failed_login() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        let original_updated_at = user.updated_at;
        user.record_failed_login();

        assert_eq!(user.failed_login_attempts, 1);
        assert!(user.last_failed_login_at.is_some());
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_lock_account() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        let lock_until = Some(Utc::now() + Duration::hours(24));
        let original_updated_at = user.updated_at;

        user.lock_account(lock_until);

        assert!(user.account_locked);
        assert_eq!(user.account_locked_until, lock_until);
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_unlock_account() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        user.account_locked = true;
        user.account_locked_until = Some(Utc::now() + Duration::hours(24));
        user.failed_login_attempts = 5;

        let original_updated_at = user.updated_at;
        user.unlock_account();

        assert!(!user.account_locked);
        assert!(user.account_locked_until.is_none());
        assert_eq!(user.failed_login_attempts, 0);
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_update_password() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        user.require_password_change = true;
        let original_updated_at = user.updated_at;

        user.update_password("new_hashed_password".to_string());

        assert_eq!(user.password_hash, Some("new_hashed_password".to_string()));
        assert!(user.password_changed_at.is_some());
        assert!(!user.require_password_change);
        assert!(user.updated_at > original_updated_at);
    }

    #[test]
    fn test_user_webauthn_enable_disable() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        let original_updated_at = user.updated_at;

        user.enable_webauthn();
        assert!(user.webauthn_enabled);
        assert!(user.updated_at > original_updated_at);

        let updated_at_after_enable = user.updated_at;
        user.disable_webauthn();
        assert!(!user.webauthn_enabled);
        assert!(user.updated_at > updated_at_after_enable);
    }

    #[test]
    fn test_user_full_name() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            None,
        );

        // Only username
        assert_eq!(user.full_name(), "testuser");

        // First name only
        user.first_name = Some("John".to_string());
        assert_eq!(user.full_name(), "John");

        // Last name only
        user.first_name = None;
        user.last_name = Some("Doe".to_string());
        assert_eq!(user.full_name(), "Doe");

        // Both names
        user.first_name = Some("John".to_string());
        user.last_name = Some("Doe".to_string());
        assert_eq!(user.full_name(), "John Doe");
    }

    #[test]
    fn test_user_claims_creation() {
        let claims = UserClaims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            realm_id: "realm123".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            iss: "authenc".to_string(),
        };

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.realm_id, "realm123");
        assert_eq!(claims.roles.len(), 2);
        assert_eq!(claims.exp, 1234567890);
        assert_eq!(claims.iat, 1234567800);
        assert_eq!(claims.iss, "authenc");
    }

    #[test]
    fn test_user_claims_serialization() {
        let claims = UserClaims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            realm_id: "realm123".to_string(),
            roles: vec!["admin".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            iss: "authenc".to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: UserClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.username, deserialized.username);
        assert_eq!(claims.email, deserialized.email);
        assert_eq!(claims.roles, deserialized.roles);
    }

    #[test]
    fn test_credential_type_serialization() {
        let credential_types = vec![
            CredentialType::Password,
            CredentialType::Totp,
            CredentialType::Webauthn,
            CredentialType::RecoveryCode,
            CredentialType::MagicLink,
            CredentialType::Social,
        ];

        for cred_type in credential_types {
            let json = serde_json::to_string(&cred_type).unwrap();
            let deserialized: CredentialType = serde_json::from_str(&json).unwrap();
            // Since CredentialType doesn't implement PartialEq, we check the JSON representation
            assert_eq!(
                serde_json::to_string(&cred_type).unwrap(),
                serde_json::to_string(&deserialized).unwrap()
            );
        }
    }

    #[test]
    fn test_user_credential_creation() {
        let user_id = Uuid::new_v4();
        let credential = UserCredential {
            id: Uuid::new_v4(),
            user_id,
            credential_type: CredentialType::Password,
            credential_data: json!({"hash": "hashed_password"}),
            priority: 1,
            enabled: true,
            created_at: Utc::now(),
            last_used_at: Some(Utc::now()),
        };

        assert!(credential.enabled);
        assert_eq!(credential.priority, 1);
        assert!(credential.last_used_at.is_some());
        assert!(matches!(
            credential.credential_type,
            CredentialType::Password
        ));
    }

    #[test]
    fn test_user_session_creation() {
        let user_id = Uuid::new_v4();
        let session = UserSession {
            id: Uuid::new_v4(),
            user_id,
            session_id: "session123".to_string(),
            client_id: Some("client123".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            started_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            last_activity_at: Utc::now(),
            terminated_at: None,
            termination_reason: None,
            refresh_token_id: Some(Uuid::new_v4()),
            attributes: Some(json!({"custom": "data"})),
        };

        assert_eq!(session.user_id, user_id);
        assert_eq!(session.session_id, "session123");
        assert!(session.client_id.is_some());
        assert!(session.ip_address.is_some());
        assert!(session.user_agent.is_some());
        assert!(session.refresh_token_id.is_some());
        assert!(session.attributes.is_some());
        assert!(session.terminated_at.is_none());
    }

    #[test]
    fn test_role_creation() {
        let realm_id = Uuid::new_v4();
        let role = Role {
            id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: Some("Administrator role".to_string()),
            realm_id: Some(realm_id),
            composite: false,
            client_role: false,
            client_id: None,
            attributes: Some(json!({"level": "high"})),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(role.name, "admin");
        assert_eq!(role.description, Some("Administrator role".to_string()));
        assert_eq!(role.realm_id, Some(realm_id));
        assert!(!role.composite);
        assert!(!role.client_role);
        assert!(role.attributes.is_some());
    }

    #[test]
    fn test_user_role_creation() {
        let user_id = Uuid::new_v4();
        let role_id = Uuid::new_v4();
        let assigned_by = Uuid::new_v4();

        let user_role = UserRole {
            id: Uuid::new_v4(),
            user_id,
            role_id,
            assigned_by,
            assigned_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(30)),
            attributes: None,
        };

        assert_eq!(user_role.user_id, user_id);
        assert_eq!(user_role.role_id, role_id);
        assert_eq!(user_role.assigned_by, assigned_by);
        assert!(user_role.expires_at.is_some());
    }

    #[test]
    fn test_permission_creation() {
        let realm_id = Uuid::new_v4();
        let permission = Permission {
            id: Uuid::new_v4(),
            name: "user.read".to_string(),
            description: Some("Read user data".to_string()),
            resource_type: "user".to_string(),
            resource_id: Some("user123".to_string()),
            action: "read".to_string(),
            realm_id: Some(realm_id),
            attributes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(permission.name, "user.read");
        assert_eq!(permission.resource_type, "user");
        assert_eq!(permission.action, "read");
        assert_eq!(permission.realm_id, Some(realm_id));
    }

    #[test]
    fn test_group_creation() {
        let realm_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();

        let group = Group {
            id: Uuid::new_v4(),
            name: "developers".to_string(),
            description: Some("Development team".to_string()),
            path: "/developers".to_string(),
            parent_id: Some(parent_id),
            realm_id: Some(realm_id),
            attributes: Some(json!({"department": "engineering"})),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(group.name, "developers");
        assert_eq!(group.path, "/developers");
        assert_eq!(group.parent_id, Some(parent_id));
        assert_eq!(group.realm_id, Some(realm_id));
        assert!(group.attributes.is_some());
    }

    #[test]
    fn test_user_group_creation() {
        let user_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let assigned_by = Uuid::new_v4();

        let user_group = UserGroup {
            id: Uuid::new_v4(),
            user_id,
            group_id,
            assigned_by,
            assigned_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(365)),
        };

        assert_eq!(user_group.user_id, user_id);
        assert_eq!(user_group.group_id, group_id);
        assert_eq!(user_group.assigned_by, assigned_by);
        assert!(user_group.expires_at.is_some());
    }

    #[test]
    fn test_user_profile_creation() {
        let user_id = Uuid::new_v4();
        let profile = UserProfile {
            user_id,
            avatar_url: Some("https://example.com/avatar.jpg".to_string()),
            bio: Some("Software developer".to_string()),
            website: Some("https://example.com".to_string()),
            location: Some("San Francisco".to_string()),
            timezone: Some("America/Los_Angeles".to_string()),
            locale: Some("en-US".to_string()),
            theme: Some("dark".to_string()),
            preferences: Some(json!({"notifications": true})),
            updated_at: Utc::now(),
        };

        assert_eq!(profile.user_id, user_id);
        assert!(profile.avatar_url.is_some());
        assert!(profile.bio.is_some());
        assert!(profile.website.is_some());
        assert!(profile.location.is_some());
        assert!(profile.timezone.is_some());
        assert!(profile.locale.is_some());
        assert!(profile.theme.is_some());
        assert!(profile.preferences.is_some());
    }

    #[test]
    fn test_identity_provider_creation() {
        let realm_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        let idp = IdentityProvider {
            id: Uuid::new_v4(),
            alias: "google".to_string(),
            display_name: Some("Google".to_string()),
            provider_id: "google".to_string(),
            enabled: true,
            trust_email: true,
            store_token: true,
            add_read_token_role_on_create: true,
            authenticate_by_default: false,
            link_only: false,
            first_broker_login_flow_id: Some(Uuid::new_v4()),
            post_broker_login_flow_id: Some(Uuid::new_v4()),
            config: json!({"client_id": "123", "client_secret": "secret"}),
            realm_id: Some(realm_id),
            organization_id: Some(org_id),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(idp.alias, "google");
        assert_eq!(idp.provider_id, "google");
        assert!(idp.enabled);
        assert!(idp.trust_email);
        assert!(idp.store_token);
        assert!(idp.first_broker_login_flow_id.is_some());
        assert!(idp.post_broker_login_flow_id.is_some());
        assert_eq!(idp.realm_id, Some(realm_id));
        assert_eq!(idp.organization_id, Some(org_id));
    }

    #[test]
    fn test_federated_identity_creation() {
        let user_id = Uuid::new_v4();
        let provider_id = Uuid::new_v4();

        let fed_identity = FederatedIdentity {
            id: Uuid::new_v4(),
            user_id,
            identity_provider_id: provider_id,
            external_id: "google123".to_string(),
            external_username: Some("user@gmail.com".to_string()),
            external_email: Some("user@gmail.com".to_string()),
            external_attributes: Some(json!({"verified": true})),
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(fed_identity.user_id, user_id);
        assert_eq!(fed_identity.identity_provider_id, provider_id);
        assert_eq!(fed_identity.external_id, "google123");
        assert!(fed_identity.external_username.is_some());
        assert!(fed_identity.external_email.is_some());
        assert!(fed_identity.external_attributes.is_some());
        assert!(fed_identity.last_login_at.is_some());
    }

    #[test]
    fn test_create_user_request_validation() {
        let realm_id = Uuid::new_v4();
        let request = CreateUserRequest {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: Some("password123".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            phone_number: Some("+1234567890".to_string()),
            realm_id: Some(realm_id),
            organization_id: Some(Uuid::new_v4()),
            attributes: Some(json!({"department": "engineering"})),
            email_verified: Some(true),
            enabled: Some(true),
            require_password_change: Some(false),
        };

        assert_eq!(request.username, "testuser");
        assert_eq!(request.email, "test@example.com");
        assert!(request.password.is_some());
        assert!(request.first_name.is_some());
        assert!(request.last_name.is_some());
        assert!(request.phone_number.is_some());
        assert_eq!(request.realm_id, Some(realm_id));
        assert!(request.organization_id.is_some());
        assert!(request.attributes.is_some());
    }

    #[test]
    fn test_update_user_request_partial_update() {
        let request = UpdateUserRequest {
            username: Some("newusername".to_string()),
            email: None,
            first_name: Some("Jane".to_string()),
            last_name: None,
            phone_number: None,
            enabled: Some(true),
            email_verified: None,
            phone_verified: Some(false),
            require_password_change: None,
            attributes: None,
        };

        assert!(request.username.is_some());
        assert!(request.email.is_none());
        assert!(request.first_name.is_some());
        assert!(request.last_name.is_none());
        assert!(request.enabled.is_some());
        assert!(request.phone_verified.is_some());
    }

    #[test]
    fn test_user_response_from_user_conversion() {
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            Some("hashed_pass".to_string()),
            Some(Uuid::new_v4()),
        );

        let response: UserResponse = user.clone().into();

        assert_eq!(response.id, user.id);
        assert_eq!(response.username, user.username);
        assert_eq!(response.email, user.email);
        assert_eq!(response.email_verified, user.email_verified);
        assert_eq!(response.first_name, user.first_name);
        assert_eq!(response.last_name, user.last_name);
        assert_eq!(response.phone_number, user.phone_number);
        assert_eq!(response.phone_verified, user.phone_verified);
        assert_eq!(response.webauthn_enabled, user.webauthn_enabled);
        assert_eq!(response.account_locked, user.account_locked);
        assert_eq!(response.last_login_at, user.last_login_at);
        assert_eq!(response.realm_id, user.realm_id);
        assert_eq!(response.organization_id, user.organization_id);
        assert_eq!(response.enabled, user.enabled);
        assert_eq!(response.created_at, user.created_at);
        assert_eq!(response.updated_at, user.updated_at);
    }

    #[test]
    fn test_execution_requirement_serialization() {
        let requirements = vec![
            ExecutionRequirement::Required,
            ExecutionRequirement::Alternative,
            ExecutionRequirement::Disabled,
            ExecutionRequirement::Conditional,
        ];

        for req in requirements {
            let json = serde_json::to_string(&req).unwrap();
            let deserialized: ExecutionRequirement = serde_json::from_str(&json).unwrap();
            // Since ExecutionRequirement doesn't implement PartialEq, we check the JSON representation
            assert_eq!(
                serde_json::to_string(&req).unwrap(),
                serde_json::to_string(&deserialized).unwrap()
            );
        }
    }

    #[test]
    fn test_authenticator_config_creation() {
        let realm_id = Uuid::new_v4();
        let config = AuthenticatorConfig {
            id: Uuid::new_v4(),
            alias: "password-form".to_string(),
            description: Some("Password authentication form".to_string()),
            realm_id: Some(realm_id),
            provider_id: "password-form".to_string(),
            config: json!({"validatePasswordPolicy": true}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(config.alias, "password-form");
        assert_eq!(config.provider_id, "password-form");
        assert_eq!(config.realm_id, Some(realm_id));
        assert!(config.description.is_some());
    }

    #[test]
    fn test_required_action_creation() {
        let realm_id = Uuid::new_v4();
        let action = RequiredAction {
            id: Uuid::new_v4(),
            alias: "UPDATE_PASSWORD".to_string(),
            name: "Update Password".to_string(),
            description: Some("User must update their password".to_string()),
            provider_id: "update-password".to_string(),
            enabled: true,
            default_action: false,
            priority: 10,
            config: Some(json!({"minimumLength": 8})),
            realm_id: Some(realm_id),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(action.alias, "UPDATE_PASSWORD");
        assert_eq!(action.name, "Update Password");
        assert!(action.enabled);
        assert!(!action.default_action);
        assert_eq!(action.priority, 10);
        assert_eq!(action.realm_id, Some(realm_id));
        assert!(action.config.is_some());
    }

    #[test]
    fn test_user_required_action_creation() {
        let user_id = Uuid::new_v4();
        let action_id = Uuid::new_v4();

        let user_action = UserRequiredAction {
            id: Uuid::new_v4(),
            user_id,
            required_action_id: action_id,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(7)),
        };

        assert_eq!(user_action.user_id, user_id);
        assert_eq!(user_action.required_action_id, action_id);
        assert!(user_action.expires_at.is_some());
    }

    #[test]
    fn test_jit_user_provisioning_request() {
        let provider_id = Uuid::new_v4();
        let realm_id = Uuid::new_v4();

        let request = JITUserProvisioningRequest {
            identity_provider_id: provider_id,
            external_id: "google123".to_string(),
            external_username: Some("user@gmail.com".to_string()),
            external_email: Some("user@gmail.com".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            external_attributes: Some(json!({"verified_email": true})),
            realm_id,
        };

        assert_eq!(request.identity_provider_id, provider_id);
        assert_eq!(request.external_id, "google123");
        assert!(request.external_username.is_some());
        assert!(request.external_email.is_some());
        assert!(request.first_name.is_some());
        assert!(request.last_name.is_some());
        assert!(request.external_attributes.is_some());
        assert_eq!(request.realm_id, realm_id);
    }

    #[test]
    fn test_jit_user_provisioning_response() {
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            Some(Uuid::new_v4()),
        );

        let fed_identity = FederatedIdentity {
            id: Uuid::new_v4(),
            user_id: user.id,
            identity_provider_id: Uuid::new_v4(),
            external_id: "google123".to_string(),
            external_username: Some("user@gmail.com".to_string()),
            external_email: Some("user@gmail.com".to_string()),
            external_attributes: None,
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = JITUserProvisioningResponse {
            user: user.clone(),
            created: true,
            federated_identity: fed_identity,
        };

        assert_eq!(response.user.id, user.id);
        assert!(response.created);
        assert_eq!(response.federated_identity.user_id, user.id);
    }

    #[test]
    fn test_create_federated_identity_request() {
        let user_id = Uuid::new_v4();
        let provider_id = Uuid::new_v4();

        let request = CreateFederatedIdentityRequest {
            user_id,
            identity_provider_id: provider_id,
            external_id: "google123".to_string(),
            external_username: Some("user@gmail.com".to_string()),
            external_email: Some("user@gmail.com".to_string()),
            external_attributes: Some(json!({"locale": "en"})),
        };

        assert_eq!(request.user_id, user_id);
        assert_eq!(request.identity_provider_id, provider_id);
        assert_eq!(request.external_id, "google123");
        assert!(request.external_username.is_some());
        assert!(request.external_email.is_some());
        assert!(request.external_attributes.is_some());
    }

    #[test]
    fn test_user_identity_provider_link_creation() {
        let user_id = Uuid::new_v4();
        let provider_id = Uuid::new_v4();

        let link = UserIdentityProviderLink {
            id: Uuid::new_v4(),
            user_id,
            identity_provider_id: provider_id,
            external_id: "google123".to_string(),
            external_username: Some("user@gmail.com".to_string()),
            token: Some("access_token_123".to_string()),
            linked_at: Utc::now(),
            last_login_at: Some(Utc::now()),
        };

        assert_eq!(link.user_id, user_id);
        assert_eq!(link.identity_provider_id, provider_id);
        assert_eq!(link.external_id, "google123");
        assert!(link.external_username.is_some());
        assert!(link.token.is_some());
        assert!(link.last_login_at.is_some());
    }

    #[test]
    fn test_authentication_flow_creation() {
        let realm_id = Uuid::new_v4();
        let flow = AuthenticationFlow {
            id: Uuid::new_v4(),
            alias: "browser".to_string(),
            description: Some("Browser-based authentication".to_string()),
            realm_id: Some(realm_id),
            provider_id: "basic-flow".to_string(),
            top_level: true,
            built_in: true,
            attributes: Some(json!({"priority": 10})),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(flow.alias, "browser");
        assert_eq!(flow.provider_id, "basic-flow");
        assert!(flow.top_level);
        assert!(flow.built_in);
        assert_eq!(flow.realm_id, Some(realm_id));
        assert!(flow.attributes.is_some());
    }

    #[test]
    fn test_authentication_execution_creation() {
        let flow_id = Uuid::new_v4();
        let execution = AuthenticationExecution {
            id: Uuid::new_v4(),
            flow_id,
            alias: "auth-username-password-form".to_string(),
            description: Some("Username and password form".to_string()),
            provider_id: "auth-username-password-form".to_string(),
            requirement: ExecutionRequirement::Required,
            priority: 10,
            parent_flow: Some(Uuid::new_v4()),
            authenticator_config: Some("password-config".to_string()),
            attributes: Some(json!({"custom": "config"})),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(execution.alias, "auth-username-password-form");
        assert!(matches!(
            execution.requirement,
            ExecutionRequirement::Required
        ));
        assert_eq!(execution.priority, 10);
        assert!(execution.parent_flow.is_some());
        assert!(execution.authenticator_config.is_some());
        assert!(execution.attributes.is_some());
    }

    #[test]
    fn test_identity_provider_mapper_creation() {
        let realm_id = Uuid::new_v4();
        let mapper = IdentityProviderMapper {
            id: Uuid::new_v4(),
            name: "google-user-attribute-mapper".to_string(),
            identity_provider_alias: "google".to_string(),
            identity_provider_mapper: "google-user-attribute-mapper".to_string(),
            config: json!({"user.attribute": "email", "attribute.name": "email"}),
            realm_id: Some(realm_id),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(mapper.name, "google-user-attribute-mapper");
        assert_eq!(mapper.identity_provider_alias, "google");
        assert_eq!(
            mapper.identity_provider_mapper,
            "google-user-attribute-mapper"
        );
        assert_eq!(mapper.realm_id, Some(realm_id));
    }

    #[test]
    fn test_group_role_creation() {
        let group_id = Uuid::new_v4();
        let role_id = Uuid::new_v4();

        let group_role = GroupRole {
            id: Uuid::new_v4(),
            group_id,
            role_id,
            assigned_at: Utc::now(),
        };

        assert_eq!(group_role.group_id, group_id);
        assert_eq!(group_role.role_id, role_id);
    }

    #[test]
    fn test_role_permission_creation() {
        let role_id = Uuid::new_v4();
        let permission_id = Uuid::new_v4();

        let role_permission = RolePermission {
            id: Uuid::new_v4(),
            role_id,
            permission_id,
            assigned_at: Utc::now(),
        };

        assert_eq!(role_permission.role_id, role_id);
        assert_eq!(role_permission.permission_id, permission_id);
    }
}
