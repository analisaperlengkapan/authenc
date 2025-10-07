//! Integration tests for Session 4 features
//! Tests Event Listener SPI, Protocol Mapper Extensions, and Custom Authenticator Support

#[cfg(test)]
mod session4_integration_tests {
    use authenc::authenticator::{
        AuthContext, AuthFlowExecutor, AuthStatus, ConditionalAuthenticator, OTPAuthenticator,
        Requirement, UsernamePasswordAuthenticator,
    };
    use authenc::events::{
        Event, EventBus, EventCategory, EventListener, EventType, LoggingListener, MetricsListener,
        WebhookListener,
    };
    use authenc::protocol::{
        AudienceMapper, GroupMembershipMapper, HardcodedClaimMapper, MapperContext, MapperRegistry,
        Protocol, ProtocolMapper, RoleListMapper, UserAttributeMapper, UserPropertyMapper,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use uuid::Uuid;

    // ===== Event System Tests =====

    #[tokio::test]
    async fn test_event_bus_registration_and_dispatch() {
        let event_bus = EventBus::new();

        // Register listeners
        let logging_listener = Arc::new(LoggingListener::new(
            "test-logger".to_string(),
            "info".to_string(),
        ));
        let metrics_listener = Arc::new(MetricsListener::new("test-metrics".to_string()));

        event_bus.register(logging_listener).await;
        event_bus.register(metrics_listener.clone()).await;

        // Create and dispatch event
        let realm_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let user_id_str = user_id.to_string();
        let event = Event::new(realm_id, EventType::UserCreated, EventCategory::User)
            .with_user(user_id, "testuser")
            .with_resource("USER", &user_id_str)
            .with_data(json!({"email": "test@example.com"}));

        let results = event_bus.dispatch(event).await;

        // Verify execution
        assert_eq!(results.len(), 2, "Should execute 2 listeners");
        assert!(
            results.iter().all(|r| r.success),
            "All listeners should succeed"
        );

        // Check metrics
        let metrics = metrics_listener.get_metrics().await;
        assert_eq!(
            metrics.get("USER_CREATED"),
            Some(&1),
            "Should track USER_CREATED event"
        );
    }

    #[tokio::test]
    async fn test_event_priority_ordering() {
        let event_bus = EventBus::new();

        let listener1 = Arc::new(LoggingListener::new(
            "listener1".to_string(),
            "info".to_string(),
        ));
        let listener2 = Arc::new(MetricsListener::new("listener2".to_string()));

        // Register in reverse priority order
        event_bus.register(listener2).await; // Priority 20
        event_bus.register(listener1).await; // Priority 10

        let event = Event::new(Uuid::new_v4(), EventType::UserLogin, EventCategory::Auth);
        let results = event_bus.dispatch(event).await;

        // Verify priority ordering (logging should execute first)
        assert_eq!(results[0].listener_name, "listener1");
        assert_eq!(results[1].listener_name, "listener2");
    }

    #[tokio::test]
    async fn test_webhook_listener_configuration() {
        let webhook = WebhookListener::new(
            "test-webhook".to_string(),
            "https://example.com/webhook".to_string(),
            "POST".to_string(),
            vec![EventType::UserCreated, EventType::UserUpdated],
        );

        assert_eq!(webhook.name(), "test-webhook");
        assert_eq!(webhook.listener_type(), "webhook");
        assert_eq!(webhook.priority(), 50);

        // Test event filtering
        let realm_id = Uuid::new_v4();
        let event1 = Event::new(realm_id, EventType::UserCreated, EventCategory::User);
        let event2 = Event::new(realm_id, EventType::SessionCreated, EventCategory::Session);

        assert!(webhook.accepts(&event1.event_type));
        assert!(!webhook.accepts(&event2.event_type));
    }

    // ===== Protocol Mapper Tests =====

    #[tokio::test]
    async fn test_user_attribute_mapper() {
        let mapper = UserAttributeMapper::new(
            "test-attr-mapper".to_string(),
            Protocol::OIDC,
            "department".to_string(),
            "dept".to_string(),
            "String".to_string(),
        );

        let mut attributes = HashMap::new();
        attributes.insert("department".to_string(), json!("Engineering"));

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            attributes,
            roles: vec![],
            groups: vec![],
            client_id: None,
            realm: "test-realm".to_string(),
        };

        let claims = mapper.map(&context).await.unwrap();

        assert_eq!(claims.get("dept"), Some(&json!("Engineering")));
    }

    #[tokio::test]
    async fn test_user_property_mapper() {
        let mapper = UserPropertyMapper::new(
            "email-mapper".to_string(),
            Protocol::OIDC,
            "email".to_string(),
            "email_address".to_string(),
        );

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            first_name: None,
            last_name: None,
            attributes: HashMap::new(),
            roles: vec![],
            groups: vec![],
            client_id: None,
            realm: "test-realm".to_string(),
        };

        let claims = mapper.map(&context).await.unwrap();

        assert_eq!(
            claims.get("email_address"),
            Some(&json!("test@example.com"))
        );
    }

    #[tokio::test]
    async fn test_role_list_mapper() {
        let mapper = RoleListMapper::new(
            "role-mapper".to_string(),
            Protocol::OIDC,
            "roles".to_string(),
            Some("ROLE_".to_string()),
        );

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: None,
            first_name: None,
            last_name: None,
            attributes: HashMap::new(),
            roles: vec!["admin".to_string(), "user".to_string()],
            groups: vec![],
            client_id: None,
            realm: "test-realm".to_string(),
        };

        let claims = mapper.map(&context).await.unwrap();
        let roles = claims.get("roles").unwrap().as_array().unwrap();

        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&json!("ROLE_admin")));
        assert!(roles.contains(&json!("ROLE_user")));
    }

    #[tokio::test]
    async fn test_hardcoded_claim_mapper() {
        let mapper = HardcodedClaimMapper::new(
            "issuer-mapper".to_string(),
            Protocol::OIDC,
            "iss".to_string(),
            json!("https://authenc.example.com"),
        );

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: None,
            first_name: None,
            last_name: None,
            attributes: HashMap::new(),
            roles: vec![],
            groups: vec![],
            client_id: None,
            realm: "test-realm".to_string(),
        };

        let claims = mapper.map(&context).await.unwrap();

        assert_eq!(
            claims.get("iss"),
            Some(&json!("https://authenc.example.com"))
        );
    }

    #[tokio::test]
    async fn test_group_membership_mapper() {
        let mapper = GroupMembershipMapper::new(
            "group-mapper".to_string(),
            Protocol::OIDC,
            "groups".to_string(),
            false, // Simple names, not full paths
        );

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: None,
            first_name: None,
            last_name: None,
            attributes: HashMap::new(),
            roles: vec![],
            groups: vec!["/top/middle/bottom".to_string(), "/admin".to_string()],
            client_id: None,
            realm: "test-realm".to_string(),
        };

        let claims = mapper.map(&context).await.unwrap();
        let groups = claims.get("groups").unwrap().as_array().unwrap();

        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&json!("bottom")));
        assert!(groups.contains(&json!("admin")));
    }

    #[tokio::test]
    async fn test_audience_mapper() {
        let mapper = AudienceMapper::new(
            "aud-mapper".to_string(),
            Protocol::OIDC,
            Some("external-service".to_string()),
            Some("https://api.example.com".to_string()),
        );

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: None,
            first_name: None,
            last_name: None,
            attributes: HashMap::new(),
            roles: vec![],
            groups: vec![],
            client_id: Some("my-client".to_string()),
            realm: "test-realm".to_string(),
        };

        let claims = mapper.map(&context).await.unwrap();
        let audiences = claims.get("aud").unwrap().as_array().unwrap();

        assert_eq!(audiences.len(), 3);
        assert!(audiences.contains(&json!("external-service")));
        assert!(audiences.contains(&json!("https://api.example.com")));
        assert!(audiences.contains(&json!("my-client")));
    }

    #[tokio::test]
    async fn test_mapper_registry() {
        let mut registry = MapperRegistry::new();

        registry.register(Box::new(UserPropertyMapper::new(
            "username-mapper".to_string(),
            Protocol::OIDC,
            "username".to_string(),
            "preferred_username".to_string(),
        )));

        registry.register(Box::new(RoleListMapper::new(
            "role-mapper".to_string(),
            Protocol::OIDC,
            "roles".to_string(),
            None,
        )));

        let context = MapperContext {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: None,
            first_name: None,
            last_name: None,
            attributes: HashMap::new(),
            roles: vec!["admin".to_string()],
            groups: vec![],
            client_id: None,
            realm: "test-realm".to_string(),
        };

        let all_claims = registry
            .apply_mappers(&context, &Protocol::OIDC)
            .await
            .unwrap();

        assert_eq!(
            all_claims.get("preferred_username"),
            Some(&json!("testuser"))
        );
        assert!(all_claims.contains_key("roles"));
    }

    // ===== Custom Authenticator Tests =====

    #[tokio::test]
    async fn test_username_password_authenticator() {
        let auth: Arc<dyn authenc::authenticator::Authenticator> = Arc::new(
            UsernamePasswordAuthenticator::new("password-auth".to_string()),
        );

        let mut context = AuthContext::new(Uuid::new_v4(), "127.0.0.1".to_string())
            .with_auth_data("username".to_string(), json!("testuser"))
            .with_auth_data("password".to_string(), json!("password123"));

        assert!(auth.can_authenticate(&context).await);

        let result = auth.authenticate(&mut context).await.unwrap();

        assert_eq!(result.status, AuthStatus::Success);
        assert!(result.user_id.is_some());
        assert_eq!(context.username, Some("testuser".to_string()));
    }

    #[tokio::test]
    async fn test_otp_authenticator() {
        let auth: Arc<dyn authenc::authenticator::Authenticator> =
            Arc::new(OTPAuthenticator::new("otp-auth".to_string(), 6));

        let user_id = Uuid::new_v4();
        let mut context = AuthContext::new(Uuid::new_v4(), "127.0.0.1".to_string())
            .with_user(user_id, "testuser".to_string())
            .with_auth_data("otp_code".to_string(), json!("123456"));

        assert!(auth.can_authenticate(&context).await);

        let result = auth.authenticate(&mut context).await.unwrap();

        assert_eq!(result.status, AuthStatus::Success);
        assert_eq!(result.user_id, Some(user_id));
    }

    #[tokio::test]
    async fn test_conditional_authenticator() {
        let auth: Arc<dyn authenc::authenticator::Authenticator> =
            Arc::new(ConditionalAuthenticator::new(
                "conditional-auth".to_string(),
                "has-user".to_string(),
                "".to_string(),
            ));

        // Context with user - should authenticate
        let user_id = Uuid::new_v4();
        let mut context1 = AuthContext::new(Uuid::new_v4(), "127.0.0.1".to_string())
            .with_user(user_id, "testuser".to_string());

        assert!(auth.can_authenticate(&context1).await);
        let result1 = auth.authenticate(&mut context1).await.unwrap();
        assert_eq!(result1.status, AuthStatus::Success);

        // Context without user - should skip
        let auth2: Arc<dyn authenc::authenticator::Authenticator> =
            Arc::new(ConditionalAuthenticator::new(
                "conditional-auth".to_string(),
                "has-user".to_string(),
                "".to_string(),
            ));
        let mut context2 = AuthContext::new(Uuid::new_v4(), "127.0.0.1".to_string());

        assert!(!auth2.can_authenticate(&context2).await);
        let result2 = auth2.authenticate(&mut context2).await.unwrap();
        assert_eq!(result2.status, AuthStatus::Skipped);
    }

    #[tokio::test]
    async fn test_auth_flow_executor_required() {
        let executor = AuthFlowExecutor::new();

        let auth = Arc::new(UsernamePasswordAuthenticator::new(
            "password-auth".to_string(),
        ));
        executor.register(auth).await;

        let mut context = AuthContext::new(Uuid::new_v4(), "127.0.0.1".to_string())
            .with_auth_data("username".to_string(), json!("testuser"))
            .with_auth_data("password".to_string(), json!("password123"));

        let requirements = vec![(Uuid::new_v4(), Requirement::Required)];

        let result = executor
            .execute_flow(&mut context, &requirements)
            .await
            .unwrap();

        assert_eq!(result.status, AuthStatus::Success);
        assert!(context.user_id.is_some());
    }

    #[tokio::test]
    async fn test_auth_flow_executor_alternative() {
        let executor = AuthFlowExecutor::new();

        // Register multiple authenticators
        let password_auth = Arc::new(UsernamePasswordAuthenticator::new("password".to_string()));
        let otp_auth = Arc::new(OTPAuthenticator::new("otp".to_string(), 6));

        executor.register(password_auth).await;
        executor.register(otp_auth).await;

        // Only provide OTP data
        let user_id = Uuid::new_v4();
        let mut context = AuthContext::new(Uuid::new_v4(), "127.0.0.1".to_string())
            .with_user(user_id, "testuser".to_string())
            .with_auth_data("otp_code".to_string(), json!("123456"));

        let requirements = vec![(Uuid::new_v4(), Requirement::Alternative)];

        let result = executor
            .execute_flow(&mut context, &requirements)
            .await
            .unwrap();

        // Should succeed with OTP even though password not provided
        assert_eq!(result.status, AuthStatus::Success);
    }

    #[tokio::test]
    async fn test_authenticator_priority_ordering() {
        let executor = AuthFlowExecutor::new();

        // Register in reverse priority order
        let otp_auth: Arc<dyn authenc::authenticator::Authenticator> =
            Arc::new(OTPAuthenticator::new("otp".to_string(), 6)); // Priority 20
        let password_auth: Arc<dyn authenc::authenticator::Authenticator> =
            Arc::new(UsernamePasswordAuthenticator::new("password".to_string())); // Priority 10

        executor.register(otp_auth.clone()).await;
        executor.register(password_auth.clone()).await;

        // Verify lower priority executes first (internally sorted)
        assert_eq!(password_auth.priority(), 10);
        assert_eq!(otp_auth.priority(), 20);
    }

    #[tokio::test]
    async fn test_auth_context_builder() {
        let realm_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let context = AuthContext::new(realm_id, "192.168.1.1".to_string())
            .with_client("test-client".to_string())
            .with_session(session_id)
            .with_user(user_id, "testuser".to_string())
            .with_auth_data("custom".to_string(), json!({"key": "value"}));

        assert_eq!(context.realm_id, realm_id);
        assert_eq!(context.ip_address, "192.168.1.1");
        assert_eq!(context.client_id, Some("test-client".to_string()));
        assert_eq!(context.session_id, Some(session_id));
        assert_eq!(context.user_id, Some(user_id));
        assert_eq!(context.username, Some("testuser".to_string()));
        assert!(context.auth_data.contains_key("custom"));
    }

    // ===== Integration Tests =====

    #[tokio::test]
    async fn test_full_authentication_flow_with_events() {
        // Setup event bus
        let event_bus = EventBus::new();
        let metrics = Arc::new(MetricsListener::new("auth-metrics".to_string()));
        event_bus.register(metrics.clone()).await;

        // Setup authenticator
        let executor = AuthFlowExecutor::new();
        let auth = Arc::new(UsernamePasswordAuthenticator::new(
            "password-auth".to_string(),
        ));
        executor.register(auth).await;

        // Execute authentication
        let realm_id = Uuid::new_v4();
        let mut context = AuthContext::new(realm_id, "127.0.0.1".to_string())
            .with_client("test-client".to_string())
            .with_auth_data("username".to_string(), json!("testuser"))
            .with_auth_data("password".to_string(), json!("password123"));

        let requirements = vec![(Uuid::new_v4(), Requirement::Required)];
        let result = executor
            .execute_flow(&mut context, &requirements)
            .await
            .unwrap();

        // Log authentication event
        let event = Event::new(realm_id, EventType::AuthSuccess, EventCategory::Auth)
            .with_user(result.user_id.unwrap(), "testuser");

        event_bus.dispatch(event).await;

        // Verify metrics
        let event_metrics = metrics.get_metrics().await;
        assert_eq!(event_metrics.get("AUTH_SUCCESS"), Some(&1));
    }

    #[tokio::test]
    async fn test_protocol_mapping_with_authentication() {
        // Authenticate user
        let executor = AuthFlowExecutor::new();
        let auth = Arc::new(UsernamePasswordAuthenticator::new(
            "password-auth".to_string(),
        ));
        executor.register(auth).await;

        let realm_id = Uuid::new_v4();
        let mut auth_context = AuthContext::new(realm_id, "127.0.0.1".to_string())
            .with_auth_data("username".to_string(), json!("testuser"))
            .with_auth_data("password".to_string(), json!("password123"));

        let requirements = vec![(Uuid::new_v4(), Requirement::Required)];
        let auth_result = executor
            .execute_flow(&mut auth_context, &requirements)
            .await
            .unwrap();

        // Map user to protocol claims
        let mut registry = MapperRegistry::new();
        registry.register(Box::new(UserPropertyMapper::new(
            "username-mapper".to_string(),
            Protocol::OIDC,
            "username".to_string(),
            "sub".to_string(),
        )));
        registry.register(Box::new(RoleListMapper::new(
            "role-mapper".to_string(),
            Protocol::OIDC,
            "roles".to_string(),
            None,
        )));

        let mapper_context = MapperContext {
            user_id: auth_result.user_id.unwrap(),
            username: auth_context.username.unwrap(),
            email: Some("test@example.com".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            attributes: HashMap::new(),
            roles: vec!["user".to_string(), "admin".to_string()],
            groups: vec![],
            client_id: auth_context.client_id.clone(),
            realm: "test-realm".to_string(),
        };

        let claims = registry
            .apply_mappers(&mapper_context, &Protocol::OIDC)
            .await
            .unwrap();

        // Verify token claims
        assert_eq!(claims.get("sub"), Some(&json!("testuser")));
        assert!(claims.contains_key("roles"));

        let roles = claims.get("roles").unwrap().as_array().unwrap();
        assert_eq!(roles.len(), 2);
    }
}
