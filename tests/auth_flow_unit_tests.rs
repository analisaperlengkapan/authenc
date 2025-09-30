use authenc::services::auth_flow::{
    AuthenticationContext, AuthenticationFlowModel, AuthenticationFlowResolver,
    AuthenticationFlowType, AuthenticationManager, AuthenticationSessionManager,
    AuthenticationStepResult, DefaultAuthenticationFlowResolver,
};
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_flow_type_serialization() {
        // Test serialization of flow types
        let flow_types = vec![
            AuthenticationFlowType::Browser,
            AuthenticationFlowType::DirectGrant,
            AuthenticationFlowType::ClientAuthentication,
            AuthenticationFlowType::Registration,
            AuthenticationFlowType::ResetCredentials,
            AuthenticationFlowType::Docker,
            AuthenticationFlowType::Custom("test".to_string()),
        ];

        for flow_type in flow_types {
            let serialized = serde_json::to_string(&flow_type).unwrap();
            let deserialized: AuthenticationFlowType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(flow_type, deserialized);
        }
    }

    #[test]
    fn test_authentication_flow_model_creation() {
        let flow = AuthenticationFlowModel {
            id: Uuid::new_v4(),
            alias: "test_flow".to_string(),
            description: "Test authentication flow".to_string(),
            flow_type: AuthenticationFlowType::Browser,
            realm_id: Uuid::new_v4(),
            enabled: true,
            priority: 10,
        };

        assert_eq!(flow.alias, "test_flow");
        assert_eq!(flow.description, "Test authentication flow");
        assert_eq!(flow.flow_type, AuthenticationFlowType::Browser);
        assert!(flow.enabled);
        assert_eq!(flow.priority, 10);
    }

    #[test]
    fn test_default_authentication_flow_resolver_creation() {
        let resolver = DefaultAuthenticationFlowResolver::new();

        // Should have initialized default flows
        let flows = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.get_available_flows())
            .unwrap();

        assert!(!flows.is_empty());
        assert!(flows.len() >= 3); // browser, direct grant, client auth
    }

    #[test]
    fn test_flow_resolution_browser_flow() {
        let resolver = DefaultAuthenticationFlowResolver::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("code".to_string()),
            grant_type: None,
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.resolve_flow(&context));

        assert!(result.is_ok());
        let flow = result.unwrap();
        assert_eq!(flow.flow_type, AuthenticationFlowType::Browser);
    }

    #[test]
    fn test_flow_resolution_direct_grant_flow() {
        let resolver = DefaultAuthenticationFlowResolver::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: None,
            grant_type: Some("password".to_string()),
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.resolve_flow(&context));

        assert!(result.is_ok());
        let flow = result.unwrap();
        assert_eq!(flow.flow_type, AuthenticationFlowType::DirectGrant);
    }

    #[test]
    fn test_flow_resolution_client_credentials_flow() {
        let resolver = DefaultAuthenticationFlowResolver::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: None,
            grant_type: Some("client_credentials".to_string()),
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.resolve_flow(&context));

        assert!(result.is_ok());
        let flow = result.unwrap();
        assert_eq!(flow.flow_type, AuthenticationFlowType::ClientAuthentication);
    }

    #[test]
    fn test_flow_resolution_default_to_browser() {
        let resolver = DefaultAuthenticationFlowResolver::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("unknown".to_string()),
            grant_type: Some("unknown".to_string()),
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.resolve_flow(&context));

        assert!(result.is_ok());
        let flow = result.unwrap();
        assert_eq!(flow.flow_type, AuthenticationFlowType::Browser);
    }

    #[test]
    fn test_authentication_session_manager_creation() {
        let _manager = AuthenticationSessionManager::new();
        // Should be created successfully
    }

    #[test]
    fn test_session_creation() {
        let mut manager = AuthenticationSessionManager::new();
        let client_id = "test_client".to_string();
        let flow_id = Uuid::new_v4().to_string();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.create_session(client_id.clone(), flow_id.clone()));

        assert!(result.is_ok());
        let session_id = result.unwrap();

        // Verify session was created
        let session_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.get_session(&session_id));

        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert_eq!(session.client_id, client_id);
        assert_eq!(session.flow_id.to_string(), flow_id);
        assert!(!session.completed);
    }

    #[test]
    fn test_session_creation_invalid_flow_id() {
        let mut manager = AuthenticationSessionManager::new();
        let client_id = "test_client".to_string();
        let invalid_flow_id = "invalid-uuid".to_string();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.create_session(client_id, invalid_flow_id));

        assert!(result.is_err());
    }

    #[test]
    fn test_get_nonexistent_session() {
        let manager = AuthenticationSessionManager::new();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.get_session("nonexistent"));

        assert!(result.is_err());
    }

    #[test]
    fn test_session_completion() {
        let mut manager = AuthenticationSessionManager::new();
        let client_id = "test_client".to_string();
        let flow_id = Uuid::new_v4().to_string();

        let session_id = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.create_session(client_id, flow_id))
            .unwrap();

        // Complete the session
        let complete_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.complete_session(&session_id));

        assert!(complete_result.is_ok());

        // Verify session is completed
        let session = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.get_session(&session_id))
            .unwrap();

        assert!(session.completed);
    }

    #[test]
    fn test_complete_nonexistent_session() {
        let mut manager = AuthenticationSessionManager::new();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.complete_session("nonexistent"));

        assert!(result.is_err());
    }

    #[test]
    fn test_authentication_manager_creation() {
        let _manager = AuthenticationManager::new();
        // Should be created successfully with default components
    }

    #[test]
    fn test_start_authentication_browser_flow() {
        let mut manager = AuthenticationManager::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("code".to_string()),
            grant_type: None,
            scopes: vec!["openid".to_string()],
            user_agent: Some("Mozilla/5.0".to_string()),
            client_ip: Some("127.0.0.1".to_string()),
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.start_authentication(&context));

        assert!(result.is_ok());
        let session_id = result.unwrap();
        assert!(!session_id.is_empty());
    }

    #[test]
    fn test_process_authentication_step() {
        let mut manager = AuthenticationManager::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("code".to_string()),
            grant_type: None,
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let session_id = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.start_authentication(&context))
            .unwrap();

        // Process authentication step
        let step_data = HashMap::from([
            ("username".to_string(), "testuser".to_string()),
            ("password".to_string(), "testpass".to_string()),
        ]);

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.process_authentication_step(&session_id, step_data));

        assert!(result.is_ok());
        let step_result = result.unwrap();
        assert!(step_result.success);
        assert!(step_result.completed);
    }

    #[test]
    fn test_process_authentication_step_missing_username() {
        let mut manager = AuthenticationManager::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("code".to_string()),
            grant_type: None,
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let session_id = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.start_authentication(&context))
            .unwrap();

        // Process authentication step without username
        let step_data = HashMap::from([("password".to_string(), "testpass".to_string())]);

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.process_authentication_step(&session_id, step_data));

        assert!(result.is_err());
    }

    #[test]
    fn test_process_authentication_step_missing_password() {
        let mut manager = AuthenticationManager::new();
        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("code".to_string()),
            grant_type: None,
            scopes: vec![],
            user_agent: None,
            client_ip: None,
            device_fingerprint: None,
            auth_method: None,
            parameters: HashMap::new(),
        };

        let session_id = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.start_authentication(&context))
            .unwrap();

        // Process authentication step without password
        let step_data = HashMap::from([("username".to_string(), "testuser".to_string())]);

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.process_authentication_step(&session_id, step_data));

        assert!(result.is_err());
    }

    #[test]
    fn test_process_authentication_step_invalid_session() {
        let mut manager = AuthenticationManager::new();

        let step_data = HashMap::from([
            ("username".to_string(), "testuser".to_string()),
            ("password".to_string(), "testpass".to_string()),
        ]);

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.process_authentication_step("invalid_session", step_data));

        assert!(result.is_err());
    }

    #[test]
    fn test_authentication_context_creation() {
        let mut parameters = HashMap::new();
        parameters.insert("custom_param".to_string(), "value".to_string());

        let context = AuthenticationContext {
            client_id: "test_client".to_string(),
            response_type: Some("code".to_string()),
            grant_type: Some("authorization_code".to_string()),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            user_agent: Some("TestAgent/1.0".to_string()),
            client_ip: Some("192.168.1.1".to_string()),
            device_fingerprint: Some("abc123".to_string()),
            auth_method: Some("password".to_string()),
            parameters,
        };

        assert_eq!(context.client_id, "test_client");
        assert_eq!(context.response_type, Some("code".to_string()));
        assert_eq!(context.grant_type, Some("authorization_code".to_string()));
        assert_eq!(context.scopes.len(), 2);
        assert_eq!(context.user_agent, Some("TestAgent/1.0".to_string()));
        assert_eq!(context.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(context.device_fingerprint, Some("abc123".to_string()));
        assert_eq!(context.auth_method, Some("password".to_string()));
        assert_eq!(
            context.parameters.get("custom_param"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_authentication_step_result_creation() {
        let mut data = HashMap::new();
        data.insert("token".to_string(), "abc123".to_string());

        let result = AuthenticationStepResult {
            success: true,
            completed: false,
            next_step: Some("mfa".to_string()),
            data,
        };

        assert!(result.success);
        assert!(!result.completed);
        assert_eq!(result.next_step, Some("mfa".to_string()));
        assert_eq!(result.data.get("token"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_flow_model_serialization() {
        let flow = AuthenticationFlowModel {
            id: Uuid::new_v4(),
            alias: "test_flow".to_string(),
            description: "Test flow".to_string(),
            flow_type: AuthenticationFlowType::Browser,
            realm_id: Uuid::new_v4(),
            enabled: true,
            priority: 5,
        };

        let serialized = serde_json::to_string(&flow).unwrap();
        let deserialized: AuthenticationFlowModel = serde_json::from_str(&serialized).unwrap();

        assert_eq!(flow.alias, deserialized.alias);
        assert_eq!(flow.description, deserialized.description);
        assert_eq!(flow.flow_type, deserialized.flow_type);
        assert_eq!(flow.enabled, deserialized.enabled);
        assert_eq!(flow.priority, deserialized.priority);
    }

    #[test]
    fn test_execution_model_creation() {
        use authenc::services::auth_flow::AuthenticationExecutionModel;

        let mut config = HashMap::new();
        config.insert("url".to_string(), "http://example.com".to_string());

        let execution = AuthenticationExecutionModel {
            id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            alias: "test_execution".to_string(),
            description: "Test execution".to_string(),
            execution_type: "authenticator".to_string(),
            enabled: true,
            priority: 10,
            configuration: config,
            requirements: vec!["user".to_string()],
        };

        assert_eq!(execution.alias, "test_execution");
        assert_eq!(execution.execution_type, "authenticator");
        assert!(execution.enabled);
        assert_eq!(execution.priority, 10);
        assert_eq!(execution.requirements.len(), 1);
        assert_eq!(
            execution.configuration.get("url"),
            Some(&"http://example.com".to_string())
        );
    }

    #[test]
    fn test_session_model_creation() {
        use authenc::services::auth_flow::AuthenticationSessionModel;

        let now = chrono::Utc::now();
        let mut session_data = HashMap::new();
        session_data.insert("key".to_string(), "value".to_string());

        let mut auth_notes = HashMap::new();
        auth_notes.insert("note".to_string(), "value".to_string());

        let session = AuthenticationSessionModel {
            id: Uuid::new_v4(),
            user_session_id: Some(Uuid::new_v4()),
            client_id: "test_client".to_string(),
            flow_id: Uuid::new_v4(),
            current_execution_id: Some(Uuid::new_v4()),
            started_at: now,
            expires_at: now + chrono::Duration::minutes(30),
            session_data,
            auth_notes,
            completed: false,
        };

        assert_eq!(session.client_id, "test_client");
        assert!(!session.completed);
        assert!(session.user_session_id.is_some());
        assert!(session.current_execution_id.is_some());
        assert_eq!(session.session_data.get("key"), Some(&"value".to_string()));
        assert_eq!(session.auth_notes.get("note"), Some(&"value".to_string()));
    }
}
