#[cfg(test)]
mod tests {
    use authenc::spi::{ProviderFactory, Spi, rich_authorization::*};
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_rich_authorization_spi() {
        let spi = RichAuthorizationSpi::new();
        assert_eq!(spi.get_name(), "rich-authorization");
        assert!(!spi.is_internal());
        assert_eq!(
            spi.get_provider_class(),
            "org.keycloak.authorization.policy.provider.rar.RichAuthorizationProvider"
        );
        assert_eq!(
            spi.get_provider_factory_class(),
            "org.keycloak.authorization.policy.provider.rar.RichAuthorizationProviderFactory"
        );
    }

    #[test]
    fn test_rich_authorization_request_creation() {
        let subject = AuthorizationSubject {
            id: "user123".to_string(),
            attributes: HashMap::from([
                ("role".to_string(), vec!["admin".to_string()]),
                ("department".to_string(), vec!["engineering".to_string()]),
            ]),
        };

        let resource = AuthorizationResource {
            id: "resource456".to_string(),
            resource_type: "document".to_string(),
            attributes: HashMap::from([
                (
                    "classification".to_string(),
                    vec!["confidential".to_string()],
                ),
                ("owner".to_string(), vec!["user123".to_string()]),
            ]),
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let action = AuthorizationAction {
            id: "read".to_string(),
            attributes: HashMap::from([("method".to_string(), vec!["GET".to_string()])]),
        };

        let mut context = HashMap::new();
        context.insert(
            "ip_address".to_string(),
            serde_json::Value::String("192.168.1.1".to_string()),
        );
        context.insert(
            "user_agent".to_string(),
            serde_json::Value::String("Mozilla/5.0".to_string()),
        );

        let request = RichAuthorizationRequest {
            subject,
            resource,
            action,
            context,
            timestamp: Utc::now(),
        };

        assert_eq!(request.subject.id, "user123");
        assert_eq!(request.resource.resource_type, "document");
        assert_eq!(request.action.id, "read");
        assert!(request.context.contains_key("ip_address"));
    }

    #[test]
    fn test_default_rich_authorization_provider() {
        let provider = DefaultRichAuthorizationProvider::new();

        // Test supported resource types
        let supported_types = provider.get_supported_resource_types();
        assert_eq!(supported_types.len(), 1);
        assert_eq!(supported_types[0], "default");

        // Test resource type support
        assert!(provider.supports_resource_type("default"));
        assert!(!provider.supports_resource_type("unknown"));
    }

    #[tokio::test]
    async fn test_default_rich_authorization_provider_evaluation() {
        let provider = DefaultRichAuthorizationProvider::new();

        let request = RichAuthorizationRequest {
            subject: AuthorizationSubject {
                id: "user123".to_string(),
                attributes: HashMap::new(),
            },
            resource: AuthorizationResource {
                id: "resource456".to_string(),
                resource_type: "document".to_string(),
                attributes: HashMap::new(),
                scopes: vec!["read".to_string()],
            },
            action: AuthorizationAction {
                id: "read".to_string(),
                attributes: HashMap::new(),
            },
            context: HashMap::new(),
            timestamp: Utc::now(),
        };

        let decision = provider.evaluate(&request).await.unwrap();

        // Default provider should deny all requests
        assert!(!decision.permitted);
        assert!(decision.obligations.is_empty());
        assert!(decision.advice.is_empty());
        assert!(decision.context.is_empty());
    }

    #[test]
    fn test_authorization_decision_serialization() {
        let decision = AuthorizationDecision {
            permitted: true,
            obligations: vec![AuthorizationObligation {
                id: "audit".to_string(),
                parameters: HashMap::from([("level".to_string(), vec!["high".to_string()])]),
            }],
            advice: vec![AuthorizationAdvice {
                id: "mfa_required".to_string(),
                parameters: HashMap::from([("method".to_string(), vec!["totp".to_string()])]),
            }],
            context: HashMap::from([(
                "session_id".to_string(),
                serde_json::Value::String(Uuid::new_v4().to_string()),
            )]),
        };

        // Test serialization
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: AuthorizationDecision = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.permitted, decision.permitted);
        assert_eq!(deserialized.obligations.len(), 1);
        assert_eq!(deserialized.advice.len(), 1);
        assert!(deserialized.context.contains_key("session_id"));
    }

    #[test]
    fn test_provider_factory() {
        let factory = DefaultRichAuthorizationProviderFactory::new();
        assert_eq!(factory.get_id(), "default-rich-authorization");
    }

    #[tokio::test]
    async fn test_provider_factory_creation() {
        let factory = DefaultRichAuthorizationProviderFactory::new();
        let config = authenc::spi::ProviderConfig::default();

        let provider = factory.create(&config).unwrap();
        assert!(provider.supports_resource_type("default"));
    }
}
