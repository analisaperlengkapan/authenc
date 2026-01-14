use std::collections::HashMap;
use std::sync::Arc;

use authenc::error::AuthencError;
use authenc::services::compliance::ComplianceFramework;
use authenc::services::compliance_mode::ComplianceEventManager;
use authenc::services::compliance_mode::ComplianceModeService;

#[cfg(test)]
mod tests {
    use super::*;

    // Mock event manager for testing
    struct MockEventManager;

    #[async_trait::async_trait]
    impl ComplianceEventManager for MockEventManager {
        async fn fire_event(
            &self,
            _event: authenc::models::events::Event,
        ) -> Result<(), AuthencError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_compliance_mode_enable_disable() {
        let event_manager = Arc::new(MockEventManager);
        let service = ComplianceModeService::new(event_manager, None);

        // Initially disabled
        assert!(!service.is_strict_mode().await);

        // Enable GDPR compliance
        service
            .enable_compliance_mode(vec![ComplianceFramework::GDPR], true)
            .await
            .unwrap();

        assert!(
            service
                .is_framework_enabled(&ComplianceFramework::GDPR)
                .await
        );
        assert!(service.is_strict_mode().await);

        // Check configuration
        let config = service.get_config().await;
        assert!(config.enabled);
        assert!(config.frameworks.contains(&ComplianceFramework::GDPR));
        assert!(config.strict_mode);

        // Disable compliance mode
        service.disable_compliance_mode().await.unwrap();

        assert!(
            !service
                .is_framework_enabled(&ComplianceFramework::GDPR)
                .await
        );
        assert!(!service.is_strict_mode().await);
    }

    #[tokio::test]
    async fn test_compliance_validation() {
        let event_manager = Arc::new(MockEventManager);
        let service = ComplianceModeService::new(event_manager, None);

        // Enable GDPR with strict mode
        service
            .enable_compliance_mode(vec![ComplianceFramework::GDPR], true)
            .await
            .unwrap();

        // Test valid data processing with consent
        let mut context = HashMap::new();
        context.insert("consent_obtained".to_string(), serde_json::json!(true));

        assert!(
            service
                .validate_operation("data_processing", &context)
                .await
                .is_ok()
        );

        // Test invalid data processing without consent
        let mut context = HashMap::new();
        context.insert("consent_obtained".to_string(), serde_json::json!(false));

        assert!(
            service
                .validate_operation("data_processing", &context)
                .await
                .is_err()
        );

        // Test data retention validation
        let mut context = HashMap::new();
        context.insert("data_age_days".to_string(), serde_json::json!(3000)); // Over 7 years

        assert!(
            service
                .validate_operation("data_retention", &context)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_hipaa_compliance_validation() {
        let event_manager = Arc::new(MockEventManager);
        let service = ComplianceModeService::new(event_manager, None);

        // Enable HIPAA compliance
        service
            .enable_compliance_mode(vec![ComplianceFramework::HIPAA], true)
            .await
            .unwrap();

        // Test unauthorized PHI access
        let mut context = HashMap::new();
        context.insert("authorized_access".to_string(), serde_json::json!(false));

        assert!(
            service
                .validate_operation("phi_access", &context)
                .await
                .is_err()
        );

        // Test unencrypted PHI storage
        let mut context = HashMap::new();
        context.insert("encrypted".to_string(), serde_json::json!(false));

        assert!(
            service
                .validate_operation("phi_storage", &context)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_multi_framework_compliance() {
        let event_manager = Arc::new(MockEventManager);
        let service = ComplianceModeService::new(event_manager, None);

        // Enable multiple frameworks
        service
            .enable_compliance_mode(
                vec![ComplianceFramework::GDPR, ComplianceFramework::SOX],
                false,
            )
            .await
            .unwrap();

        assert!(
            service
                .is_framework_enabled(&ComplianceFramework::GDPR)
                .await
        );
        assert!(
            service
                .is_framework_enabled(&ComplianceFramework::SOX)
                .await
        );
        assert!(
            !service
                .is_framework_enabled(&ComplianceFramework::HIPAA)
                .await
        );

        // Test SOX segregation of duties
        let mut context = HashMap::new();
        context.insert(
            "same_user_initiated_and_approved".to_string(),
            serde_json::json!(true),
        );

        assert!(
            service
                .validate_operation("financial_transaction", &context)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_framework_config() {
        let event_manager = Arc::new(MockEventManager);
        let service = ComplianceModeService::new(event_manager, None);

        // Enable GDPR
        service
            .enable_compliance_mode(vec![ComplianceFramework::GDPR], false)
            .await
            .unwrap();

        // Check GDPR config
        let gdpr_config = service
            .get_framework_config(&ComplianceFramework::GDPR)
            .await;
        assert!(gdpr_config.is_some());

        let config = gdpr_config.unwrap();
        assert_eq!(config["data_retention_days"], 2555);
        assert_eq!(config["consent_required"], true);
    }

    #[tokio::test]
    async fn test_compliance_with_consent_store() {
        let event_manager = Arc::new(MockEventManager);
        // Use Database::mock() which doesn't connect immediately
        let database = Arc::new(authenc::database::Database::mock().await);
        let consent_store = Arc::new(authenc::services::stores::ConsentStore::new(database));

        let service = ComplianceModeService::new(event_manager, Some(consent_store));

        // Enable GDPR
        service
            .enable_compliance_mode(vec![ComplianceFramework::GDPR], false)
            .await
            .unwrap();

        // Run checks
        let results = service.run_compliance_checks().await.unwrap();

        // Find consent management check by looking for specific evidence string
        // defined in GDPRConsentManagementCheck::execute
        let consent_check = results.iter().find(|r| {
            r.evidence
                .contains(&"Consent management system integrated".to_string())
        });

        assert!(
            consent_check.is_some(),
            "Consent management check should be present and passed"
        );
        let check = consent_check.unwrap();

        // Should be Compliant because consent_store is Some(_)
        match check.status {
            authenc::services::compliance::ComplianceStatus::Compliant => {}
            _ => panic!("Expected Compliant status, got {:?}", check.status),
        }
    }
}
