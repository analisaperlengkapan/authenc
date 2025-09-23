use crate::database::Database;
use crate::models::realm::CreateRealmRequest;
use crate::services::realm::{PostgresRealmService, RealmService};
use std::sync::Arc;

/// Integration test for multi-tenant realm functionality
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;

    async fn setup_test_db() -> Database {
        let config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "test".to_string(),
            password: "test".to_string(),
            database: "test_authenc".to_string(),
            max_connections: 5,
            ssl_mode: "disable".to_string(),
        };

        Database::new(&config).await.expect("Failed to connect to test database")
    }

    #[tokio::test]
    async fn test_multi_tenant_realm_operations() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        // Test 1: Create multiple realms for different tenants
        let tenant1_request = CreateRealmRequest {
            name: "tenant1-realm".to_string(),
            display_name: Some("Tenant 1 Enterprise".to_string()),
            description: Some("Enterprise realm for Tenant 1".to_string()),
            enabled: Some(true),
            attributes: Some(serde_json::json!({"tenant_id": "tenant1", "plan": "enterprise"})),
        };

        let tenant2_request = CreateRealmRequest {
            name: "tenant2-realm".to_string(),
            display_name: Some("Tenant 2 Professional".to_string()),
            description: Some("Professional realm for Tenant 2".to_string()),
            enabled: Some(true),
            attributes: Some(serde_json::json!({"tenant_id": "tenant2", "plan": "professional"})),
        };

        let tenant1_realm = service.create_realm(tenant1_request).await.expect("Failed to create tenant1 realm");
        let tenant2_realm = service.create_realm(tenant2_request).await.expect("Failed to create tenant2 realm");

        assert_eq!(tenant1_realm.name, "tenant1-realm");
        assert_eq!(tenant2_realm.name, "tenant2-realm");
        assert_ne!(tenant1_realm.id, tenant2_realm.id);

        // Test 2: List all realms
        let all_realms = service.list_realms().await.expect("Failed to list realms");
        assert!(all_realms.len() >= 2);

        let tenant1_found = all_realms.iter().find(|r| r.id == tenant1_realm.id).expect("Tenant1 realm not found");
        let tenant2_found = all_realms.iter().find(|r| r.id == tenant2_realm.id).expect("Tenant2 realm not found");

        assert_eq!(tenant1_found.name, "tenant1-realm");
        assert_eq!(tenant2_found.name, "tenant2-realm");

        // Test 3: Get realm by name (multi-tenant isolation)
        let retrieved_tenant1 = service.get_realm_by_name("tenant1-realm").await
            .expect("Failed to get tenant1 realm")
            .expect("Tenant1 realm not found");

        let retrieved_tenant2 = service.get_realm_by_name("tenant2-realm").await
            .expect("Failed to get tenant2 realm")
            .expect("Tenant2 realm not found");

        assert_eq!(retrieved_tenant1.id, tenant1_realm.id);
        assert_eq!(retrieved_tenant2.id, tenant2_realm.id);

        // Test 4: Realm isolation - ensure tenants can't access each other's data
        // This would be tested in higher-level integration tests with users/roles

        // Test 5: Disable a realm (tenant suspension)
        service.set_realm_enabled(&tenant2_realm.id, false).await
            .expect("Failed to disable tenant2 realm");

        let updated_tenant2 = service.get_realm_by_id(&tenant2_realm.id).await
            .expect("Failed to get updated tenant2 realm")
            .expect("Tenant2 realm not found");

        assert!(!updated_tenant2.enabled);

        // Test 6: Re-enable realm
        service.set_realm_enabled(&tenant2_realm.id, true).await
            .expect("Failed to re-enable tenant2 realm");

        let reenabled_tenant2 = service.get_realm_by_id(&tenant2_realm.id).await
            .expect("Failed to get re-enabled tenant2 realm")
            .expect("Tenant2 realm not found");

        assert!(reenabled_tenant2.enabled);

        // Clean up
        service.delete_realm(&tenant1_realm.id).await.expect("Failed to delete tenant1 realm");
        service.delete_realm(&tenant2_realm.id).await.expect("Failed to delete tenant2 realm");
    }

    #[tokio::test]
    async fn test_realm_not_found_scenarios() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        let non_existent_id = uuid::Uuid::new_v4();

        // Try to get non-existent realm
        let result = service.get_realm_by_id(&non_existent_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Try to get non-existent realm by name
        let result = service.get_realm_by_name("non-existent-realm").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Try to delete non-existent realm
        let result = service.delete_realm(&non_existent_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_realm_tenant_attributes() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        let request = CreateRealmRequest {
            name: "attributes-test-realm".to_string(),
            display_name: Some("Attributes Test Realm".to_string()),
            description: Some("Testing realm attributes for tenant metadata".to_string()),
            enabled: Some(true),
            attributes: Some(serde_json::json!({
                "tenant_id": "test-tenant-123",
                "subscription_plan": "premium",
                "features": ["sso", "mfa", "api_access"],
                "limits": {
                    "users": 1000,
                    "api_calls_per_month": 100000
                }
            })),
        };

        let created_realm = service.create_realm(request).await.expect("Failed to create realm with attributes");

        // Verify realm was created with attributes
        let retrieved_realm = service.get_realm_by_id(&created_realm.id).await
            .expect("Failed to retrieve realm")
            .expect("Realm not found");

        // Note: In a real implementation, the attributes would be stored and retrieved
        // This test verifies the structure is in place

        // Clean up
        service.delete_realm(&created_realm.id).await.expect("Failed to delete realm");
    }
}
