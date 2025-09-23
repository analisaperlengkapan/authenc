use crate::database::Database;
use crate::models::realm::{CreateRealmRequest, UpdateRealmRequest};
use crate::services::realm::{PostgresRealmService, RealmService, RealmManager};
use std::sync::Arc;
use uuid::Uuid;

/// Test realm service functionality
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
    async fn test_create_and_get_realm() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        let request = CreateRealmRequest {
            name: "test-realm".to_string(),
            display_name: Some("Test Realm".to_string()),
            description: Some("A test realm for unit testing".to_string()),
            enabled: Some(true),
            attributes: None,
        };

        // Create realm
        let created_realm = service.create_realm(request).await.expect("Failed to create realm");

        assert_eq!(created_realm.name, "test-realm");
        assert_eq!(created_realm.display_name, Some("Test Realm".to_string()));
        assert!(created_realm.enabled);

        // Get realm by ID
        let retrieved_realm = service.get_realm_by_id(&created_realm.id).await
            .expect("Failed to get realm by ID")
            .expect("Realm not found");

        assert_eq!(retrieved_realm.id, created_realm.id);
        assert_eq!(retrieved_realm.name, "test-realm");

        // Get realm by name
        let retrieved_by_name = service.get_realm_by_name("test-realm").await
            .expect("Failed to get realm by name")
            .expect("Realm not found");

        assert_eq!(retrieved_by_name.id, created_realm.id);

        // Clean up
        service.delete_realm(&created_realm.id).await.expect("Failed to delete realm");
    }

    #[tokio::test]
    async fn test_update_realm() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        // Create initial realm
        let create_request = CreateRealmRequest {
            name: "update-test-realm".to_string(),
            display_name: Some("Update Test Realm".to_string()),
            description: Some("Initial description".to_string()),
            enabled: Some(true),
            attributes: None,
        };

        let created_realm = service.create_realm(create_request).await.expect("Failed to create realm");

        // Update realm
        let update_request = UpdateRealmRequest {
            display_name: Some("Updated Test Realm".to_string()),
            description: Some("Updated description".to_string()),
            enabled: Some(false),
            ssl_required: Some("all".to_string()),
            registration_allowed: Some(false),
            verify_email: Some(true),
            reset_password_allowed: Some(false),
            brute_force_protected: Some(true),
            attributes: Some(serde_json::json!({"custom": "value"})),
        };

        let updated_realm = service.update_realm(&created_realm.id, update_request).await
            .expect("Failed to update realm");

        assert_eq!(updated_realm.display_name, Some("Updated Test Realm".to_string()));
        assert_eq!(updated_realm.description, Some("Updated description".to_string()));
        assert!(!updated_realm.enabled);

        // Clean up
        service.delete_realm(&created_realm.id).await.expect("Failed to delete realm");
    }

    #[tokio::test]
    async fn test_list_realms() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        // Create multiple realms
        let realm1_request = CreateRealmRequest {
            name: "list-test-realm-1".to_string(),
            display_name: Some("List Test Realm 1".to_string()),
            description: None,
            enabled: Some(true),
            attributes: None,
        };

        let realm2_request = CreateRealmRequest {
            name: "list-test-realm-2".to_string(),
            display_name: Some("List Test Realm 2".to_string()),
            description: None,
            enabled: Some(false),
            attributes: None,
        };

        let created_realm1 = service.create_realm(realm1_request).await.expect("Failed to create realm 1");
        let created_realm2 = service.create_realm(realm2_request).await.expect("Failed to create realm 2");

        // List all realms
        let realms = service.list_realms().await.expect("Failed to list realms");

        assert!(realms.len() >= 2);

        let found_realm1 = realms.iter().find(|r| r.id == created_realm1.id).expect("Realm 1 not found in list");
        let found_realm2 = realms.iter().find(|r| r.id == created_realm2.id).expect("Realm 2 not found in list");

        assert_eq!(found_realm1.name, "list-test-realm-1");
        assert_eq!(found_realm2.name, "list-test-realm-2");
        assert!(found_realm1.enabled);
        assert!(!found_realm2.enabled);

        // Clean up
        service.delete_realm(&created_realm1.id).await.expect("Failed to delete realm 1");
        service.delete_realm(&created_realm2.id).await.expect("Failed to delete realm 2");
    }

    #[tokio::test]
    async fn test_realm_manager() {
        let db = setup_test_db().await;
        let service = Arc::new(PostgresRealmService::new(Arc::new(db)));
        let manager = RealmManager::new(service);

        // Create realm using manager
        let realm = manager.create_realm(
            "manager-test-realm",
            Some("Manager Test Realm".to_string()),
            Some("Created by RealmManager".to_string())
        ).await.expect("Failed to create realm via manager");

        assert_eq!(realm.name, "manager-test-realm");
        assert_eq!(realm.display_name, Some("Manager Test Realm".to_string()));

        // Get realm by name
        let retrieved = manager.get_realm("manager-test-realm").await
            .expect("Failed to get realm")
            .expect("Realm not found");

        assert_eq!(retrieved.id, realm.id);

        // Check if realm exists and is enabled
        let exists_and_enabled = manager.realm_exists_and_enabled("manager-test-realm").await
            .expect("Failed to check realm status");

        assert!(exists_and_enabled);

        // Disable realm
        manager.set_realm_status("manager-test-realm", false).await
            .expect("Failed to disable realm");

        let disabled_check = manager.realm_exists_and_enabled("manager-test-realm").await
            .expect("Failed to check disabled realm status");

        assert!(!disabled_check);

        // List active realms
        let active_realms = manager.list_active_realms().await.expect("Failed to list active realms");

        // The disabled realm should not be in the active list
        let found_in_active = active_realms.iter().any(|r| r.id == realm.id);
        assert!(!found_in_active);

        // Clean up
        let service = manager.service.as_ref();
        if let Ok(uuid) = Uuid::parse_str(&realm.id.to_string()) {
            service.delete_realm(&uuid).await.expect("Failed to delete realm");
        }
    }

    #[tokio::test]
    async fn test_realm_not_found() {
        let db = setup_test_db().await;
        let service = PostgresRealmService::new(Arc::new(db));

        let non_existent_id = Uuid::new_v4();

        // Try to get non-existent realm by ID
        let result = service.get_realm_by_id(&non_existent_id).await
            .expect("Database query should succeed");

        assert!(result.is_none());

        // Try to get non-existent realm by name
        let result = service.get_realm_by_name("non-existent-realm").await
            .expect("Database query should succeed");

        assert!(result.is_none());

        // Try to update non-existent realm
        let update_request = UpdateRealmRequest {
            display_name: Some("Should not work".to_string()),
            description: None,
            enabled: None,
            ssl_required: None,
            registration_allowed: None,
            verify_email: None,
            reset_password_allowed: None,
            brute_force_protected: None,
            attributes: None,
        };

        let result = service.update_realm(&non_existent_id, update_request).await;
        assert!(result.is_err());

        // Try to delete non-existent realm
        let result = service.delete_realm(&non_existent_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_realm_isolation() {
        let db = setup_test_db().await;
        let service1 = PostgresRealmService::new(Arc::new(db.clone()));
        let service2 = PostgresRealmService::new(Arc::new(db));

        // Create realm with service1
        let request = CreateRealmRequest {
            name: "isolation-test-realm".to_string(),
            display_name: Some("Isolation Test Realm".to_string()),
            description: None,
            enabled: Some(true),
            attributes: None,
        };

        let created_realm = service1.create_realm(request).await.expect("Failed to create realm");

        // Both services should be able to access the same realm
        let retrieved_by_service2 = service2.get_realm_by_id(&created_realm.id).await
            .expect("Service2 failed to get realm")
            .expect("Realm not found by service2");

        assert_eq!(retrieved_by_service2.id, created_realm.id);

        // Clean up
        service1.delete_realm(&created_realm.id).await.expect("Failed to delete realm");
    }
}</content>
<parameter name="filePath">/home/clouduser/authence/authenc/tests/realm_management_tests.rs
