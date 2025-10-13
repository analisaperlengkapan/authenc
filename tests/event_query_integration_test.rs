/// Integration test for event querying functionality
/// This test verifies that the Send safety fix works correctly
use authenc::spi::events::*;

#[tokio::test]
async fn test_event_provider_without_database() {
    // Create provider without database connection
    let provider = DefaultEventProvider::new_without_database();

    // Test that provider can be created (database field is private, so we just verify creation)
    // assert!(provider.database.is_none()); // Cannot access private field

    // Test query_events returns empty when no database
    let query = EventQuery {
        realm_id: Some("test".to_string()),
        user_id: None,
        client_id: None,
        event_types: None,
        date_from: None,
        date_to: None,
        ip_address: None,
        max_results: None,
        first_result: None,
    };

    let result = provider.query_events(query).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);

    // Test query_admin_events returns empty when no database
    let admin_query = AdminEventQuery {
        realm_id: Some("test".to_string()),
        resource_type: None,
        operation_type: None, // Changed from operation_types (singular, not plural)
        auth_user_id: None,
        ip_address: None, // Added missing field
        date_from: None,
        date_to: None,
        max_results: None,
        first_result: None,
    };

    let admin_result = provider.query_admin_events(admin_query).await;
    assert!(admin_result.is_ok());
    assert_eq!(admin_result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_event_storage_without_database() {
    use chrono::Utc;
    use std::collections::HashMap;

    let provider = DefaultEventProvider::new_without_database();

    // Test store_event succeeds even without database (no-op)
    let event = Event {
        id: "test-1".to_string(),
        time: Utc::now(),
        event_type: EventType::Login,
        realm_id: Some("test-realm".to_string()),
        client_id: Some("test-client".to_string()),
        user_id: Some("test-user".to_string()),
        session_id: None,
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        error: None,
        details: HashMap::new(),
    };

    let result = provider.store_event(event).await;
    assert!(result.is_ok());

    // Test store_admin_event succeeds even without database (no-op)
    let admin_event = AdminEvent {
        id: "admin-1".to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin".to_string(),
            ip_address: "127.0.0.1".to_string(),
            user_agent: None,
        },
        resource_type: "USER".to_string(),
        operation_type: AdminEventOperationType::Create,
        resource_path: Some("/users/123".to_string()),
        representation: None,
        error: None,
    };

    let admin_result = provider.store_admin_event(admin_event).await;
    assert!(admin_result.is_ok());
}

/// This test verifies that the async functions can be sent across threads
/// (i.e., they satisfy the Send bound required by async_trait)
#[tokio::test]
async fn test_send_safety() {
    let provider = DefaultEventProvider::new_without_database();

    // Spawn on a separate thread to verify Send bound
    let handle = tokio::spawn(async move {
        let query = EventQuery {
            realm_id: None,
            user_id: None,
            client_id: None,
            event_types: None,
            date_from: None,
            date_to: None,
            ip_address: None,
            max_results: None,
            first_result: None,
        };

        provider.query_events(query).await
    });

    let result = handle.await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}
