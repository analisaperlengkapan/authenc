use authenc::config::AppConfig;
use authenc::database::Database;
use authenc::spi::events::{
    AdminEvent, AdminEventAuthDetails, AdminEventOperationType, Event, EventType,
    DefaultEventProvider, EventStoreProvider,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;

/// Helper function to create a test database
async fn create_test_database() -> Database {
    let config = AppConfig::default();
    Database::new(&config.database).await.unwrap()
}

#[tokio::test]
async fn test_store_event_success() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        event_type: EventType::Login,
        realm_id: Some("test-realm".to_string()),
        client_id: Some("test-client".to_string()),
        user_id: Some("test-user".to_string()),
        session_id: Some("test-session".to_string()),
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        error: None,
        details: HashMap::new(),
    };

    let result = provider.store_event(event).await;
    if let Err(e) = &result {
        eprintln!("Error storing event: {:?}", e);
    }
    assert!(result.is_ok(), "Store event should succeed: {:?}", result);
}

#[tokio::test]
async fn test_store_event_with_error() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        event_type: EventType::LoginError,
        realm_id: Some("test-realm".to_string()),
        client_id: Some("test-client".to_string()),
        user_id: Some("test-user".to_string()),
        session_id: Some("test-session".to_string()),
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        error: Some("Invalid credentials".to_string()),
        details: HashMap::new(),
    };

    let result = provider.store_event(event).await;
    assert!(result.is_ok(), "Store event with error should succeed");
}

#[tokio::test]
async fn test_store_event_multiple_types() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let event_types = vec![
        EventType::Login,
        EventType::Register,
        EventType::Logout,
        EventType::UpdateProfile,
        EventType::UpdatePassword,
    ];

    for event_type in event_types {
        let event = Event {
            id: uuid::Uuid::new_v4().to_string(),
            time: Utc::now(),
            event_type,
            realm_id: Some("test-realm".to_string()),
            client_id: Some("test-client".to_string()),
            user_id: Some("test-user".to_string()),
            session_id: Some("test-session".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            error: None,
            details: HashMap::new(),
        };

        let result = provider.store_event(event).await;
        assert!(result.is_ok(), "Store event type {:?} should succeed", event_type);
    }
}

#[tokio::test]
async fn test_store_admin_event_create() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let admin_event = AdminEvent {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin-user-123".to_string(),
            ip_address: "10.0.0.1".to_string(),
            user_agent: Some("Admin Console".to_string()),
        },
        resource_type: "USER".to_string(),
        operation_type: AdminEventOperationType::Create,
        resource_path: Some("/users/123".to_string()),
        representation: Some(r#"{"username":"testuser"}"#.to_string()),
        error: None,
    };

    let result = provider.store_admin_event(admin_event).await;
    assert!(result.is_ok(), "Store admin event should succeed");
}

#[tokio::test]
async fn test_store_admin_event_update() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let admin_event = AdminEvent {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin-user-456".to_string(),
            ip_address: "10.0.0.2".to_string(),
            user_agent: Some("Admin API".to_string()),
        },
        resource_type: "CLIENT".to_string(),
        operation_type: AdminEventOperationType::Update,
        resource_path: Some("/clients/client-123".to_string()),
        representation: Some(r#"{"client_id":"test-client","enabled":true}"#.to_string()),
        error: None,
    };

    let result = provider.store_admin_event(admin_event).await;
    assert!(result.is_ok(), "Store admin update event should succeed");
}

#[tokio::test]
async fn test_store_admin_event_delete() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let admin_event = AdminEvent {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin-user-789".to_string(),
            ip_address: "10.0.0.3".to_string(),
            user_agent: None,
        },
        resource_type: "REALM".to_string(),
        operation_type: AdminEventOperationType::Delete,
        resource_path: Some("/realms/test-realm".to_string()),
        representation: None,
        error: None,
    };

    let result = provider.store_admin_event(admin_event).await;
    assert!(result.is_ok(), "Store admin delete event should succeed");
}

#[tokio::test]
async fn test_store_admin_event_action() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let admin_event = AdminEvent {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin-user-101".to_string(),
            ip_address: "10.0.0.4".to_string(),
            user_agent: Some("Admin Portal".to_string()),
        },
        resource_type: "USER".to_string(),
        operation_type: AdminEventOperationType::Action,
        resource_path: Some("/users/123/reset-password".to_string()),
        representation: None,
        error: None,
    };

    let result = provider.store_admin_event(admin_event).await;
    assert!(result.is_ok(), "Store admin action event should succeed");
}

#[tokio::test]
async fn test_store_admin_event_with_error() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let admin_event = AdminEvent {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin-user-202".to_string(),
            ip_address: "10.0.0.5".to_string(),
            user_agent: Some("Admin CLI".to_string()),
        },
        resource_type: "GROUP".to_string(),
        operation_type: AdminEventOperationType::Create,
        resource_path: Some("/groups/new-group".to_string()),
        representation: Some(r#"{"name":"new-group"}"#.to_string()),
        error: Some("Group already exists".to_string()),
    };

    let result = provider.store_admin_event(admin_event).await;
    assert!(result.is_ok(), "Store admin event with error should succeed");
}

#[tokio::test]
async fn test_store_event_with_details() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    let mut details = HashMap::new();
    details.insert("auth_method".to_string(), "password".to_string());
    details.insert("remember_me".to_string(), "true".to_string());
    details.insert("redirect_uri".to_string(), "https://example.com/callback".to_string());

    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        event_type: EventType::Login,
        realm_id: Some("test-realm".to_string()),
        client_id: Some("web-app".to_string()),
        user_id: Some("user-123".to_string()),
        session_id: Some("session-456".to_string()),
        ip_address: Some("203.0.113.45".to_string()),
        user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
        error: None,
        details,
    };

    let result = provider.store_event(event).await;
    assert!(result.is_ok(), "Store event with details should succeed");
}

#[tokio::test]
async fn test_store_multiple_events_bulk() {
    let db = Arc::new(create_test_database().await);
    let provider = DefaultEventProvider::new(db);

    // Store 10 events
    for i in 0..10 {
        let event = Event {
            id: uuid::Uuid::new_v4().to_string(),
            time: Utc::now(),
            event_type: if i % 2 == 0 { EventType::Login } else { EventType::Logout },
            realm_id: Some("test-realm".to_string()),
            client_id: Some(format!("client-{}", i)),
            user_id: Some(format!("user-{}", i)),
            session_id: Some(format!("session-{}", i)),
            ip_address: Some(format!("192.168.1.{}", i)),
            user_agent: Some("Test Agent".to_string()),
            error: None,
            details: HashMap::new(),
        };

        let result = provider.store_event(event).await;
        assert!(result.is_ok(), "Store event {} should succeed", i);
    }
}

#[tokio::test]
async fn test_event_without_database() {
    let provider = DefaultEventProvider::new_without_database();

    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        event_type: EventType::Login,
        realm_id: Some("test-realm".to_string()),
        client_id: None,
        user_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        error: None,
        details: HashMap::new(),
    };

    // Should succeed even without database (no-op)
    let result = provider.store_event(event).await;
    assert!(result.is_ok(), "Store event without database should succeed (no-op)");
}

#[tokio::test]
async fn test_admin_event_without_database() {
    let provider = DefaultEventProvider::new_without_database();

    let admin_event = AdminEvent {
        id: uuid::Uuid::new_v4().to_string(),
        time: Utc::now(),
        realm_id: "test-realm".to_string(),
        auth_details: AdminEventAuthDetails {
            user_id: "admin-user".to_string(),
            ip_address: "10.0.0.1".to_string(),
            user_agent: None,
        },
        resource_type: "USER".to_string(),
        operation_type: AdminEventOperationType::Create,
        resource_path: None,
        representation: None,
        error: None,
    };

    // Should succeed even without database (no-op)
    let result = provider.store_admin_event(admin_event).await;
    assert!(result.is_ok(), "Store admin event without database should succeed (no-op)");
}
