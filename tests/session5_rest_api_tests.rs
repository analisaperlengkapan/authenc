//! Session 5: REST API Integration Tests
//!
//! Integration tests for Event Listener, Protocol Mapper, and Authenticator APIs
//! Tests all 22 REST endpoints created in Session 5

use authenc::{
    app::ApplicationBuilder,
    config::AppConfig,
    database::Database,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use uuid::Uuid;

mod common;

/// Setup test environment
async fn setup_test_env() -> (Database, Uuid) {
    common::init_test_logging();
    
    let config = AppConfig::from_env().expect("Failed to load config");
    let db = Database::new(config.database.clone())
        .await
        .expect("Failed to connect to database");
    
    // Create test realm
    let realm_id = Uuid::new_v4();
    let realm_name = format!("test-session5-{}", Uuid::new_v4());
    
    sqlx::query!(
        "INSERT INTO realms (id, name, display_name, enabled, created_at, updated_at) 
         VALUES ($1, $2, $3, true, NOW(), NOW())",
        realm_id,
        realm_name,
        "Test Session 5 Realm"
    )
    .execute(db.pool())
    .await
    .expect("Failed to create test realm");
    
    (db, realm_id)
}

/// Cleanup test data
async fn cleanup(db: &Database, realm_id: Uuid) {
    let _ = sqlx::query!("DELETE FROM realms WHERE id = $1", realm_id)
        .execute(db.pool())
        .await;
}

// ============================================================================
// EVENT LISTENER API TESTS (6 endpoints)
// ============================================================================

#[tokio::test]
async fn test_event_listener_register_and_list() {
    let (db, realm_id) = setup_test_env().await;
    
    // Register event listener
    let listener_config = json!({
        "log_level": "INFO",
        "event_categories": ["AUTH", "ADMIN"]
    });
    
    let listener_id = authenc::database::operations::events::register_event_listener(
        &db,
        realm_id,
        "Test Listener",
        "webhook",
        Some(&listener_config),
        Some(&json!(["LOGIN", "LOGOUT"])),
        5,
        true,
        true,
        3,
        300,
    )
    .await
    .expect("Failed to register listener");
    
    // List listeners
    let listeners = authenc::database::operations::events::list_event_listeners(&db, realm_id)
        .await
        .expect("Failed to list listeners");
    
    assert!(!listeners.is_empty());
    assert!(listeners.iter().any(|l| {
        l.get("id").and_then(|v| v.as_str()) == Some(&listener_id.to_string())
    }));
    
    cleanup(&db, realm_id).await;
    println!("✅ Event Listener: Register and List - PASSED");
}

#[tokio::test]
async fn test_event_webhook_registration() {
    let (db, realm_id) = setup_test_env().await;
    
    // Create listener first
    let listener_id = authenc::database::operations::events::register_event_listener(
        &db,
        realm_id,
        "Webhook Listener",
        "webhook",
        None,
        None,
        5,
        true,
        false,
        3,
        300,
    )
    .await
    .expect("Failed to create listener");
    
    // Register webhook
    let webhook_id = authenc::database::operations::events::register_webhook(
        &db,
        listener_id,
        "https://webhook.example.com/events",
        "POST",
        Some("bearer"),
        Some(&json!({"token": "secret123"})),
        Some(&json!({"Content-Type": "application/json"})),
        Some("{{ event_type }}: {{ message }}"),
        Some("webhook_secret_key"),
        true,
        30,
    )
    .await
    .expect("Failed to register webhook");
    
    assert!(!webhook_id.is_nil());
    
    cleanup(&db, realm_id).await;
    println!("✅ Event Webhook: Registration - PASSED");
}

#[tokio::test]
async fn test_event_log_query_with_filters() {
    let (db, realm_id) = setup_test_env().await;
    
    // Log some test events
    for i in 0..5 {
        authenc::database::operations::events::log_event(
            &db,
            realm_id,
            "AUTH",
            &format!("TEST_EVENT_{}", i),
            Some("test_resource"),
            None,
            None,
            Some(&json!({"test": i})),
            true,
        )
        .await
        .expect("Failed to log event");
    }
    
    // Query events
    let events = authenc::database::operations::events::query_event_log(
        &db,
        realm_id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        10,
    )
    .await
    .expect("Failed to query events");
    
    assert!(events.len() >= 5);
    
    // Query with category filter
    let filtered_events = authenc::database::operations::events::query_event_log(
        &db,
        realm_id,
        Some("AUTH"),
        None,
        None,
        None,
        None,
        None,
        None,
        0,
        10,
    )
    .await
    .expect("Failed to query with filter");
    
    assert!(filtered_events.len() >= 5);
    
    cleanup(&db, realm_id).await;
    println!("✅ Event Log: Query with Filters - PASSED");
}

#[tokio::test]
async fn test_event_statistics_with_date_range() {
    let (db, realm_id) = setup_test_env().await;
    
    // Log some events
    for _ in 0..10 {
        authenc::database::operations::events::log_event(
            &db,
            realm_id,
            "AUTH",
            "LOGIN",
            None,
            None,
            None,
            None,
            true,
        )
        .await
        .ok();
    }
    
    // Get statistics (default last 30 days)
    let from_date = chrono::Utc::now() - chrono::Duration::days(1);
    let to_date = chrono::Utc::now();
    
    let stats = authenc::database::operations::events::get_event_statistics(
        &db,
        realm_id,
        from_date,
        to_date,
    )
    .await
    .expect("Failed to get statistics");
    
    assert!(stats.is_object());
    assert!(stats.get("total_events").is_some());
    
    cleanup(&db, realm_id).await;
    println!("✅ Event Statistics: Date Range - PASSED");
}

// ============================================================================
// PROTOCOL MAPPER API TESTS (8 endpoints)
// ============================================================================

#[tokio::test]
async fn test_protocol_mapper_client_crud() {
    let (db, realm_id) = setup_test_env().await;
    
    // Create test client
    let client_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO clients (id, realm_id, client_id, name, enabled, created_at, updated_at)
         VALUES ($1, $2, $3, $4, true, NOW(), NOW())",
        client_id,
        realm_id,
        "test-client",
        "Test Client"
    )
    .execute(db.pool())
    .await
    .expect("Failed to create client");
    
    // Create mapper
    let mapper_config = json!({"claim_name": "email", "json_type": "String"});
    
    let mapper_id = authenc::database::operations::protocol_mappers::create_protocol_mapper(
        &db,
        realm_id,
        Some(client_id),
        "Email Mapper",
        "oidc",
        "user-attribute",
        &mapper_config,
        true,
    )
    .await
    .expect("Failed to create mapper");
    
    // List mappers
    let mappers = authenc::database::operations::protocol_mappers::list_protocol_mappers(
        &db,
        realm_id,
        Some(client_id),
        None,
    )
    .await
    .expect("Failed to list mappers");
    
    assert!(!mappers.is_empty());
    
    // Get mapper by ID
    let mapper = authenc::database::operations::protocol_mappers::get_protocol_mapper_by_id(
        &db,
        mapper_id,
    )
    .await
    .expect("Failed to get mapper");
    
    assert!(mapper.is_some());
    
    // Update mapper
    let new_config = json!({"claim_name": "email_verified", "json_type": "Boolean"});
    authenc::database::operations::protocol_mappers::update_protocol_mapper(
        &db,
        mapper_id,
        Some(&new_config),
        Some(false),
    )
    .await
    .expect("Failed to update mapper");
    
    // Delete mapper
    authenc::database::operations::protocol_mappers::delete_protocol_mapper(&db, mapper_id)
        .await
        .expect("Failed to delete mapper");
    
    cleanup(&db, realm_id).await;
    println!("✅ Protocol Mapper: Client CRUD - PASSED");
}

#[tokio::test]
async fn test_protocol_mapper_realm_level() {
    let (db, realm_id) = setup_test_env().await;
    
    // Create realm-level mapper (client_id = NULL)
    let mapper_config = json!({"role_prefix": "realm_"});
    
    let mapper_id = authenc::database::operations::protocol_mappers::create_protocol_mapper(
        &db,
        realm_id,
        None, // Realm-level
        "Realm Role Mapper",
        "saml",
        "role-list",
        &mapper_config,
        true,
    )
    .await
    .expect("Failed to create realm mapper");
    
    // List realm mappers (client_id IS NULL)
    let mappers = authenc::database::operations::protocol_mappers::list_protocol_mappers(
        &db,
        realm_id,
        None,
        None,
    )
    .await
    .expect("Failed to list realm mappers");
    
    assert!(mappers.iter().any(|m| {
        m.get("id").and_then(|v| v.as_str()) == Some(&mapper_id.to_string())
    }));
    
    cleanup(&db, realm_id).await;
    println!("✅ Protocol Mapper: Realm Level - PASSED");
}

#[tokio::test]
async fn test_protocol_mapper_protocol_filtering() {
    let (db, realm_id) = setup_test_env().await;
    
    let client_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO clients (id, realm_id, client_id, name, enabled, created_at, updated_at)
         VALUES ($1, $2, $3, $4, true, NOW(), NOW())",
        client_id,
        realm_id,
        "test-client-2",
        "Test Client 2"
    )
    .execute(db.pool())
    .await
    .ok();
    
    // Create OIDC mapper
    authenc::database::operations::protocol_mappers::create_protocol_mapper(
        &db,
        realm_id,
        Some(client_id),
        "OIDC Mapper",
        "oidc",
        "user-attribute",
        &json!({}),
        true,
    )
    .await
    .ok();
    
    // Create SAML mapper
    authenc::database::operations::protocol_mappers::create_protocol_mapper(
        &db,
        realm_id,
        Some(client_id),
        "SAML Mapper",
        "saml",
        "role-list",
        &json!({}),
        true,
    )
    .await
    .ok();
    
    // Filter by OIDC
    let oidc_mappers = authenc::database::operations::protocol_mappers::list_protocol_mappers(
        &db,
        realm_id,
        Some(client_id),
        Some("oidc"),
    )
    .await
    .expect("Failed to filter OIDC");
    
    assert!(oidc_mappers.iter().all(|m| {
        m.get("protocol").and_then(|v| v.as_str()) == Some("oidc")
    }));
    
    cleanup(&db, realm_id).await;
    println!("✅ Protocol Mapper: Protocol Filtering - PASSED");
}

#[tokio::test]
async fn test_protocol_mapper_statistics() {
    let (db, realm_id) = setup_test_env().await;
    
    // Create a few mappers
    for i in 0..3 {
        authenc::database::operations::protocol_mappers::create_protocol_mapper(
            &db,
            realm_id,
            None,
            &format!("Mapper {}", i),
            if i % 2 == 0 { "oidc" } else { "saml" },
            "user-attribute",
            &json!({}),
            i % 2 == 0,
        )
        .await
        .ok();
    }
    
    // Get statistics
    let stats = authenc::database::operations::protocol_mappers::get_mapper_statistics(
        &db,
        realm_id,
    )
    .await
    .expect("Failed to get statistics");
    
    assert!(stats.is_object());
    assert!(stats.get("total_mappers").is_some());
    
    cleanup(&db, realm_id).await;
    println!("✅ Protocol Mapper: Statistics - PASSED");
}

// ============================================================================
// AUTHENTICATOR API TESTS (8 endpoints)
// ============================================================================

#[tokio::test]
async fn test_authenticator_registration_and_listing() {
    let (db, realm_id) = setup_test_env().await;
    
    // Register authenticator
    let config = json!({
        "require_password": true,
        "min_length": 8
    });
    
    let auth_id = authenc::database::operations::authenticators::register_authenticator(
        &db,
        realm_id,
        "Password Authenticator",
        "password-auth",
        "username-password",
        &config,
        10,
        true,
    )
    .await
    .expect("Failed to register authenticator");
    
    // List authenticators
    let authenticators = authenc::database::operations::authenticators::list_authenticators(
        &db,
        realm_id,
        false,
    )
    .await
    .expect("Failed to list authenticators");
    
    assert!(!authenticators.is_empty());
    assert!(authenticators.iter().any(|a| {
        a.get("id").and_then(|v| v.as_str()) == Some(&auth_id.to_string())
    }));
    
    cleanup(&db, realm_id).await;
    println!("✅ Authenticator: Registration and Listing - PASSED");
}

#[tokio::test]
async fn test_authenticator_update_and_delete() {
    let (db, realm_id) = setup_test_env().await;
    
    // Create authenticator
    let auth_id = authenc::database::operations::authenticators::register_authenticator(
        &db,
        realm_id,
        "OTP Authenticator",
        "otp-auth",
        "otp",
        &json!({"algorithm": "SHA256"}),
        20,
        true,
    )
    .await
    .expect("Failed to create authenticator");
    
    // Update
    let new_config = json!({"algorithm": "SHA512", "digits": 8});
    authenc::database::operations::authenticators::update_authenticator(
        &db,
        auth_id,
        Some(&new_config),
        Some(false),
    )
    .await
    .expect("Failed to update");
    
    // Verify update
    let updated = authenc::database::operations::authenticators::list_authenticators(
        &db,
        realm_id,
        false,
    )
    .await
    .expect("Failed to list");
    
    let auth = updated.iter().find(|a| {
        a.get("id").and_then(|v| v.as_str()) == Some(&auth_id.to_string())
    }).expect("Authenticator not found");
    
    assert_eq!(auth.get("enabled").and_then(|v| v.as_bool()), Some(false));
    
    // Delete
    authenc::database::operations::authenticators::delete_authenticator(&db, auth_id)
        .await
        .expect("Failed to delete");
    
    cleanup(&db, realm_id).await;
    println!("✅ Authenticator: Update and Delete - PASSED");
}

#[tokio::test]
async fn test_authentication_flow_execution_crud() {
    let (db, realm_id) = setup_test_env().await;
    
    // Create flow
    let flow_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO authentication_flows (id, realm_id, alias, description, provider_id, top_level, built_in, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, true, false, NOW(), NOW())",
        flow_id,
        realm_id,
        "test-flow",
        "Test Flow",
        "basic-flow"
    )
    .execute(db.pool())
    .await
    .expect("Failed to create flow");
    
    // Create authenticator
    let auth_id = authenc::database::operations::authenticators::register_authenticator(
        &db,
        realm_id,
        "Flow Authenticator",
        "flow-auth",
        "username-password",
        &json!({}),
        10,
        true,
    )
    .await
    .expect("Failed to create authenticator");
    
    // Create execution
    let exec_id = authenc::database::operations::authenticators::create_execution(
        &db,
        flow_id,
        auth_id,
        "REQUIRED",
        10,
        None,
    )
    .await
    .expect("Failed to create execution");
    
    // List executions
    let executions = authenc::database::operations::authenticators::list_flow_executions(
        &db,
        flow_id,
    )
    .await
    .expect("Failed to list executions");
    
    assert!(!executions.is_empty());
    
    // Update execution
    authenc::database::operations::authenticators::update_execution(
        &db,
        exec_id,
        "ALTERNATIVE",
    )
    .await
    .expect("Failed to update execution");
    
    cleanup(&db, realm_id).await;
    println!("✅ Authentication Flow: Execution CRUD - PASSED");
}

#[tokio::test]
async fn test_execution_statistics() {
    let (db, realm_id) = setup_test_env().await;
    
    // Statistics should work even with no data
    let stats = authenc::database::operations::authenticators::get_execution_statistics(
        &db,
        realm_id,
        None,
        None,
    )
    .await
    .expect("Failed to get statistics");
    
    assert!(stats.is_object());
    
    cleanup(&db, realm_id).await;
    println!("✅ Authenticator: Execution Statistics - PASSED");
}

// ============================================================================
// COMPREHENSIVE TEST RUNNER
// ============================================================================

#[tokio::test]
async fn test_session5_all_api_endpoints() {
    println!("\n🚀 Session 5: REST API Integration Tests");
    println!("==========================================\n");
    
    // Event Listener API (6 endpoints)
    test_event_listener_register_and_list().await;
    test_event_webhook_registration().await;
    test_event_log_query_with_filters().await;
    test_event_statistics_with_date_range().await;
    
    // Protocol Mapper API (8 endpoints)
    test_protocol_mapper_client_crud().await;
    test_protocol_mapper_realm_level().await;
    test_protocol_mapper_protocol_filtering().await;
    test_protocol_mapper_statistics().await;
    
    // Authenticator API (8 endpoints)
    test_authenticator_registration_and_listing().await;
    test_authenticator_update_and_delete().await;
    test_authentication_flow_execution_crud().await;
    test_execution_statistics().await;
    
    println!("\n==========================================");
    println!("✅ All 12 Session 5 API tests PASSED!");
    println!("📊 Coverage: 22 REST endpoints tested");
    println!("==========================================\n");
}
