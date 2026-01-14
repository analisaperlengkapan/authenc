use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::models::user::{CreateUserRequest, UpdateUserRequest};
use authenc::services::stores::user_store::{UserStore, UserStoreTrait};
use std::fs;
use std::sync::Arc;
use uuid::Uuid;

// Test helper function to setup the test schema
async fn setup_test_schema(database: &Database) -> Result<(), Box<dyn std::error::Error>> {
    // Read the test schema file
    let schema_sql = fs::read_to_string("test_schema.sql")?;

    // Split the SQL into individual statements and execute them
    let statements: Vec<&str> = schema_sql.split(';').collect();
    for statement in statements {
        let trimmed = statement.trim();
        if !trimmed.is_empty() {
            database.execute(trimmed, &[]).await?;
        }
    }

    Ok(())
}

// Test helper function to create a test realm
async fn setup_test_realm(database: &Database) -> Result<Uuid, Box<dyn std::error::Error>> {
    let realm_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
    let realm_name = "test_realm".to_string();

    // Insert directly using the simple schema
    let query = r#"
        INSERT INTO realms (id, name, display_name, enabled)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO NOTHING
    "#;

    database
        .execute(query, &[&realm_id, &realm_name, &"Test Realm", &true])
        .await?;

    Ok(realm_id)
}

#[tokio::test]
async fn test_user_store_comprehensive_operations() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Setup the test schema
    if let Err(e) = setup_test_schema(&database).await {
        println!("Skipping test due to schema setup failure: {}", e);
        return;
    }

    // Clean up any existing test data
    let _ = database.execute("DELETE FROM users", &[]).await;
    let _ = database.execute("DELETE FROM realms", &[]).await;

    // Create test realm first
    let realm_id = match setup_test_realm(&database).await {
        Ok(id) => id,
        Err(e) => {
            println!("Skipping test due to realm creation failure: {}", e);
            return;
        }
    };

    let store = UserStore::new(database.clone());

    // Generate unique usernames for this test run
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let unique_suffix = format!("_{}", timestamp);

    // Test 1: Create multiple users
    let users = vec![
        CreateUserRequest {
            username: format!("alice{}", unique_suffix),
            email: format!("alice{}@example.com", unique_suffix),
            password: Some("hash1".into()),
            first_name: Some("Alice".into()),
            last_name: Some("Smith".into()),
            phone_number: Some("+1234567890".into()),
            realm_id: Some(realm_id),
            organization_id: None,
            attributes: None,
        },
        CreateUserRequest {
            username: format!("bob{}", unique_suffix),
            email: format!("bob{}@example.com", unique_suffix),
            password: Some("hash2".into()),
            first_name: Some("Bob".into()),
            last_name: Some("Johnson".into()),
            phone_number: None,
            realm_id: Some(realm_id),
            organization_id: None,
            attributes: None,
        },
    ];

    let mut created_users = Vec::new();
    for user_req in users {
        let user = store.add_user(user_req).await.unwrap();
        created_users.push(user);
    }

    assert_eq!(created_users.len(), 2);

    // Test 2: Retrieve users by different methods
    let alice_username = format!("alice{}", unique_suffix);
    let alice = store
        .get_user_by_username(&realm_id, &alice_username)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.username, alice_username);
    assert_eq!(alice.email, format!("alice{}@example.com", unique_suffix));

    let bob_username = format!("bob{}", unique_suffix);
    let bob = store
        .get_user_by_email(&realm_id, &format!("bob{}@example.com", unique_suffix))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bob.username, bob_username);

    // Test 3: Update user
    let alice_id = alice.id;
    let update_req = UpdateUserRequest {
        username: Some(format!("alice_updated{}", unique_suffix)),
        email: Some(format!("alice.updated{}@example.com", unique_suffix)),
        first_name: Some("Alice".into()),
        last_name: Some("Updated".into()),
        phone_number: Some("+1234567890".into()),
        enabled: Some(true),
        email_verified: Some(true),
        phone_verified: Some(false),
        require_password_change: Some(false),
        attributes: None,
    };
    let updated_alice = store.update_user(alice_id, update_req).await.unwrap();
    assert_eq!(
        updated_alice.username,
        format!("alice_updated{}", unique_suffix)
    );
    assert_eq!(
        updated_alice.email,
        format!("alice.updated{}@example.com", unique_suffix)
    );

    // Test 4: Verify updated user can still be retrieved
    let retrieved_alice = store.get_user(alice_id).await.unwrap().unwrap();
    assert_eq!(
        retrieved_alice.username,
        format!("alice_updated{}", unique_suffix)
    );

    // Test 5: Get all users
    let all_users = store.get_all().await.unwrap();
    assert!(all_users.len() >= 2);

    // Test 6: Test edge cases
    let non_existent_user = store.get_user(Uuid::new_v4()).await.unwrap();
    assert!(non_existent_user.is_none());

    let non_existent_username = store.get_user_by_username(&realm_id, "nonexistent").await.unwrap();
    assert!(non_existent_username.is_none());

    let non_existent_email = store
        .get_user_by_email(&realm_id, "nonexistent@example.com")
        .await
        .unwrap();
    assert!(non_existent_email.is_none());
}

#[tokio::test]
async fn test_user_store_error_handling() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Setup the test schema
    if let Err(e) = setup_test_schema(&database).await {
        println!("Skipping test due to schema setup failure: {}", e);
        return;
    }

    // Create test realm first
    let realm_id = match setup_test_realm(&database).await {
        Ok(id) => id,
        Err(e) => {
            println!("Skipping test due to realm creation failure: {}", e);
            return;
        }
    };

    let store = UserStore::new(database.clone());

    // Test updating non-existent user
    let fake_id = Uuid::new_v4();
    let update_req = UpdateUserRequest {
        username: Some("test".into()),
        email: None,
        first_name: None,
        last_name: None,
        phone_number: None,
        enabled: Some(true),
        email_verified: Some(false),
        phone_verified: Some(false),
        require_password_change: Some(false),
        attributes: None,
    };

    let result = store.update_user(fake_id, update_req).await;
    assert!(result.is_err()); // Should return an error for non-existent user
}

#[tokio::test]
async fn test_user_store_bulk_operations() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Setup the test schema
    if let Err(e) = setup_test_schema(&database).await {
        println!("Skipping test due to schema setup failure: {}", e);
        return;
    }

    // Clean up any existing test data
    let _ = database.execute("DELETE FROM users", &[]).await;
    let _ = database.execute("DELETE FROM realms", &[]).await;

    // Create test realm first
    let realm_id = match setup_test_realm(&database).await {
        Ok(id) => id,
        Err(e) => {
            println!("Skipping test due to realm creation failure: {}", e);
            return;
        }
    };

    let store = UserStore::new(database.clone());

    // Generate unique usernames for this test run
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let unique_suffix = format!("_{}", timestamp);

    // Create bulk users
    let mut bulk_users = Vec::new();
    for i in 0..10 {
        let user_req = CreateUserRequest {
            username: format!("bulk_user_{}{}", i, unique_suffix),
            email: format!("bulk{}_user{}@example.com", i, unique_suffix),
            password: Some(format!("hash_{}", i)),
            first_name: Some(format!("Bulk{}", i)),
            last_name: Some(format!("User{}", i)),
            phone_number: None,
            realm_id: Some(realm_id),
            organization_id: None,
            attributes: None,
        };
        bulk_users.push(user_req);
    }

    let mut created_bulk_users = Vec::new();
    for user_req in bulk_users {
        let user = store.add_user(user_req).await.unwrap();
        created_bulk_users.push(user);
    }

    assert_eq!(created_bulk_users.len(), 10);

    // Verify all users can be retrieved
    for user in &created_bulk_users {
        let retrieved = store.get_user(user.id).await.unwrap().unwrap();
        assert_eq!(retrieved.id, user.id);
    }

    // Verify get_all returns all users
    let all_users = store.get_all().await.unwrap();
    assert!(all_users.len() >= 10);
}
