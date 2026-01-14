use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::models::user::{CreateUserRequest, User};
use authenc::services::stores::user_store::{UserStore, UserStoreTrait};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn user_store_basic_flow() {
    // Create a test database configuration
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
    let store = UserStore::new(database);

    let request = CreateUserRequest {
        username: "alice".into(),
        email: "alice@example.com".into(),
        password: Some("password123".into()),
        first_name: None,
        last_name: None,
        phone_number: None,
        realm_id: Some(Uuid::new_v4()),
        organization_id: None,
        attributes: None,
    };

    let user = store.add_user(request).await.unwrap();
    let id = user.id;

    let all_users = store.get_all().await.unwrap();
    assert_eq!(all_users.len(), 1);

    let retrieved_user = store.get_user(id).await.unwrap().expect("User not found");
    assert_eq!(retrieved_user.username, "alice");
    assert!(store.get_user_by_username(user.realm_id.as_ref().unwrap(), "alice").await.unwrap().is_some());

    // Proper password hashing and verification
    let password_hash = retrieved_user
        .password_hash
        .expect("Password hash should be present");
    assert_ne!(password_hash, "password123", "Password should be hashed");
    assert!(
        authenc::utils::crypto::password::verify_password(&password_hash, "password123").await.unwrap(),
        "Password verification failed"
    );
    assert!(
        !authenc::utils::crypto::password::verify_password(&password_hash, "wrongpassword")
            .await
            .unwrap(),
        "Wrong password should fail verification"
    );
}
