use authenc::config::DatabaseConfig;
use authenc::database::operations;
use authenc::database::Database;
use authenc::models::user::CreateUserRequest;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the same database config as the server
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "postgres".to_string(),
        password: "postgres".to_string(),
        database: "authenc".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database = Database::new(&database_config).await?;

    // Create test realm if it doesn't exist
    let realm_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;

    // Create test user
    let create_user_request = CreateUserRequest {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: Some("testpass".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        phone_number: None,
        realm_id: Some(realm_id),
        organization_id: None,
        attributes: None,
    };

    match operations::users::create_user(&database, &create_user_request).await {
        Ok(user) => println!("Created test user: {} with ID: {}", user.username, user.id),
        Err(e) => println!("Failed to create user: {}", e),
    }

    Ok(())
}
