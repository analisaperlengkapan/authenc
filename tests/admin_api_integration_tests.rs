use authenc::app::AppState;
use authenc::handlers::create_router;
use authenc_core::config::AppConfig;
use authenc_database::database::Database;
use authenc_services::services::admin::{CreateRoleRequest, CreateUserRequest, UpdateUserRequest};
use axum_test::TestServer;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

async fn setup_test_server() -> (TestServer, Database, Uuid) {
    let mut config = AppConfig::from_env().unwrap_or_default();
    // Ensure we use the test database
    if let Ok(test_db_url) = std::env::var("DATABASE_URL") {
         config.database.host = test_db_url;
    }

    let state = AppState::new(config).await.expect("Failed to create AppState");
    let realm_id = Uuid::new_v4();
    let realm_name = format!("admin-test-realm-{}", Uuid::new_v4());

    // Create test realm directly in DB for speed
    state.database.execute(
        "INSERT INTO realms (id, name, display_name, enabled, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
        &[&realm_id, &realm_name, &"Admin API Test Realm"],
    )
    .await
    .expect("Failed to create test realm");

    let router = create_router(Arc::new(state.clone()));
    let server = TestServer::new(router).expect("Failed to create test server");

    (server, (*state.database).clone(), realm_id)
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_admin_user_crud_flow() {
    let (server, db, realm_id) = setup_test_server().await;

    // 1. Create User
    let create_request = CreateUserRequest {
        username: "admin_test_user".to_string(),
        email: "admin_test@example.com".to_string(),
        password: Some("SecurePass123!".to_string()),
        first_name: Some("Admin".to_string()),
        last_name: Some("Test".to_string()),
        phone_number: None,
        realm_id,
        organization_id: None,
        roles: vec![],
        groups: vec![],
        attributes: None,
        email_verified: true,
        enabled: true,
        require_password_change: Some(false),
    };

    let response = server
        .post("/api/v1/admin/users")
        .json(&create_request)
        .await;

    response.assert_status_success();
    let user_resp: authenc_services::services::admin::UserResponse = response.json();
    assert_eq!(user_resp.username, "admin_test_user");
    let user_id = user_resp.id;

    // 2. Get User
    let response = server
        .get(&format!("/api/v1/admin/users/{}", user_id))
        .await;
    response.assert_status_success();
    let user_resp: authenc_services::services::admin::UserResponse = response.json();
    assert_eq!(user_resp.id, user_id);

    // 3. Update User
    let update_request = UpdateUserRequest {
        username: None,
        email: Some("updated_admin@example.com".to_string()),
        first_name: Some("Updated".to_string()),
        last_name: None,
        phone_number: None,
        roles: None,
        groups: None,
        email_verified: None,
        phone_verified: None,
        enabled: Some(false),
        require_password_change: None,
        attributes: None,
    };

    let response = server
        .put(&format!("/api/v1/admin/users/{}", user_id))
        .json(&update_request)
        .await;
    response.assert_status_success();
    let user_resp: authenc_services::services::admin::UserResponse = response.json();
    assert_eq!(user_resp.email, "updated_admin@example.com");
    assert!(!user_resp.enabled);

    // 4. List Users
    let response = server
        .get(&format!("/api/v1/admin/users?realm_id={}", realm_id))
        .await;
    response.assert_status_success();
    let list_resp: authenc_services::services::admin::UserListResponse = response.json();
    assert!(list_resp.users.iter().any(|u| u.id == user_id));

    // 5. Delete User
    let response = server
        .delete(&format!("/api/v1/admin/users/{}", user_id))
        .await;
    response.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Verify deletion
    let response = server
        .get(&format!("/api/v1/admin/users/{}", user_id))
        .await;
    response.assert_status(axum::http::StatusCode::NOT_FOUND);

    // Cleanup realm
    let _ = db.execute("DELETE FROM realms WHERE id = $1", &[&realm_id]).await;
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_admin_role_crud_flow() {
    let (server, db, realm_id) = setup_test_server().await;

    // 1. Create Role
    let create_request = CreateRoleRequest {
        name: "test_admin_role".to_string(),
        description: "A test role for admin API".to_string(),
        realm_id,
        composite: false,
        client_role: false,
        attributes: std::collections::HashMap::new(),
    };

    let response = server
        .post("/api/v1/admin/roles")
        .json(&create_request)
        .await;

    response.assert_status_success();
    let role_resp: authenc_services::services::admin::RoleResponse = response.json();
    assert_eq!(role_resp.name, "test_admin_role");
    let role_id = role_resp.id;

    // 2. Get Role
    let response = server
        .get(&format!("/api/v1/admin/roles/{}", role_id))
        .await;
    response.assert_status_success();
    let role_resp: authenc_services::services::admin::RoleResponse = response.json();
    assert_eq!(role_resp.id, role_id);

    // 3. Update Role
    let update_request = CreateRoleRequest {
        name: "test_admin_role".to_string(), // Name usually remains same or used for lookup
        description: "Updated description".to_string(),
        realm_id,
        composite: true,
        client_role: false,
        attributes: std::collections::HashMap::new(),
    };

    let response = server
        .put(&format!("/api/v1/admin/roles/{}", role_id))
        .json(&update_request)
        .await;
    response.assert_status_success();
    let role_resp: authenc_services::services::admin::RoleResponse = response.json();
    assert_eq!(role_resp.description, "Updated description");
    assert!(role_resp.composite);

    // 4. List Roles
    let response = server
        .get(&format!("/api/v1/admin/roles?realm_id={}", realm_id))
        .await;
    response.assert_status_success();
    let roles: Vec<authenc_services::services::admin::RoleResponse> = response.json();
    assert!(roles.iter().any(|r| r.id == role_id));

    // 5. Delete Role
    let response = server
        .delete(&format!("/api/v1/admin/roles/{}", role_id))
        .await;
    response.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Verify deletion
    let response = server
        .get(&format!("/api/v1/admin/roles/{}", role_id))
        .await;
    response.assert_status(axum::http::StatusCode::NOT_FOUND);

    // Cleanup realm
    let _ = db.execute("DELETE FROM realms WHERE id = $1", &[&realm_id]).await;
}
