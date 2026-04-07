use authenc::app::AppState;
use authenc::handlers::create_router;
use authenc_core::config::AppConfig;
use authenc_database::database::Database;
use authenc_services::services::admin::{CreateRoleRequest, CreateUserRequest, UpdateRoleRequest, UpdateUserRequest};
use axum_test::TestServer;
use std::sync::Arc;
use uuid::Uuid;

/// Guard that cleans up the test realm on drop, even if a test panics.
struct RealmCleanup {
    db: Database,
    realm_id: Uuid,
}

impl Drop for RealmCleanup {
    fn drop(&mut self) {
        // Best-effort cleanup using a blocking runtime handle.
        // If we're inside a tokio runtime, spawn a blocking cleanup.
        let db = self.db.clone();
        let realm_id = self.realm_id;
        // Use std::thread to avoid nested runtime panics
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(async {
                // Delete child records explicitly in dependency order.
                // The canonical schema uses ON DELETE CASCADE for users → realms,
                // but roles, user_roles, groups, user_groups, and policies are
                // defined in separate migrations whose FK constraints may not
                // cascade. Explicit cleanup prevents orphaned test data.

                // 1. user_roles / user_groups for users in this realm
                let _ = db.execute(
                    "DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE realm_id = $1)",
                    &[&realm_id],
                ).await;
                let _ = db.execute(
                    "DELETE FROM user_groups WHERE user_id IN (SELECT id FROM users WHERE realm_id = $1)",
                    &[&realm_id],
                ).await;

                // 2. roles and policies belonging to this realm
                let _ = db.execute(
                    "DELETE FROM roles WHERE realm_id = $1",
                    &[&realm_id],
                ).await;
                let _ = db.execute(
                    "DELETE FROM policies WHERE realm_id = $1",
                    &[&realm_id],
                ).await;

                // 3. users belonging to this realm
                let _ = db.execute(
                    "DELETE FROM users WHERE realm_id = $1",
                    &[&realm_id],
                ).await;

                // 4. the realm itself
                let _ = db.execute(
                    "DELETE FROM realms WHERE id = $1",
                    &[&realm_id],
                ).await;
            });
        })
        .join()
        .ok();
    }
}

async fn setup_test_server() -> (TestServer, Database, Uuid) {
    let mut config = AppConfig::from_env().unwrap_or_default();
    // Ensure we use the test database by parsing DATABASE_URL into its components.
    // AppConfig::from_env() already handles this, but the unwrap_or_default() fallback
    // would skip it, so we parse here as a safety net.
    if let Ok(test_db_url) = std::env::var("DATABASE_URL") {
        if let Ok(url) = url::Url::parse(&test_db_url) {
            if let Some(host) = url.host_str() {
                config.database.host = host.to_string();
            }
            if let Some(port) = url.port() {
                config.database.port = port;
            }
            if !url.username().is_empty() {
                config.database.username = url.username().to_string();
            }
            if let Some(password) = url.password() {
                config.database.password = password.to_string();
            }
            if let Some(mut segments) = url.path_segments() {
                if let Some(db) = segments.next() {
                    let db_name = db.trim_start_matches('/');
                    if !db_name.is_empty() {
                        config.database.database = db_name.to_string();
                    }
                }
            }
        }
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
    let _cleanup = RealmCleanup { db: db.clone(), realm_id };

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

    response.assert_status(axum::http::StatusCode::CREATED);
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
        organization_id: None,
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
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_admin_role_crud_flow() {
    let (server, db, realm_id) = setup_test_server().await;
    let _cleanup = RealmCleanup { db: db.clone(), realm_id };

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

    response.assert_status(axum::http::StatusCode::CREATED);
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
    let update_request = UpdateRoleRequest {
        name: None, // Keep existing name
        description: Some("Updated description".to_string()),
        composite: Some(true),
        client_role: None,
        attributes: None,
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
}
