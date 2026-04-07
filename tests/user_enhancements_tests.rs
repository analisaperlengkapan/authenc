use authenc_models::models::user::UserResponse;
use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;
use uuid::Uuid;
use std::sync::Arc;

mod common;

async fn setup_test_server() -> TestServer {
    let config = common::build_test_config().await;

    // Create a minimal AppState-like structure for the router
    let state = authenc::app::AppState::new(config).await.expect("Failed to create AppState");
    let state_arc = Arc::new(state);

    let app = authenc::handlers::create_router(state_arc);
    TestServer::new(app).expect("Failed to create test server")
}

#[tokio::test]
async fn test_delete_user_totp_endpoint() {
    // Skip if no DB
    let config = common::build_test_config().await;
    if authenc::database::Database::new(&config.database).await.is_err() {
        return;
    }

    let server = setup_test_server().await;

    // Create a test user first to get a token
    let realm_name = "master";
    let login_res = server.post("/api/v1/auth/login").json(&json!({
        "username": "admin",
        "password": "password",
        "realm": realm_name
    })).await;

    if login_res.status_code() != StatusCode::OK {
        println!("Skipping test: Admin login failed (probably no seeded data)");
        return;
    }

    let token = login_res.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();
    let auth_header = format!("Bearer {}", token);

    // Get a user ID from the list
    let users_res = server.get("/api/v1/auth/realms/00000000-0000-0000-0000-000000000000/users")
        .add_header("Authorization", auth_header.clone())
        .await;

    let user_id = users_res.json::<Vec<UserResponse>>()[0].id;

    // Test deleting TOTP
    let response = server
        .delete(&format!("/api/v1/auth/realms/00000000-0000-0000-0000-000000000000/users/{}/totp", user_id))
        .add_header("Authorization", auth_header)
        .await;

    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_password_policy_unified_error() {
    let config = common::build_test_config().await;
    if authenc::database::Database::new(&config.database).await.is_err() {
        return;
    }
    let server = setup_test_server().await;

    // Login as admin
    let login_res = server.post("/api/v1/auth/login").json(&json!({
        "username": "admin",
        "password": "password",
        "realm": "master"
    })).await;

    if login_res.status_code() != StatusCode::OK { return; }
    let token = login_res.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();

    // Attempt to create user with weak password
    let response = server
        .post("/api/v1/auth/realms/00000000-0000-0000-0000-000000000000/users")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "username": "weak-user",
            "email": "weak@example.com",
            "password": "123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body = response.json::<serde_json::Value>();
    assert_eq!(body["error"]["code"], "VALIDATION_ERROR");
    assert!(body["error"]["message"].as_str().unwrap().contains("Password policy"));
}

#[tokio::test]
async fn test_update_user_organization_id() {
    let config = common::build_test_config().await;
    if authenc::database::Database::new(&config.database).await.is_err() {
        return;
    }
    let server = setup_test_server().await;

    // Login as admin
    let login_res = server.post("/api/v1/auth/login").json(&json!({
        "username": "admin",
        "password": "password",
        "realm": "master"
    })).await;

    if login_res.status_code() != StatusCode::OK { return; }
    let token = login_res.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();
    let auth_header = format!("Bearer {}", token);

    // Get a user ID
    let users_res = server.get("/api/v1/auth/realms/00000000-0000-0000-0000-000000000000/users")
        .add_header("Authorization", auth_header.clone())
        .await;
    let user = &users_res.json::<Vec<UserResponse>>()[0];
    let user_id = user.id;

    // Update organization_id
    let org_id = Uuid::new_v4();
    let response = server
        .put(&format!("/api/v1/auth/realms/00000000-0000-0000-0000-000000000000/users/{}", user_id))
        .add_header("Authorization", auth_header.clone())
        .json(&json!({
            "username": user.username,
            "email": user.email,
            "organization_id": org_id
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify update
    let verify_res = server.get(&format!("/api/v1/auth/realms/00000000-0000-0000-0000-000000000000/users/{}", user_id))
        .add_header("Authorization", auth_header)
        .await;

    let updated_user = verify_res.json::<UserResponse>();
    assert_eq!(updated_user.organization_id, Some(org_id));
}
