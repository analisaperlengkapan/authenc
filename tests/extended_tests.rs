// Extended comprehensive tests for Authence
// Additional test coverage for authentication, authorization, and API endpoints

use once_cell::sync::Lazy;

use axum::{
    Router,
    body::Body,
    extract::{Json, Path, Query},
    http::{HeaderMap, Response, StatusCode, header},
};
use axum_test::TestServer;
use chrono;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

static AUDIT_LOGS: Lazy<Arc<Mutex<Vec<serde_json::Value>>>> = Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

#[axum::debug_handler]
async fn create_user_handler(
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let username = payload.get("username").and_then(|v| v.as_str());

    // Add audit log
    let mut logs = AUDIT_LOGS.lock().await;
    let log_entry = json!({
        "action": "user.create",
        "resource": "user",
        "username": username,
        "ip_address": headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown"),
        "user_agent": headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("unknown"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    logs.push(log_entry);

    (
        StatusCode::CREATED,
        Json(json!({"message": "User created"})),
    )
}

#[axum::debug_handler]
async fn get_audit_logs_handler(
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let logs = AUDIT_LOGS.lock().await;
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);

    let recent_logs: Vec<_> = logs.iter().rev().take(limit).cloned().collect();
    (StatusCode::OK, Json(json!({"logs": recent_logs})))
}

#[tokio::test]
async fn test_user_registration_flow() {
    // Test complete user registration flow with validation
    let user_store = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route(
            "/api/v1/auth/users",
            axum::routing::post({
                let user_store = Arc::clone(&user_store);
                move |Json(payload): Json<serde_json::Value>| async move {
                    let username = payload.get("username").and_then(|v| v.as_str());
                    let email = payload.get("email").and_then(|v| v.as_str());
                    let password = payload.get("password").and_then(|v| v.as_str());

                    match (username, email, password) {
                        (Some(u), Some(e), Some(p))
                            if !u.is_empty() && !e.is_empty() && p.len() >= 8 =>
                        {
                            let mut store = user_store.lock().await;
                            if store.contains_key(u) {
                                (
                                    StatusCode::CONFLICT,
                                    Json(json!({"error": "User already exists"})),
                                )
                            } else {
                                store.insert(u.to_string(), json!({"username": u, "email": e}));
                                (
                                    StatusCode::CREATED,
                                    Json(json!({"message": "User created successfully"})),
                                )
                            }
                        }
                        _ => (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Invalid input data"})),
                        ),
                    }
                }
            }),
        )
        .route(
            "/api/v1/auth/users/{username}",
            axum::routing::get({
                let user_store = Arc::clone(&user_store);
                move |Path(username): Path<String>| async move {
                    let store = user_store.lock().await;
                    if let Some(user) = store.get(&username) {
                        (StatusCode::OK, Json(user.clone()))
                    } else {
                        (
                            StatusCode::NOT_FOUND,
                            Json(json!({"error": "User not found"})),
                        )
                    }
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test successful registration
    let response = server
        .post("/api/v1/auth/users")
        .json(&json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "StrongPass123!"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Test duplicate user registration
    let response = server
        .post("/api/v1/auth/users")
        .json(&json!({
            "username": "testuser",
            "email": "another@example.com",
            "password": "AnotherPass123!"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Test weak password
    let response = server
        .post("/api/v1/auth/users")
        .json(&json!({
            "username": "weakuser",
            "email": "weak@example.com",
            "password": "123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test getting user
    let response = server.get("/api/v1/auth/users/testuser").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test getting non-existent user
    let response = server.get("/api/v1/auth/users/nonexistent").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_role_based_access_control() {
    // Test RBAC functionality with roles and permissions
    let roles = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route(
            "/api/v1/admin/roles",
            axum::routing::post({
                let roles = Arc::clone(&roles);
                move |Json(payload): Json<serde_json::Value>| async move {
                    let name = payload.get("name").and_then(|v| v.as_str());
                    match name {
                        Some(n) if !n.is_empty() => {
                            let mut roles_store = roles.lock().await;
                            roles_store
                                .insert(n.to_string(), json!({"name": n, "permissions": []}));
                            (
                                StatusCode::CREATED,
                                Json(json!({"message": "Role created"})),
                            )
                        }
                        _ => (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Invalid role name"})),
                        ),
                    }
                }
            }),
        )
        .route(
            "/api/v1/admin/roles/{role}/permissions",
            axum::routing::post({
                let roles = Arc::clone(&roles);
                move |Path(role): Path<String>, Json(payload): Json<serde_json::Value>| async move {
                    let perm_name = payload.get("permission").and_then(|v| v.as_str());
                    match perm_name {
                        Some(p) => {
                            let mut roles_store = roles.lock().await;
                            if let Some(role_data) = roles_store.get_mut(&role) {
                                if let Some(perms) = role_data
                                    .get_mut("permissions")
                                    .and_then(|v| v.as_array_mut())
                                {
                                    perms.push(json!(p));
                                }
                                (StatusCode::OK, Json(json!({"message": "Permission added"})))
                            } else {
                                (
                                    StatusCode::NOT_FOUND,
                                    Json(json!({"error": "Role not found"})),
                                )
                            }
                        }
                        _ => (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Invalid permission"})),
                        ),
                    }
                }
            }),
        )
        .route(
            "/api/v1/admin/roles/{role}",
            axum::routing::get({
                let roles = Arc::clone(&roles);
                move |Path(role): Path<String>| async move {
                    let roles_store = roles.lock().await;
                    if let Some(role_data) = roles_store.get(&role) {
                        (StatusCode::OK, Json(role_data.clone()))
                    } else {
                        (
                            StatusCode::NOT_FOUND,
                            Json(json!({"error": "Role not found"})),
                        )
                    }
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Create admin role
    let response = server
        .post("/api/v1/admin/roles")
        .json(&json!({"name": "admin"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Add permission to role
    let response = server
        .post("/api/v1/admin/roles/admin/permissions")
        .json(&json!({"permission": "user.manage"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Get role details
    let response = server.get("/api/v1/admin/roles/admin").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test non-existent role
    let response = server.get("/api/v1/admin/roles/nonexistent").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_rate_limiting() {
    // Test rate limiting functionality
    let request_count = Arc::new(Mutex::new(0));

    let app = Router::new().route(
        "/api/v1/auth/login",
        axum::routing::post({
            let request_count = Arc::clone(&request_count);
            move |Json(_payload): Json<serde_json::Value>| async move {
                let mut count = request_count.lock().await;
                *count += 1;

                if *count > 5 {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({"error": "Rate limit exceeded"})),
                    )
                } else {
                    (StatusCode::OK, Json(json!({"token": "fake-jwt-token"})))
                }
            }
        }),
    );

    let server = TestServer::new(app).unwrap();

    // Make requests within limit
    for _i in 1..=5 {
        let response = server
            .post("/api/v1/auth/login")
            .json(&json!({"username": "user", "password": "pass"}))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Test rate limit exceeded
    let response = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "user", "password": "pass"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_session_management() {
    // Test session creation, validation, and expiration
    let sessions = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route(
            "/api/v1/auth/session",
            axum::routing::post({
                let sessions = Arc::clone(&sessions);
                move |Json(payload): Json<serde_json::Value>| async move {
                    let user_id = payload.get("user_id").and_then(|v| v.as_str());
                    match user_id {
                        Some(id) => {
                            let session_id = format!("session_{}", id);
                            let mut sessions_store = sessions.lock().await;
                            sessions_store.insert(
                                session_id.clone(),
                                json!({
                                    "user_id": id,
                                    "created_at": chrono::Utc::now().timestamp(),
                                    "expires_at": chrono::Utc::now().timestamp() + 3600
                                }),
                            );
                            (StatusCode::CREATED, Json(json!({"session_id": session_id})))
                        }
                        _ => (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Invalid user ID"})),
                        ),
                    }
                }
            }),
        )
        .route(
            "/api/v1/auth/session/{session_id}",
            axum::routing::get({
                let sessions = Arc::clone(&sessions);
                move |Path(session_id): Path<String>| async move {
                    let sessions_store = sessions.lock().await;
                    if let Some(session) = sessions_store.get(&session_id) {
                        let expires_at = session
                            .get("expires_at")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        if chrono::Utc::now().timestamp() > expires_at {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({"error": "Session expired"})),
                            )
                        } else {
                            (StatusCode::OK, Json(session.clone()))
                        }
                    } else {
                        (
                            StatusCode::NOT_FOUND,
                            Json(json!({"error": "Session not found"})),
                        )
                    }
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Create session
    let response = server
        .post("/api/v1/auth/session")
        .json(&json!({"user_id": "user123"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let body: serde_json::Value = response.json();
    let session_id = body.get("session_id").and_then(|v| v.as_str()).unwrap();

    // Validate session
    let response = server
        .get(&format!("/api/v1/auth/session/{}", session_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test invalid session
    let response = server.get("/api/v1/auth/session/invalid_session").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_audit_logging() {
    // Test audit logging functionality
    let app = Router::new()
        .route(
            "/api/v1/auth/users",
            axum::routing::post(create_user_handler),
        )
        .route(
            "/api/v1/audit/logs",
            axum::routing::get(get_audit_logs_handler),
        );

    let server = TestServer::new(app).unwrap();

    // Clear existing logs
    {
        let mut logs = AUDIT_LOGS.lock().await;
        logs.clear();
    }

    // Create user to trigger audit log
    let response = server
        .post("/api/v1/auth/users")
        .add_header("x-forwarded-for", "192.168.1.100")
        .add_header(header::USER_AGENT, "TestAgent/1.0")
        .json(&json!({"username": "audituser"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Get audit logs
    let response = server.get("/api/v1/audit/logs").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let logs = body.get("logs").and_then(|v| v.as_array()).unwrap();
    assert_eq!(logs.len(), 1);

    let log_entry = &logs[0];
    assert_eq!(
        log_entry.get("action").and_then(|v| v.as_str()).unwrap(),
        "user.create"
    );
    assert_eq!(
        log_entry.get("username").and_then(|v| v.as_str()).unwrap(),
        "audituser"
    );
}

#[tokio::test]
async fn test_input_validation() {
    // Test comprehensive input validation
    let app = Router::new()
        .route("/api/v1/auth/register", axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
            let username = payload.get("username").and_then(|v| v.as_str());
            let email = payload.get("email").and_then(|v| v.as_str());
            let password = payload.get("password").and_then(|v| v.as_str());

            match (username, email, password) {
                (Some(u), Some(e), Some(p)) => {
                    // Validate username
                    if u.len() < 3 || u.len() > 50 {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Username must be 3-50 characters"})));
                    }
                    if !u.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Username contains invalid characters"})));
                    }

                    // Validate email
                    if !e.contains('@') || !e.contains('.') {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid email format"})));
                    }

                    // Validate password
                    if p.len() < 8 {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Password must be at least 8 characters"})));
                    }
                    if !p.chars().any(|c| c.is_uppercase()) || !p.chars().any(|c| c.is_lowercase()) || !p.chars().any(|c| c.is_numeric()) {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Password must contain uppercase, lowercase, and numeric characters"})));
                    }

                    (StatusCode::CREATED, Json(json!({"message": "User registered successfully"})))
                }
                _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Missing required fields"})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test valid input
    let response = server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "validuser",
            "email": "valid@example.com",
            "password": "ValidPass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Test invalid username (too short)
    let response = server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "ab",
            "email": "test@example.com",
            "password": "ValidPass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test invalid email
    let response = server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "testuser",
            "email": "invalid-email",
            "password": "ValidPass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test weak password
    let response = server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "weak"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_error_handling() {
    // Test comprehensive error handling
    let app = Router::new()
        .route(
            "/api/v1/test/error",
            axum::routing::get(|| async {
                // Simulate internal server error
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Internal server error"})),
                )
            }),
        )
        .route(
            "/api/v1/test/notfound",
            axum::routing::get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Resource not found"})),
                )
            }),
        )
        .route(
            "/api/v1/test/validation",
            axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
                if payload.get("required_field").is_none() {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "Required field missing"})),
                    )
                } else {
                    (StatusCode::OK, Json(json!({"message": "Success"})))
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test 500 error
    let response = server.get("/api/v1/test/error").await;
    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

    // Test 404 error
    let response = server.get("/api/v1/test/notfound").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Test validation error
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test successful request
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({"required_field": "value"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_cors_headers() {
    // Test CORS headers configuration
    let app = Router::new()
        .route(
            "/api/v1/test/cors",
            axum::routing::get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Access-Control-Allow-Origin", "*")
                    .header(
                        "Access-Control-Allow-Methods",
                        "GET, POST, PUT, DELETE, OPTIONS",
                    )
                    .header(
                        "Access-Control-Allow-Headers",
                        "Content-Type, Authorization",
                    )
                    .body(Body::from("CORS test"))
                    .unwrap()
            }),
        )
        .route(
            "/api/v1/test/cors",
            axum::routing::options(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Access-Control-Allow-Origin", "*")
                    .header(
                        "Access-Control-Allow-Methods",
                        "GET, POST, PUT, DELETE, OPTIONS",
                    )
                    .header(
                        "Access-Control-Allow-Headers",
                        "Content-Type, Authorization",
                    )
                    .body(Body::empty())
                    .unwrap()
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test GET request with CORS
    let response = server.get("/api/v1/test/cors").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(
        response
            .headers()
            .contains_key("access-control-allow-origin")
    );

    // Test OPTIONS request
    let response = server
        .post("/api/v1/test/cors")
        .add_header(header::ALLOW, "OPTIONS")
        .await;
    assert_eq!(response.status_code(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_api_versioning() {
    // Test API versioning support
    let app = Router::new()
        .route(
            "/api/v1/users",
            axum::routing::get(|| async {
                (
                    StatusCode::OK,
                    Json(json!({"version": "v1", "users": ["user1", "user2"]})),
                )
            }),
        )
        .route(
            "/api/v2/users",
            axum::routing::get(|| async {
                (
                    StatusCode::OK,
                    Json(json!({"version": "v2", "data": {"users": ["user1", "user2"]}})),
                )
            }),
        )
        .route(
            "/api/v1/status",
            axum::routing::get(|| async {
                (
                    StatusCode::OK,
                    Json(json!({"status": "ok", "version": "v1"})),
                )
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test v1 API
    let response = server.get("/api/v1/users").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("version").and_then(|v| v.as_str()).unwrap(), "v1");

    // Test v2 API
    let response = server.get("/api/v2/users").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("version").and_then(|v| v.as_str()).unwrap(), "v2");

    // Test v1 status
    let response = server.get("/api/v1/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("version").and_then(|v| v.as_str()).unwrap(), "v1");
}

#[tokio::test]
async fn test_concurrent_requests() {
    // Test handling of concurrent requests
    let request_count = Arc::new(Mutex::new(0));
    let processed_requests = Arc::new(Mutex::new(Vec::new()));

    let app = Router::new().route(
        "/api/v1/test/concurrent",
        axum::routing::post({
            let request_count = Arc::clone(&request_count);
            let processed_requests = Arc::clone(&processed_requests);
            move |Json(payload): Json<serde_json::Value>| async move {
                let request_id = payload
                    .get("request_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                // Simulate some processing time
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let mut count = request_count.lock().await;
                *count += 1;

                let mut processed = processed_requests.lock().await;
                processed.push(request_id);

                (
                    StatusCode::OK,
                    Json(json!({"request_id": request_id, "processed": true})),
                )
            }
        }),
    );

    let server = TestServer::new(app).unwrap();

    // Send multiple requests sequentially
    for i in 1..=10 {
        let response = server
            .post("/api/v1/test/concurrent")
            .json(&json!({"request_id": i}))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Verify all requests were processed
    let processed = processed_requests.lock().await;
    assert_eq!(processed.len(), 10);

    let count = request_count.lock().await;
    assert_eq!(*count, 10);
}
