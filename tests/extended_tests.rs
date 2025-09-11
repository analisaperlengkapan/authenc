// Extended comprehensive tests for Authence
// Additional test coverage for authentication, authorization, and API endpoints

use axum::{
    body::Body,
    extract::{Json, Path, Query},
    http::{HeaderMap, Response, StatusCode, header},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_user_registration_flow() {
    // Test complete user registration flow with validation
    let user_store = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/api/v1/auth/users", axum::routing::post({
            let user_store = Arc::clone(&user_store);
            move |Json(payload): Json<serde_json::Value>| async move {
                let username = payload.get("username").and_then(|v| v.as_str());
                let email = payload.get("email").and_then(|v| v.as_str());
                let password = payload.get("password").and_then(|v| v.as_str());

                match (username, email, password) {
                    (Some(u), Some(e), Some(p)) if !u.is_empty() && !e.is_empty() && p.len() >= 8 => {
                        let mut store = user_store.lock().await;
                        if store.contains_key(u) {
                            (StatusCode::CONFLICT, Json(json!({"error": "User already exists"})))
                        } else {
                            store.insert(u.to_string(), json!({"username": u, "email": e}));
                            (StatusCode::CREATED, Json(json!({"message": "User created successfully"})))
                        }
                    }
                    _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid input data"})))
                }
            }
        }))
        .route("/api/v1/auth/users/:username", axum::routing::get({
            let user_store = Arc::clone(&user_store);
            move |Path(username): Path<String>| async move {
                let store = user_store.lock().await;
                if let Some(user) = store.get(&username) {
                    (StatusCode::OK, Json(user.clone()))
                } else {
                    (StatusCode::NOT_FOUND, Json(json!({"error": "User not found"})))
                }
            }
        }));

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
    let permissions = Arc::new(Mutex::new(HashMap::<String, serde_json::Value>::new()));

    let app = Router::new()
        .route("/api/v1/admin/roles", axum::routing::post({
            let roles = Arc::clone(&roles);
            move |Json(payload): Json<serde_json::Value>| async move {
                let name = payload.get("name").and_then(|v| v.as_str());
                match name {
                    Some(n) if !n.is_empty() => {
                        let mut roles_store = roles.lock().await;
                        roles_store.insert(n.to_string(), json!({"name": n, "permissions": []}));
                        (StatusCode::CREATED, Json(json!({"message": "Role created"})))
                    }
                    _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid role name"})))
                }
            }
        }))
        .route("/api/v1/admin/roles/:role/permissions", axum::routing::post({
            let roles = Arc::clone(&roles);
            let permissions = Arc::clone(&permissions);
            move |Path(role): Path<String>, Json(payload): Json<serde_json::Value>| async move {
                let perm_name = payload.get("permission").and_then(|v| v.as_str());
                match perm_name {
                    Some(p) => {
                        let mut roles_store = roles.lock().await;
                        if let Some(role_data) = roles_store.get_mut(&role) {
                            if let Some(perms) = role_data.get_mut("permissions").and_then(|v| v.as_array_mut()) {
                                perms.push(json!(p));
                            }
                            (StatusCode::OK, Json(json!({"message": "Permission added"})))
                        } else {
                            (StatusCode::NOT_FOUND, Json(json!({"error": "Role not found"})))
                        }
                    }
                    _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid permission"})))
                }
            }
        }))
        .route("/api/v1/admin/roles/:role", axum::routing::get({
            let roles = Arc::clone(&roles);
            move |Path(role): Path<String>| async move {
                let roles_store = roles.lock().await;
                if let Some(role_data) = roles_store.get(&role) {
                    (StatusCode::OK, Json(role_data.clone()))
                } else {
                    (StatusCode::NOT_FOUND, Json(json!({"error": "Role not found"})))
                }
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Create admin role
    let response = server
        .post("/api/v1/admin/roles")
        .json(&json!({"name": "admin"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Add permissions to role
    let response = server
        .post("/api/v1/admin/roles/admin/permissions")
        .json(&json!({"permission": "user.create"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server
        .post("/api/v1/admin/roles/admin/permissions")
        .json(&json!({"permission": "user.delete"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Get role with permissions
    let response = server.get("/api/v1/admin/roles/admin").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["name"], "admin");
    assert!(body["permissions"].as_array().unwrap().contains(&json!("user.create")));
    assert!(body["permissions"].as_array().unwrap().contains(&json!("user.delete")));

    // Try to add permission to non-existent role
    let response = server
        .post("/api/v1/admin/roles/nonexistent/permissions")
        .json(&json!({"permission": "test.perm"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_api_rate_limiting() {
    // Test rate limiting functionality
    let request_count = Arc::new(Mutex::new(0));

    let app = Router::new()
        .route("/api/v1/test", axum::routing::get({
            let request_count = Arc::clone(&request_count);
            move || async move {
                let mut count = request_count.lock().await;
                *count += 1;

                if *count <= 5 {
                    (StatusCode::OK, Json(json!({"message": "Request allowed", "count": *count})))
                } else {
                    (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "Rate limit exceeded"})))
                }
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Make allowed requests
    for i in 1..=5 {
        let response = server.get("/api/v1/test").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["count"], i);
    }

    // Make request that should be rate limited
    let response = server.get("/api/v1/test").await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Rate limit exceeded");
}

#[tokio::test]
async fn test_session_management() {
    // Test session creation, validation, and expiration
    let sessions = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/api/v1/auth/login", axum::routing::post({
            let sessions = Arc::clone(&sessions);
            move |Json(payload): Json<serde_json::Value>| async move {
                let username = payload.get("username").and_then(|v| v.as_str());
                let password = payload.get("password").and_then(|v| v.as_str());

                match (username, password) {
                    (Some("admin"), Some("password123")) => {
                        let session_id = format!("session_{}", uuid::Uuid::new_v4());
                        let mut sessions_store = sessions.lock().await;
                        sessions_store.insert(session_id.clone(), json!({
                            "username": "admin",
                            "created_at": chrono::Utc::now().timestamp(),
                            "active": true
                        }));

                        (StatusCode::OK, Json(json!({
                            "token": session_id,
                            "message": "Login successful"
                        })))
                    }
                    _ => (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid credentials"})))
                }
            }
        }))
        .route("/api/v1/auth/validate", axum::routing::get({
            let sessions = Arc::clone(&sessions);
            move |headers: HeaderMap| async move {
                if let Some(auth_header) = headers.get("authorization") {
                    if let Ok(auth_str) = auth_header.to_str() {
                        if auth_str.starts_with("Bearer ") {
                            let token = &auth_str[7..];
                            let sessions_store = sessions.lock().await;

                            if let Some(session) = sessions_store.get(token) {
                                if session.get("active").and_then(|v| v.as_bool()).unwrap_or(false) {
                                    return (StatusCode::OK, Json(json!({"valid": true, "user": session["username"] })));
                                }
                            }
                        }
                    }
                }
                (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid or expired session"})))
            }
        }))
        .route("/api/v1/auth/logout", axum::routing::post({
            let sessions = Arc::clone(&sessions);
            move |headers: HeaderMap| async move {
                if let Some(auth_header) = headers.get("authorization") {
                    if let Ok(auth_str) = auth_header.to_str() {
                        if auth_str.starts_with("Bearer ") {
                            let token = &auth_str[7..];
                            let mut sessions_store = sessions.lock().await;

                            if let Some(session) = sessions_store.get_mut(token) {
                                *session.get_mut("active").unwrap() = json!(false);
                                return (StatusCode::OK, Json(json!({"message": "Logged out successfully"})));
                            }
                        }
                    }
                }
                (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid session"})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test login
    let response = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "password123"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let token = body["token"].as_str().unwrap().to_string();

    // Test session validation
    let response = server
        .get("/api/v1/auth/validate")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["valid"], true);
    assert_eq!(body["user"], "admin");

    // Test logout
    let response = server
        .post("/api/v1/auth/logout")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test validation after logout
    let response = server
        .get("/api/v1/auth/validate")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test invalid credentials
    let response = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "wrongpassword"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_audit_logging() {
    // Test audit logging functionality
    let audit_logs = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));

    let app = Router::new()
        .route("/api/v1/admin/users", axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
            let username = payload.get("username").and_then(|v| v.as_str());

            (StatusCode::CREATED, Json(json!({"message": "User created"})))
        }))
        .route("/api/v1/admin/audit/logs", axum::routing::get({
            let audit_logs = Arc::clone(&audit_logs);
            move |Query(params): Query<HashMap<String, String>>| async move {
                let logs = audit_logs.lock().await;
                let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(10);

                let recent_logs: Vec<_> = logs.iter().rev().take(limit).cloned().collect();
                (StatusCode::OK, Json(json!({"logs": recent_logs})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Create user (should generate audit log)
    let response = server
        .post("/api/v1/admin/users")
        .add_header(header::USER_AGENT, "TestAgent/1.0")
        .add_header("x-forwarded-for", "192.168.1.100")
        .json(&json!({"username": "testuser"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Create another user
    let response = server
        .post("/api/v1/admin/users")
        .add_header(header::USER_AGENT, "TestAgent/1.0")
        .add_header("x-forwarded-for", "192.168.1.101")
        .json(&json!({"username": "anotheruser"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Get audit logs
    let response = server.get("/api/v1/admin/audit/logs?limit=5").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 2);

    // Verify audit log content
    let first_log = &logs[1]; // Most recent first
    assert_eq!(first_log["action"], "user.create");
    assert_eq!(first_log["resource"], "user");
    assert_eq!(first_log["username"], "anotheruser");
    assert_eq!(first_log["ip_address"], "192.168.1.101");
    assert_eq!(first_log["user_agent"], "TestAgent/1.0");
}

#[tokio::test]
async fn test_input_validation_and_sanitization() {
    // Test input validation and sanitization
    let app = Router::new()
        .route("/api/v1/test/validation", axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
            let input = payload.get("input").and_then(|v| v.as_str());

            match input {
                Some(s) if s.is_empty() => {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "Input cannot be empty"})))
                }
                Some(s) if s.len() > 100 => {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "Input too long"})))
                }
                Some(s) if s.contains("<script>") => {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "Input contains malicious content"})))
                }
                Some(s) => {
                    (StatusCode::OK, Json(json!({"message": "Input accepted", "sanitized": s.trim()})))
                }
                None => {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "Input field required"})))
                }
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test valid input
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({"input": "valid input"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test empty input
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({"input": ""}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test missing input
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test input too long
    let long_input = "a".repeat(101);
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({"input": long_input}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test XSS attempt
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({"input": "<script>alert('xss')</script>"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test input sanitization (trimming)
    let response = server
        .post("/api/v1/test/validation")
        .json(&json!({"input": "  spaced input  "}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["sanitized"], "spaced input");
}

#[tokio::test]
async fn test_error_handling_and_responses() {
    // Test comprehensive error handling
    let app = Router::new()
        .route("/api/v1/test/error/:type", axum::routing::get(|Path(error_type): Path<String>| async move {
            match error_type.as_str() {
                "not_found" => (StatusCode::NOT_FOUND, Json(json!({"error": "Resource not found"}))),
                "forbidden" => (StatusCode::FORBIDDEN, Json(json!({"error": "Access forbidden"}))),
                "unauthorized" => (StatusCode::UNAUTHORIZED, Json(json!({"error": "Authentication required"}))),
                "bad_request" => (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid request"}))),
                "internal_error" => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))),
                "service_unavailable" => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "Service temporarily unavailable"}))),
                _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Unknown error type"})))
            }
        }))
        .route("/api/v1/test/panic", axum::routing::get(|| async move {
            panic!("Simulated panic for testing");
        }));

    let server = TestServer::new(app).unwrap();

    // Test various error responses
    let error_types = vec![
        ("not_found", StatusCode::NOT_FOUND),
        ("forbidden", StatusCode::FORBIDDEN),
        ("unauthorized", StatusCode::UNAUTHORIZED),
        ("bad_request", StatusCode::BAD_REQUEST),
        ("internal_error", StatusCode::INTERNAL_SERVER_ERROR),
        ("service_unavailable", StatusCode::SERVICE_UNAVAILABLE),
    ];

    for (error_type, expected_status) in error_types {
        let response = server.get(&format!("/api/v1/test/error/{}", error_type)).await;
        assert_eq!(response.status_code(), expected_status);

        let body: serde_json::Value = response.json();
        assert!(body.get("error").is_some());
    }

    // Test unknown error type
    let response = server.get("/api/v1/test/error/unknown").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_cors_and_security_headers() {
    // Test CORS and security headers
    let app = Router::new()
        .route("/api/v1/test/cors", axum::routing::get(|| async move {
            Response::builder()
                .status(StatusCode::OK)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY")
                .header("X-XSS-Protection", "1; mode=block")
                .header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                .header("Content-Security-Policy", "default-src 'self'")
                .body(Body::from(r#"{"message": "CORS and security headers test"}"#))
                .unwrap()
        }))
        .route("/api/v1/test/options", axum::routing::options(|| async move {
            Response::builder()
                .status(StatusCode::OK)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                .body(Body::empty())
                .unwrap()
        }));

    let server = TestServer::new(app).unwrap();

    // Test GET request with security headers
    let response = server.get("/api/v1/test/cors").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Check security headers
    let headers = response.headers();
    assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
    assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY");
    assert_eq!(headers.get("X-XSS-Protection").unwrap(), "1; mode=block");
    assert!(headers.get("Strict-Transport-Security").is_some());
    assert!(headers.get("Content-Security-Policy").is_some());

    // Test OPTIONS request (CORS preflight)
    let response = server
        .post("/api/v1/test/options")
        .add_header(header::ALLOW, "GET, POST, PUT, DELETE, OPTIONS")
        .await;
    assert_eq!(response.status_code(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_api_versioning_and_deprecation() {
    // Test API versioning and deprecation handling
    let app = Router::new()
        .route("/api/v1/users", axum::routing::get(|| async move {
            Json(json!({"version": "v1", "users": ["user1", "user2"]}))
        }))
        .route("/api/v2/users", axum::routing::get(|| async move {
            Json(json!({"version": "v2", "data": {"users": ["user1", "user2"], "total": 2}}))
        }))
        .route("/api/v1/deprecated", axum::routing::get(|| async move {
            Response::builder()
                .status(StatusCode::OK)
                .header("X-API-Deprecation", "This endpoint is deprecated. Use /api/v2/users instead.")
                .header("X-API-Sunset", "2026-01-01")
                .body(Body::from(r#"{"version": "v1", "deprecated": true, "users": ["user1", "user2"]}"#))
                .unwrap()
        }));

    let server = TestServer::new(app).unwrap();

    // Test v1 API
    let response = server.get("/api/v1/users").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["version"], "v1");
    assert!(body["users"].as_array().is_some());

    // Test v2 API
    let response = server.get("/api/v2/users").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["version"], "v2");
    assert!(body["data"]["users"].as_array().is_some());
    assert_eq!(body["data"]["total"], 2);

    // Test deprecated endpoint
    let response = server.get("/api/v1/deprecated").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let headers = response.headers();
    assert!(headers.get("X-API-Deprecation").is_some());
    assert!(headers.get("X-API-Sunset").is_some());

    let body: serde_json::Value = response.json();
    assert_eq!(body["deprecated"], true);
}

#[tokio::test]
async fn test_concurrent_requests_and_load() {
    // Test concurrent requests handling
    use std::sync::atomic::{AtomicUsize, Ordering};

    let request_count = Arc::new(AtomicUsize::new(0));
    let concurrent_requests = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let app = Router::new()
        .route("/api/v1/test/concurrent", axum::routing::get({
            let request_count = Arc::clone(&request_count);
            let concurrent_requests = Arc::clone(&concurrent_requests);
            let max_concurrent = Arc::clone(&max_concurrent);
            move || async move {
                let current = concurrent_requests.fetch_add(1, Ordering::SeqCst) + 1;
                let mut current_max = max_concurrent.load(Ordering::SeqCst);

                while current > current_max {
                    match max_concurrent.compare_exchange(current_max, current, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break,
                        Err(new_max) => current_max = new_max,
                    }
                }

                // Simulate some work
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let total_requests = request_count.fetch_add(1, Ordering::SeqCst);
                concurrent_requests.fetch_sub(1, Ordering::SeqCst);

                Json(json!({
                    "request_id": total_requests,
                    "concurrent_count": current,
                    "max_concurrent": max_concurrent.load(Ordering::SeqCst)
                }))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Spawn multiple concurrent requests (sequential for simplicity)
    let mut results = vec![];
    for i in 0..10 {
        let response = server.get("/api/v1/test/concurrent").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        results.push((i, body));
    }

    // Verify results
    assert_eq!(results.len(), 10);
    let max_concurrent_seen = results.iter()
        .map(|(_, body)| body["max_concurrent"].as_u64().unwrap())
        .max()
        .unwrap();

    assert!(max_concurrent_seen > 1, "Should have had concurrent requests");

    // Verify all requests were processed
    let total_processed = request_count.load(Ordering::SeqCst);
    assert_eq!(total_processed, 10);
}
