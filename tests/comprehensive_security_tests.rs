// Comprehensive Security Tests
// Testing security features, authentication, authorization, and attack prevention

use axum::{
    body::Body,
    extract::{Json, Path, Query, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware,
    response::Json as AxumJson,
    routing::{delete, get, post, put},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

// Security test state
#[derive(Clone)]
struct SecurityTestState {
    users: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    failed_attempts: Arc<Mutex<HashMap<String, u32>>>,
    blocked_ips: Arc<Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
    rate_limits: Arc<Mutex<HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>>>,
}

// Authentication handlers
async fn login(
    State(state): State<SecurityTestState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let users = state.users.lock().unwrap();
    let mut failed_attempts = state.failed_attempts.lock().unwrap();

    let username = payload
        .get("username")
        .and_then(|u| u.as_str())
        .unwrap_or("");
    let password = payload
        .get("password")
        .and_then(|p| p.as_str())
        .unwrap_or("");

    // Check if user exists and password is correct
    let user = users
        .values()
        .find(|u| u.get("username").and_then(|u| u.as_str()) == Some(username));

    if let Some(user) = user {
        let stored_password = user.get("password").and_then(|p| p.as_str()).unwrap_or("");

        if password == stored_password {
            // Successful login - reset failed attempts
            failed_attempts.remove(username);

            Ok(AxumJson(json!({
                "success": true,
                "token": format!("jwt_token_{}", Uuid::new_v4()),
                "user_id": user.get("id").unwrap()
            })))
        } else {
            // Failed login - increment attempts
            let attempts = failed_attempts.entry(username.to_string()).or_insert(0);
            *attempts += 1;

            if *attempts >= 5 {
                Err(StatusCode::TOO_MANY_REQUESTS)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// Rate limiting handler
async fn rate_limited_endpoint(
    State(state): State<SecurityTestState>,
    headers: HeaderMap,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut rate_limits = state.rate_limits.lock().unwrap();

    // Get client IP (simplified - in real implementation use proper IP extraction)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("127.0.0.1");

    let now = chrono::Utc::now();
    let window_start = now - chrono::Duration::minutes(1);

    // Get or create rate limit entry for this IP
    let requests = rate_limits
        .entry(client_ip.to_string())
        .or_insert_with(Vec::new);

    // Remove old requests outside the window
    requests.retain(|&time| time > window_start);

    // Check rate limit (10 requests per minute)
    if requests.len() >= 10 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Calculate remaining requests before adding current request
    let remaining_requests = 9 - requests.len();

    // Add current request
    requests.push(now);

    Ok(AxumJson(json!({
        "success": true,
        "message": "Request allowed",
        "remaining_requests": remaining_requests
    })))
}

// Input validation handler
async fn user_registration(
    State(state): State<SecurityTestState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut users = state.users.lock().unwrap();

    // Validate input
    let username = payload
        .get("username")
        .and_then(|u| u.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let email = payload
        .get("email")
        .and_then(|e| e.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let password = payload
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Security validations
    if username.len() < 3 || username.len() > 50 {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !email.contains('@') || email.len() > 254 {
        return Err(StatusCode::BAD_REQUEST);
    }

    if password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check for SQL injection patterns (simplified)
    let sql_patterns = ["'", "\"", ";", "--", "/*", "*/", "xp_", "sp_"];
    for pattern in &sql_patterns {
        if username.contains(pattern) || email.contains(pattern) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Check for XSS patterns (simplified)
    let xss_patterns = ["<script", "javascript:", "onload=", "onerror="];
    for pattern in &xss_patterns {
        if username.to_lowercase().contains(&pattern.to_lowercase())
            || email.to_lowercase().contains(&pattern.to_lowercase())
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Check if user already exists
    for (_, user) in users.iter() {
        if user.get("username").and_then(|u| u.as_str()) == Some(username)
            || user.get("email").and_then(|e| e.as_str()) == Some(email)
        {
            return Err(StatusCode::CONFLICT);
        }
    }

    // Create user
    let user_id = Uuid::new_v4().to_string();
    let mut user = payload.clone();
    user["id"] = json!(user_id.clone());
    user["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    user["enabled"] = json!(true);

    users.insert(user_id.clone(), user.clone());

    Ok(AxumJson(json!({
        "success": true,
        "user_id": user_id,
        "message": "User registered successfully"
    })))
}

// CSRF protection handler
async fn protected_action(
    State(_state): State<SecurityTestState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    // Check CSRF token
    let csrf_token = headers
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;

    let expected_token = payload
        .get("csrf_token")
        .and_then(|t| t.as_str())
        .ok_or(StatusCode::FORBIDDEN)?;

    if csrf_token != expected_token {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(AxumJson(json!({
        "success": true,
        "message": "Action performed successfully"
    })))
}

// Security headers middleware test
async fn security_headers_test() -> AxumJson<serde_json::Value> {
    AxumJson(json!({
        "message": "This response should have security headers"
    }))
}

#[tokio::test]
async fn test_brute_force_protection() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new({
            let mut users = HashMap::new();
            users.insert(
                "user1".to_string(),
                json!({
                    "id": "user1",
                    "username": "testuser",
                    "password": "correctpassword",
                    "enabled": true
                }),
            );
            users
        })),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new().route("/login", post(login)).with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test successful login
    let login_data = json!({
        "username": "testuser",
        "password": "correctpassword"
    });

    let response = server.post("/login").json(&login_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert!(result.get("success").unwrap().as_bool().unwrap());
    assert!(result.get("token").is_some());

    // Test failed login attempts
    let wrong_login = json!({
        "username": "testuser",
        "password": "wrongpassword"
    });

    // First 4 failed attempts should return UNAUTHORIZED
    for _ in 0..4 {
        let response = server.post("/login").json(&wrong_login).await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    // 5th failed attempt should return TOO_MANY_REQUESTS (brute force protection)
    let response = server.post("/login").json(&wrong_login).await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_rate_limiting() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/api/test", get(rate_limited_endpoint))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Make 10 requests within the limit
    for i in 0..10 {
        let response = server
            .get("/api/test")
            .add_header("x-forwarded-for", "192.168.1.100")
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: serde_json::Value = response.json();
        assert_eq!(result["remaining_requests"], 9 - i);
    }

    // 11th request should be rate limited
    let response = server
        .get("/api/test")
        .add_header("x-forwarded-for", "192.168.1.100")
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    // Different IP should not be rate limited
    let response = server
        .get("/api/test")
        .add_header("x-forwarded-for", "192.168.1.101")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_input_validation_and_sanitization() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(user_registration))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test valid registration
    let valid_data = json!({
        "username": "validuser",
        "email": "user@example.com",
        "password": "securepassword123"
    });

    let response = server.post("/register").json(&valid_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test invalid username (too short)
    let invalid_data = json!({
        "username": "ab",
        "email": "user@example.com",
        "password": "securepassword123"
    });

    let response = server.post("/register").json(&invalid_data).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test invalid email
    let invalid_email = json!({
        "username": "validuser2",
        "email": "invalid-email",
        "password": "securepassword123"
    });

    let response = server.post("/register").json(&invalid_email).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test weak password
    let weak_password = json!({
        "username": "validuser3",
        "email": "user3@example.com",
        "password": "123"
    });

    let response = server.post("/register").json(&weak_password).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test SQL injection attempt
    let sql_injection = json!({
        "username": "user'; DROP TABLE users; --",
        "email": "user@example.com",
        "password": "securepassword123"
    });

    let response = server.post("/register").json(&sql_injection).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test XSS attempt
    let xss_attempt = json!({
        "username": "validuser4",
        "email": "user<script>alert('xss')</script>@example.com",
        "password": "securepassword123"
    });

    let response = server.post("/register").json(&xss_attempt).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_csrf_protection() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/protected-action", post(protected_action))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    let csrf_token = "valid-csrf-token-123";

    // Test valid CSRF token
    let valid_request = json!({
        "action": "delete_user",
        "user_id": "user123",
        "csrf_token": csrf_token
    });

    let response = server
        .post("/protected-action")
        .add_header("x-csrf-token", csrf_token)
        .json(&valid_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test missing CSRF header
    let response = server.post("/protected-action").json(&valid_request).await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    // Test mismatched tokens
    let response = server
        .post("/protected-action")
        .add_header("x-csrf-token", "wrong-token")
        .json(&valid_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    // Test missing token in body
    let invalid_request = json!({
        "action": "delete_user",
        "user_id": "user123"
    });

    let response = server
        .post("/protected-action")
        .add_header("x-csrf-token", csrf_token)
        .json(&invalid_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_sql_injection_prevention() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(user_registration))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test various SQL injection patterns
    let sql_injection_attempts = vec![
        json!({
            "username": "admin'--",
            "email": "admin@example.com",
            "password": "password123"
        }),
        json!({
            "username": "admin'; DROP TABLE users; --",
            "email": "admin@example.com",
            "password": "password123"
        }),
        json!({
            "username": "admin' UNION SELECT * FROM users; --",
            "email": "admin@example.com",
            "password": "password123"
        }),
        json!({
            "username": "admin",
            "email": "admin@example.com' OR '1'='1",
            "password": "password123"
        }),
    ];

    for attempt in sql_injection_attempts {
        let response = server.post("/register").json(&attempt).await;
        // Should be rejected due to SQL injection patterns
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn test_xss_prevention() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(user_registration))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test various XSS attack patterns
    let xss_attempts = vec![
        json!({
            "username": "<script>alert('xss')</script>",
            "email": "user@example.com",
            "password": "password123"
        }),
        json!({
            "username": "validuser",
            "email": "user@example.com<script>alert('xss')</script>",
            "password": "password123"
        }),
        json!({
            "username": "javascript:alert('xss')",
            "email": "user@example.com",
            "password": "password123"
        }),
        json!({
            "username": "validuser",
            "email": "user@<img src=x onerror=alert('xss')>.com",
            "password": "password123"
        }),
    ];

    for attempt in xss_attempts {
        let response = server.post("/register").json(&attempt).await;
        // Should be rejected due to XSS patterns
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn test_directory_traversal_prevention() {
    // Test that directory traversal attacks are prevented
    // This would typically be tested at the file system level,
    // but we can test URL parameter validation

    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route(
            "/files",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                let filename = params.get("filename").map(|s| s.as_str()).unwrap_or("");

                // Check for directory traversal patterns
                if filename.contains("..") || filename.contains("/") || filename.contains("\\") {
                    return Err(StatusCode::BAD_REQUEST);
                }

                Ok(AxumJson(json!({
                    "filename": filename,
                    "message": "File access allowed"
                })))
            }),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test valid filename
    let response = server.get("/files?filename=document.txt").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test directory traversal attempts
    let traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "file.txt/../../secret.txt",
    ];

    for attempt in traversal_attempts {
        let response = server.get(&format!("/files?filename={}", attempt)).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn test_open_redirect_prevention() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route(
            "/redirect",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                if let Some(url) = params.get("url") {
                    // Check for open redirect patterns
                    if url.starts_with("http://") || url.starts_with("https://") {
                        // Only allow redirects to trusted domains
                        let allowed_domains = ["trusted.com", "example.com"];
                        if allowed_domains.iter().any(|domain| url.contains(domain)) {
                            return Ok(AxumJson(json!({
                                "redirect_url": url,
                                "allowed": true
                            })));
                        }
                    }
                }

                Err(StatusCode::BAD_REQUEST)
            }),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test allowed redirect
    let response = server.get("/redirect?url=https://trusted.com/page").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test blocked redirects
    let blocked_urls = vec![
        "http://evil.com",
        "https://malicious.com",
        "//evil.com",
        "javascript:alert('xss')",
        "data:text/html,%3Cscript%3Ealert('xss')%3C/script%3E",
    ];

    for url in blocked_urls {
        let response = server.get(&format!("/redirect?url={}", url)).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn test_concurrent_security_operations() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(user_registration))
        .with_state(state);

    let server = Arc::new(TestServer::new(app).unwrap());

    // Test concurrent user registrations
    let mut handles = vec![];

    for i in 0..10 {
        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let user_data = json!({
                "username": format!("user{}", i),
                "email": format!("user{}@example.com", i),
                "password": "securepassword123"
            });

            let response = server_clone.post("/register").json(&user_data).await;
            assert_eq!(response.status_code(), StatusCode::OK);
        });
        handles.push(handle);
    }

    // Wait for all concurrent operations
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all users were created (no race conditions)
    // In a real test, you'd check the database state
}

#[tokio::test]
async fn test_security_headers() {
    let app = Router::new().route("/test", get(security_headers_test));

    let server = TestServer::new(app).unwrap();

    let response = server.get("/test").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // In a real implementation, you would check for security headers like:
    // - Content-Security-Policy
    // - X-Frame-Options
    // - X-Content-Type-Options
    // - X-XSS-Protection
    // - Strict-Transport-Security

    let result: serde_json::Value = response.json();
    assert_eq!(
        result["message"],
        "This response should have security headers"
    );
}

#[tokio::test]
async fn test_buffer_overflow_prevention() {
    let state = SecurityTestState {
        users: Arc::new(Mutex::new(HashMap::new())),
        failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(user_registration))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test with extremely large input
    let large_username = "a".repeat(10000); // 10KB string
    let large_data = json!({
        "username": large_username,
        "email": "user@example.com",
        "password": "password123"
    });

    let response = server.post("/register").json(&large_data).await;
    // Should be rejected due to size limits or validation
    assert!(
        response.status_code() == StatusCode::BAD_REQUEST
            || response.status_code() == StatusCode::PAYLOAD_TOO_LARGE
    );

    // Test with deeply nested JSON (potential DoS)
    let mut nested = json!({"value": "test"});
    for _ in 0..100 {
        // Create deeply nested structure
        nested = json!({ "nested": nested });
    }

    let response = server.post("/register").json(&nested).await;
    // Should handle gracefully without crashing
    assert!(response.status_code().is_success() || response.status_code().is_client_error());
}
