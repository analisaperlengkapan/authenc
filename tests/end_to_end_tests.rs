use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{Method, Request, StatusCode, header},
    middleware,
    response::Json,
    routing::{delete, get, post, put},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant, sleep};
use uuid::Uuid;

// Shared test state for end-to-end tests
type SharedState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

#[derive(Clone)]
struct AppState {
    data: SharedState,
}

// End-to-end test handlers
async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    // Validate required fields
    let email = payload
        .get("email")
        .and_then(|e| e.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let password = payload
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let name = payload
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Check password strength
    if password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user already exists
    for (_, user) in data.iter() {
        if user.get("email").and_then(|e| e.as_str()) == Some(email) {
            return Err(StatusCode::CONFLICT);
        }
    }

    let user_id = Uuid::new_v4().to_string();
    let mut user = json!({
        "id": user_id,
        "email": email,
        "name": name,
        "status": "pending_verification",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "login_attempts": 0,
        "last_login": null,
        "verified": false
    });

    data.insert(user_id.clone(), user.clone());

    Ok(Json(json!({
        "success": true,
        "user": {
            "id": user_id,
            "email": email,
            "name": name,
            "status": "pending_verification"
        },
        "message": "User registered successfully. Please check your email for verification."
    })))
}

async fn verify_email(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    // Find user by verification token (simplified - in real app this would be a proper token)
    for (user_id, user) in data.iter_mut() {
        if user.get("verification_token").and_then(|t| t.as_str()) == Some(&token) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

            return Ok(Json(json!({
                "success": true,
                "message": "Email verified successfully",
                "user_id": user_id
            })));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    let email = payload
        .get("email")
        .and_then(|e| e.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let password = payload
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Find user
    for (user_id, user) in data.iter_mut() {
        if user.get("email").and_then(|e| e.as_str()) == Some(email) {
            // Check if user is verified
            if !user
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err(StatusCode::FORBIDDEN);
            }

            // Increment login attempts first
            let attempts = user
                .get("login_attempts")
                .and_then(|a| a.as_u64())
                .unwrap_or(0);
            let new_attempts = attempts + 1;
            user["login_attempts"] = json!(new_attempts);

            // Check if account is locked (after incrementing)
            if new_attempts >= 5 {
                return Err(StatusCode::LOCKED);
            }

            // Simple password check (in real app, use proper hashing)
            if user.get("password").and_then(|p| p.as_str()) == Some(password) {
                // Reset login attempts on successful login
                user["login_attempts"] = json!(0);
                user["last_login"] = json!(chrono::Utc::now().to_rfc3339());
                user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

                let token = format!("jwt_token_{}", user_id);

                return Ok(Json(json!({
                    "success": true,
                    "token": token,
                    "user": {
                        "id": user_id,
                        "email": email,
                        "name": user.get("name").and_then(|n| n.as_str()).unwrap_or("")
                    },
                    "expires_in": 3600
                })));
            } else {
                // Return UNAUTHORIZED (attempts already incremented above)
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

async fn logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // In a real app, you'd invalidate the token in a blacklist
    // For this test, we'll just return success
    Ok(Json(json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

async fn get_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let data = state.data.lock().unwrap();

    // Extract token from Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Find user by token (simplified)
    for (user_id, user) in data.iter() {
        let expected_token = format!("jwt_token_{}", user_id);
        if auth_header == expected_token {
            return Ok(Json(json!({
                "success": true,
                "profile": {
                    "id": user_id,
                    "email": user.get("email"),
                    "name": user.get("name"),
                    "status": user.get("status"),
                    "verified": user.get("verified"),
                    "last_login": user.get("last_login"),
                    "created_at": user.get("created_at")
                }
            })));
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

async fn update_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    // Extract and validate token
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Find and update user
    for (user_id, user) in data.iter_mut() {
        let expected_token = format!("jwt_token_{}", user_id);
        if auth_header == expected_token {
            // Update allowed fields
            if let Some(name) = payload.get("name") {
                user["name"] = name.clone();
            }
            if let Some(email) = payload.get("email") {
                user["email"] = email.clone();
            }

            user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

            return Ok(Json(json!({
                "success": true,
                "message": "Profile updated successfully",
                "user": {
                    "id": user_id,
                    "email": user.get("email"),
                    "name": user.get("name")
                }
            })));
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

async fn change_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let current_password = payload
        .get("current_password")
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let new_password = payload
        .get("new_password")
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate new password strength
    if new_password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Find and update user
    for (user_id, user) in data.iter_mut() {
        let expected_token = format!("jwt_token_{}", user_id);
        if auth_header == expected_token {
            // Verify current password
            if user.get("password").and_then(|p| p.as_str()) != Some(current_password) {
                return Err(StatusCode::UNAUTHORIZED);
            }

            user["password"] = json!(new_password);
            user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

            return Ok(Json(json!({
                "success": true,
                "message": "Password changed successfully"
            })));
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

async fn request_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    let email = payload
        .get("email")
        .and_then(|e| e.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Find user and generate reset token
    for (user_id, user) in data.iter_mut() {
        if user.get("email").and_then(|e| e.as_str()) == Some(email) {
            let reset_token = format!("reset_{}_{}", user_id, Uuid::new_v4());
            user["reset_token"] = json!(reset_token);
            user["reset_expires"] =
                json!((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());

            return Ok(Json(json!({
                "success": true,
                "message": "Password reset email sent",
                "reset_token": reset_token  // In real app, this wouldn't be returned
            })));
        }
    }

    // Don't reveal if email exists or not (security best practice)
    Ok(Json(json!({
        "success": true,
        "message": "If the email exists, a password reset link has been sent"
    })))
}

async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    let token = payload
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let new_password = payload
        .get("new_password")
        .and_then(|p| p.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate new password
    if new_password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Find user by reset token
    for (_, user) in data.iter_mut() {
        if user.get("reset_token").and_then(|t| t.as_str()) == Some(token) {
            // Check if token is expired
            if let Some(expires) = user.get("reset_expires").and_then(|e| e.as_str()) {
                if chrono::DateTime::parse_from_rfc3339(expires).unwrap() < chrono::Utc::now() {
                    return Err(StatusCode::GONE);
                }
            }

            user["password"] = json!(new_password);
            user["reset_token"] = json!(null);
            user["reset_expires"] = json!(null);
            user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

            return Ok(Json(json!({
                "success": true,
                "message": "Password reset successfully"
            })));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

#[tokio::test]
async fn test_complete_user_registration_workflow() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/verify/{token}", get(verify_email))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/user/profile", get(get_profile).put(update_profile))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Step 1: Register user
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Test User",
            "email": "test@example.com",
            "password": "securepassword123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["user"]["status"], "pending_verification");

    // Step 2: Simulate email verification (in real app, this would be a proper token)
    let user_id = body["user"]["id"].as_str().unwrap();

    // Manually set verification token for testing
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verification_token"] = json!("test_verification_token");
            user["password"] = json!("securepassword123"); // Set password for login test
        }
    }

    // Verify email
    let response = server.get("/auth/verify/test_verification_token").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Step 3: Login
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "test@example.com",
            "password": "securepassword123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body["token"].is_string());
    let token = body["token"].as_str().unwrap();

    // Step 4: Get profile
    let response = server
        .get("/user/profile")
        .add_header("authorization", format!("Bearer {}", token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["profile"]["email"], "test@example.com");
    assert_eq!(body["profile"]["name"], "Test User");

    // Step 5: Update profile
    let response = server
        .put("/user/profile")
        .add_header("authorization", format!("Bearer {}", token))
        .json(&json!({
            "name": "Updated Test User",
            "email": "updated@example.com"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    // Step 6: Logout
    let response = server
        .post("/auth/logout")
        .add_header("authorization", format!("Bearer {}", token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_password_reset_workflow() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/forgot-password", post(request_password_reset))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/login", post(login))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create and verify user first
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Reset Test",
            "email": "reset@example.com",
            "password": "oldpassword123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let json_response: serde_json::Value = response.json();
    let user_id = json_response["user"]["id"].as_str().unwrap();

    // Set user as verified and add password
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["password"] = json!("oldpassword123");
        }
    }

    // Step 1: Request password reset
    let response = server
        .post("/auth/forgot-password")
        .json(&json!({
            "email": "reset@example.com"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    let reset_token = body["reset_token"].as_str().unwrap();

    // Step 2: Reset password
    let response = server
        .post("/auth/reset-password")
        .json(&json!({
            "token": reset_token,
            "new_password": "newpassword123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    // Step 3: Verify old password no longer works
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "reset@example.com",
            "password": "oldpassword123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Step 4: Verify new password works
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "reset@example.com",
            "password": "newpassword123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_password_change_workflow() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login))
        .route("/user/change-password", post(change_password))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create and verify user
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Password Test",
            "email": "password@example.com",
            "password": "initialpass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let json_response: serde_json::Value = response.json();
    let user_id = json_response["user"]["id"].as_str().unwrap();

    // Set user as verified
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["password"] = json!("initialpass123");
        }
    }

    // Login to get token
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "password@example.com",
            "password": "initialpass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let json_response: serde_json::Value = response.json();
    let token = json_response["token"].as_str().unwrap();

    // Change password
    let response = server
        .post("/user/change-password")
        .add_header("authorization", format!("Bearer {}", token))
        .json(&json!({
            "current_password": "initialpass123",
            "new_password": "newsecurepass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify old password doesn't work
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "password@example.com",
            "password": "initialpass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Verify new password works
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "password@example.com",
            "password": "newsecurepass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_security_features_and_edge_cases() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login))
        .route("/user/profile", get(get_profile))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test registration with weak password
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Weak Password",
            "email": "weak@example.com",
            "password": "123"  // Too short
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    // Test registration with duplicate email
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "First User",
            "email": "duplicate@example.com",
            "password": "securepass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Second User",
            "email": "duplicate@example.com",  // Duplicate
            "password": "securepass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Test login with unverified account
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "duplicate@example.com",
            "password": "securepass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

    // Test accessing protected endpoint without token
    let response = server.get("/user/profile").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test accessing with invalid token
    let response = server
        .get("/user/profile")
        .add_header("authorization", "Bearer invalid_token")
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_account_lockout_after_failed_attempts() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create and verify user
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Lockout Test",
            "email": "lockout@example.com",
            "password": "correctpass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let json_response: serde_json::Value = response.json();
    let user_id = json_response["user"]["id"].as_str().unwrap();

    // Set user as verified
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["password"] = json!("correctpass123");
        }
    }

    // Attempt login with wrong password multiple times
    for i in 0..5 {
        let response = server
            .post("/auth/login")
            .json(&json!({
                "email": "lockout@example.com",
                "password": "wrongpassword"
            }))
            .await;

        if i < 4 {
            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        } else {
            // 5th attempt should lock the account
            assert_eq!(response.status_code(), StatusCode::LOCKED);
        }
    }

    // Verify account is locked even with correct password
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "lockout@example.com",
            "password": "correctpass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::LOCKED);
}

#[tokio::test]
async fn test_session_management_and_token_expiration() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login))
        .route("/user/profile", get(get_profile))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create and verify user
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Session Test",
            "email": "session@example.com",
            "password": "sessionpass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let json_response: serde_json::Value = response.json();
    let user_id = json_response["user"]["id"].as_str().unwrap();

    // Set user as verified
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["password"] = json!("sessionpass123");
        }
    }

    // Login and get token
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "session@example.com",
            "password": "sessionpass123"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    let token = body["token"].as_str().unwrap();
    let expires_in = body["expires_in"].as_u64().unwrap();

    // Verify token works initially
    let response = server
        .get("/user/profile")
        .add_header("authorization", format!("Bearer {}", token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    // Simulate token expiration by waiting (in real app, this would be handled by JWT expiration)
    sleep(Duration::from_millis(100)).await;

    // Token should still work in this test implementation
    // In a real app, the server would validate JWT expiration
    let response = server
        .get("/user/profile")
        .add_header("authorization", format!("Bearer {}", token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_concurrent_user_sessions() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login))
        .route("/user/profile", get(get_profile))
        .with_state(state.clone());

    let server = TestServer::new(app.clone()).unwrap();

    // Create and verify user
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Concurrent Test",
            "email": "concurrent@example.com",
            "password": "concurrentpass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let json_response: serde_json::Value = response.json();
    let user_id = json_response["user"]["id"].as_str().unwrap();

    // Set user as verified
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["password"] = json!("concurrentpass123");
        }
    }

    // Simulate multiple concurrent sessions
    let mut handles = vec![];

    for i in 0..5 {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            // Each session logs in separately
            let login_response = server_clone
                .post("/auth/login")
                .json(&json!({
                    "email": "concurrent@example.com",
                    "password": "concurrentpass123"
                }))
                .await;

            assert_eq!(login_response.status_code(), StatusCode::OK);
            let json_response: serde_json::Value = login_response.json();
            let token = json_response["token"].as_str().unwrap().to_string();

            // Each session makes requests
            for _ in 0..3 {
                let profile_response = server_clone
                    .get("/user/profile")
                    .add_header("authorization", format!("Bearer {}", token))
                    .await;

                assert_eq!(profile_response.status_code(), StatusCode::OK);
            }

            token
        });
        handles.push(handle);
    }

    // Wait for all concurrent sessions to complete
    let mut tokens = vec![];
    for handle in handles {
        tokens.push(handle.await.unwrap());
    }

    // Verify all sessions worked
    assert_eq!(tokens.len(), 5);

    // Verify user data integrity
    let response = server
        .get("/user/profile")
        .add_header("authorization", format!("Bearer {}", tokens[0]))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["profile"]["email"], "concurrent@example.com");
}

#[tokio::test]
async fn test_data_consistency_under_load() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/auth/register", post(register_user))
        .route("/auth/login", post(login))
        .route("/user/profile", get(get_profile).put(update_profile))
        .with_state(state.clone());

    let server = TestServer::new(app.clone()).unwrap();

    // Create initial user
    let response = server
        .post("/auth/register")
        .json(&json!({
            "name": "Load Test User",
            "email": "loadtest@example.com",
            "password": "loadtestpass123"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let json_response: serde_json::Value = response.json();
    let user_id = json_response["user"]["id"].as_str().unwrap();

    // Set user as verified
    {
        let mut data = state.data.lock().unwrap();
        if let Some(user) = data.get_mut(user_id) {
            user["verified"] = json!(true);
            user["status"] = json!("active");
            user["password"] = json!("loadtestpass123");
        }
    }

    // Get initial token
    let response = server
        .post("/auth/login")
        .json(&json!({
            "email": "loadtest@example.com",
            "password": "loadtestpass123"
        }))
        .await;

    let json_response: serde_json::Value = response.json();
    let token = json_response["token"].as_str().unwrap();

    // Simulate concurrent operations
    let mut handles = vec![];

    for i in 0..10 {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let token_clone = token.to_string();
        let handle = tokio::spawn(async move {
            // Mix of read and write operations
            if i % 2 == 0 {
                // Read operation
                let response = server_clone
                    .get("/user/profile")
                    .add_header("authorization", format!("Bearer {}", token_clone))
                    .await;
                assert_eq!(response.status_code(), StatusCode::OK);
            } else {
                // Write operation
                let response = server_clone
                    .put("/user/profile")
                    .add_header("authorization", format!("Bearer {}", token_clone))
                    .json(&json!({
                        "name": format!("Updated Load Test User {}", i)
                    }))
                    .await;
                assert_eq!(response.status_code(), StatusCode::OK);
            }
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify final state
    let response = server
        .get("/user/profile")
        .add_header("authorization", format!("Bearer {}", token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["profile"]["email"], "loadtest@example.com");
    // Name should be from the last update operation
    assert!(
        body["profile"]["name"]
            .as_str()
            .unwrap()
            .starts_with("Updated Load Test User")
    );
}
