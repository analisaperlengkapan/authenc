// Advanced Authentication Flow Tests
// Testing comprehensive authentication workflows, MFA, token management, and security flows

use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AuthState {
    users: Arc<Mutex<HashMap<String, User>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    tokens: Arc<Mutex<HashMap<String, TokenInfo>>>,
    mfa_codes: Arc<Mutex<HashMap<String, MfaCode>>>,
}

#[derive(Clone)]
struct User {
    id: String,
    email: String,
    password_hash: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    account_locked: bool,
    login_attempts: u32,
    last_login: Option<String>,
}

#[derive(Clone)]
struct Session {
    id: String,
    user_id: String,
    created_at: String,
    expires_at: String,
    ip_address: String,
    user_agent: String,
    is_active: bool,
}

#[derive(Clone)]
struct TokenInfo {
    token: String,
    user_id: String,
    token_type: String, // access, refresh, api_key
    issued_at: String,
    expires_at: String,
    is_revoked: bool,
    scopes: Vec<String>,
}

#[derive(Clone)]
struct MfaCode {
    user_id: String,
    code: String,
    created_at: String,
    expires_at: String,
    used: bool,
}

impl AuthState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            mfa_codes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_user_registration_flow() {
    let auth_state = AuthState::new();

    let app = Router::new()
        .route("/auth/register", post(move |State(state): State<AuthState>, Json(registration): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;

            let email = registration.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let password = registration.get("password").and_then(|p| p.as_str()).unwrap_or("");

            // Basic validation
            if email.is_empty() || password.len() < 8 {
                return Err(StatusCode::BAD_REQUEST);
            }

            // Check if user already exists
            if users.contains_key(email) {
                return Err(StatusCode::CONFLICT);
            }

            let user_id = format!("user_{}", users.len() + 1);
            users.insert(email.to_string(), User {
                id: user_id.clone(),
                email: email.to_string(),
                password_hash: format!("hash_{}", password), // In real app, this would be properly hashed
                mfa_enabled: false,
                mfa_secret: None,
                account_locked: false,
                login_attempts: 0,
                last_login: None,
            });

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "email": email,
                "status": "registered",
                "message": "User registered successfully. Please check your email for verification."
            })))
        }))
        .route("/auth/verify-email", post(move |State(state): State<AuthState>, Json(verification): Json<serde_json::Value>| async move {
            let users = state.users.lock().await;

            let email = verification.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let token = verification.get("verification_token").and_then(|t| t.as_str()).unwrap_or("");

            if let Some(user) = users.get(email) {
                // In real app, verify token against stored verification token
                if token == "valid_token_123" {
                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "email": email,
                        "status": "verified",
                        "message": "Email verified successfully"
                    })))
                } else {
                    Err(StatusCode::BAD_REQUEST)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(auth_state);

    let server = TestServer::new(app).unwrap();

    // Test successful registration
    let registration_data = json!({"email": "test@example.com", "password": "securepassword123"});
    let response = server.post("/auth/register").json(&registration_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "registered");
    assert!(body["user_id"].as_str().is_some());

    // Test email verification
    let verification_data =
        json!({"email": "test@example.com", "verification_token": "valid_token_123"});
    let response = server
        .post("/auth/verify-email")
        .json(&verification_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "verified");

    // Test duplicate registration
    let response = server.post("/auth/register").json(&registration_data).await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Test invalid registration data
    let invalid_data = json!({"email": "", "password": "123"});
    let response = server.post("/auth/register").json(&invalid_data).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_and_session_management() {
    let auth_state = AuthState::new();

    // Pre-populate with a test user
    {
        let mut users = auth_state.users.lock().await;
        users.insert(
            "test@example.com".to_string(),
            User {
                id: "user_123".to_string(),
                email: "test@example.com".to_string(),
                password_hash: "hash_securepassword123".to_string(),
                mfa_enabled: false,
                mfa_secret: None,
                account_locked: false,
                login_attempts: 0,
                last_login: None,
            },
        );
    }

    let app = Router::new()
        .route("/auth/login", post(move |State(state): State<AuthState>, Json(login): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;
            let mut sessions = state.sessions.lock().await;

            let email = login.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let password = login.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let ip_address = login.get("ip_address").and_then(|i| i.as_str()).unwrap_or("127.0.0.1");
            let user_agent = login.get("user_agent").and_then(|u| u.as_str()).unwrap_or("TestAgent/1.0");

            if let Some(user) = users.get_mut(email) {
                if user.account_locked {
                    return Err(StatusCode::LOCKED);
                }

                // Check password (simplified)
                if format!("hash_{}", password) != user.password_hash {
                    user.login_attempts += 1;
                    if user.login_attempts >= 5 {
                        user.account_locked = true;
                    }
                    return Err(StatusCode::UNAUTHORIZED);
                }

                // Reset login attempts on successful login
                user.login_attempts = 0;
                user.last_login = Some("2024-12-01T12:00:00Z".to_string());

                // Create session
                let session_id = format!("session_{}", sessions.len() + 1);
                sessions.insert(session_id.clone(), Session {
                    id: session_id.clone(),
                    user_id: user.id.clone(),
                    created_at: "2024-12-01T12:00:00Z".to_string(),
                    expires_at: "2024-12-01T13:00:00Z".to_string(),
                    ip_address: ip_address.to_string(),
                    user_agent: user_agent.to_string(),
                    is_active: true,
                });

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "session_id": session_id,
                    "user_id": user.id,
                    "access_token": "access_token_123",
                    "refresh_token": "refresh_token_456",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                })))
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }))
        .route("/auth/logout", post(move |State(state): State<AuthState>, Json(logout): Json<serde_json::Value>| async move {
            let mut sessions = state.sessions.lock().await;

            let session_id = logout.get("session_id").and_then(|s| s.as_str()).unwrap_or("");

            if let Some(session) = sessions.get_mut(session_id) {
                session.is_active = false;
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({"status": "logged_out", "message": "Successfully logged out"})))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/auth/session/validate", get(move |State(state): State<AuthState>, Json(validation): Json<serde_json::Value>| async move {
            let sessions = state.sessions.lock().await;

            let session_id = validation.get("session_id").and_then(|s| s.as_str()).unwrap_or("");

            if let Some(session) = sessions.get(session_id) {
                if session.is_active {
                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "session_id": session_id,
                        "user_id": session.user_id,
                        "is_valid": true,
                        "expires_at": session.expires_at
                    })))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(auth_state);

    let server = TestServer::new(app).unwrap();

    // Test successful login
    let login_data = json!({
        "email": "test@example.com",
        "password": "securepassword123",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    });
    let response = server.post("/auth/login").json(&login_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["session_id"].as_str().is_some());
    assert!(body["access_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");

    let session_id = body["session_id"].as_str().unwrap();

    // Test session validation
    let validation_data = json!({"session_id": session_id});
    let response = server
        .get("/auth/session/validate")
        .json(&validation_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["is_valid"], true);

    // Test logout
    let logout_data = json!({"session_id": session_id});
    let response = server.post("/auth/logout").json(&logout_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test session validation after logout
    let response = server
        .get("/auth/session/validate")
        .json(&validation_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test failed login attempts
    let wrong_password_data = json!({"email": "test@example.com", "password": "wrongpassword"});
    for _ in 0..5 {
        let response = server.post("/auth/login").json(&wrong_password_data).await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    // Test account lockout
    let response = server.post("/auth/login").json(&wrong_password_data).await;
    assert_eq!(response.status_code(), StatusCode::LOCKED);
}

#[tokio::test]
async fn test_multi_factor_authentication() {
    let auth_state = AuthState::new();

    // Pre-populate with MFA-enabled user
    {
        let mut users = auth_state.users.lock().await;
        users.insert(
            "mfa@example.com".to_string(),
            User {
                id: "user_mfa_123".to_string(),
                email: "mfa@example.com".to_string(),
                password_hash: "hash_securepassword123".to_string(),
                mfa_enabled: true,
                mfa_secret: Some("JBSWY3DPEHPK3PXP".to_string()), // Test TOTP secret
                account_locked: false,
                login_attempts: 0,
                last_login: None,
            },
        );
    }

    let app = Router::new()
        .route("/auth/mfa/setup", post(move |State(state): State<AuthState>, Json(setup): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;

            let email = setup.get("email").and_then(|e| e.as_str()).unwrap_or("");

            if let Some(user) = users.get_mut(email) {
                user.mfa_enabled = true;
                user.mfa_secret = Some("JBSWY3DPEHPK3PXP".to_string());

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "email": email,
                    "mfa_enabled": true,
                    "secret": user.mfa_secret,
                    "qr_code_url": "otpauth://totp/Authence:mfa@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Authence",
                    "message": "MFA setup completed. Use the QR code to configure your authenticator app."
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/auth/mfa/verify", post(move |State(state): State<AuthState>, Json(verification): Json<serde_json::Value>| async move {
            let users = state.users.lock().await;
            let mut mfa_codes = state.mfa_codes.lock().await;

            let email = verification.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let code = verification.get("code").and_then(|c| c.as_str()).unwrap_or("");

            if let Some(user) = users.get(email) {
                if !user.mfa_enabled {
                    return Err(StatusCode::BAD_REQUEST);
                }

                // Generate expected TOTP code (simplified - in real app use proper TOTP library)
                let expected_code = "123456"; // This would be calculated based on secret and time

                if code == expected_code {
                    // Mark code as used
                    mfa_codes.insert(format!("{}_{}", email, code), MfaCode {
                        user_id: user.id.clone(),
                        code: code.to_string(),
                        created_at: "2024-12-01T12:00:00Z".to_string(),
                        expires_at: "2024-12-01T12:01:00Z".to_string(),
                        used: true,
                    });

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "email": email,
                        "mfa_verified": true,
                        "message": "MFA verification successful"
                    })))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/auth/mfa/disable", post(move |State(state): State<AuthState>, Json(disable): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;

            let email = disable.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let code = disable.get("verification_code").and_then(|c| c.as_str()).unwrap_or("");

            if let Some(user) = users.get_mut(email) {
                if !user.mfa_enabled {
                    return Err(StatusCode::BAD_REQUEST);
                }

                // Verify code before disabling
                let expected_code = "123456";
                if code == expected_code {
                    user.mfa_enabled = false;
                    user.mfa_secret = None;

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "email": email,
                        "mfa_disabled": true,
                        "message": "MFA has been disabled for your account"
                    })))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(auth_state);

    let server = TestServer::new(app).unwrap();

    // Test MFA setup
    let setup_data = json!({"email": "mfa@example.com"});
    let response = server.post("/auth/mfa/setup").json(&setup_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["mfa_enabled"], true);
    assert!(body["secret"].as_str().is_some());
    assert!(body["qr_code_url"].as_str().is_some());

    // Test MFA verification with correct code
    let verify_data = json!({"email": "mfa@example.com", "code": "123456"});
    let response = server.post("/auth/mfa/verify").json(&verify_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["mfa_verified"], true);

    // Test MFA verification with wrong code
    let wrong_verify_data = json!({"email": "mfa@example.com", "code": "000000"});
    let response = server
        .post("/auth/mfa/verify")
        .json(&wrong_verify_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test MFA disable
    let disable_data = json!({"email": "mfa@example.com", "verification_code": "123456"});
    let response = server.post("/auth/mfa/disable").json(&disable_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["mfa_disabled"], true);
}

#[tokio::test]
async fn test_token_management_and_refresh() {
    let auth_state = AuthState::new();

    // Pre-populate with tokens
    {
        let mut tokens = auth_state.tokens.lock().await;
        tokens.insert(
            "access_token_123".to_string(),
            TokenInfo {
                token: "access_token_123".to_string(),
                user_id: "user_123".to_string(),
                token_type: "access".to_string(),
                issued_at: "2024-12-01T12:00:00Z".to_string(),
                expires_at: "2024-12-01T13:00:00Z".to_string(),
                is_revoked: false,
                scopes: vec!["read".to_string(), "write".to_string()],
            },
        );
        tokens.insert(
            "refresh_token_456".to_string(),
            TokenInfo {
                token: "refresh_token_456".to_string(),
                user_id: "user_123".to_string(),
                token_type: "refresh".to_string(),
                issued_at: "2024-12-01T12:00:00Z".to_string(),
                expires_at: "2024-12-07T12:00:00Z".to_string(),
                is_revoked: false,
                scopes: vec!["refresh".to_string()],
            },
        );
    }

    let app = Router::new()
        .route("/auth/token/refresh", post(move |State(state): State<AuthState>, Json(refresh): Json<serde_json::Value>| async move {
            let tokens = state.tokens.lock().await;

            let refresh_token = refresh.get("refresh_token").and_then(|t| t.as_str()).unwrap_or("");

            if let Some(token_info) = tokens.get(refresh_token) {
                if token_info.token_type != "refresh" || token_info.is_revoked {
                    return Err(StatusCode::UNAUTHORIZED);
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "access_token": "new_access_token_789",
                    "refresh_token": "new_refresh_token_101",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scopes": token_info.scopes
                })))
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }))
        .route("/auth/token/revoke", post(move |State(state): State<AuthState>, Json(revoke): Json<serde_json::Value>| async move {
            let mut tokens = state.tokens.lock().await;

            let token = revoke.get("token").and_then(|t| t.as_str()).unwrap_or("");

            if let Some(token_info) = tokens.get_mut(token) {
                token_info.is_revoked = true;
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({"status": "revoked", "message": "Token has been revoked"})))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/auth/token/introspect", post(move |State(state): State<AuthState>, Json(introspect): Json<serde_json::Value>| async move {
            let tokens = state.tokens.lock().await;

            let token = introspect.get("token").and_then(|t| t.as_str()).unwrap_or("");

            if let Some(token_info) = tokens.get(token) {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "active": !token_info.is_revoked,
                    "client_id": token_info.user_id,
                    "token_type": token_info.token_type,
                    "exp": token_info.expires_at,
                    "iat": token_info.issued_at,
                    "scope": token_info.scopes.join(" ")
                })))
            } else {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({"active": false})))
            }
        }))
        .with_state(auth_state);

    let server = TestServer::new(app).unwrap();

    // Test token refresh
    let refresh_data = json!({"refresh_token": "refresh_token_456"});
    let response = server.post("/auth/token/refresh").json(&refresh_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");

    // Test token introspection
    let introspect_data = json!({"token": "access_token_123"});
    let response = server
        .post("/auth/token/introspect")
        .json(&introspect_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true);
    assert_eq!(body["token_type"], "access");

    // Test token revocation
    let revoke_data = json!({"token": "access_token_123"});
    let response = server.post("/auth/token/revoke").json(&revoke_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test introspection after revocation
    let response = server
        .post("/auth/token/introspect")
        .json(&introspect_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], false);

    // Test invalid refresh token
    let invalid_refresh_data = json!({"refresh_token": "invalid_token"});
    let response = server
        .post("/auth/token/refresh")
        .json(&invalid_refresh_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_password_reset_flow() {
    let auth_state = AuthState::new();

    // Pre-populate with a test user
    {
        let mut users = auth_state.users.lock().await;
        users.insert(
            "reset@example.com".to_string(),
            User {
                id: "user_reset_123".to_string(),
                email: "reset@example.com".to_string(),
                password_hash: "hash_oldpassword".to_string(),
                mfa_enabled: false,
                mfa_secret: None,
                account_locked: false,
                login_attempts: 0,
                last_login: None,
            },
        );
    }

    let app = Router::new()
        .route("/auth/password/reset-request", post(move |State(state): State<AuthState>, Json(request): Json<serde_json::Value>| async move {
            let users = state.users.lock().await;

            let email = request.get("email").and_then(|e| e.as_str()).unwrap_or("");

            if users.contains_key(email) {
                // In real app, send email with reset token
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "email": email,
                    "status": "reset_requested",
                    "message": "Password reset email sent. Please check your inbox.",
                    "reset_token": "reset_token_789" // In real app, this would be sent via email
                })))
            } else {
                // Don't reveal if email exists for security
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "status": "reset_requested",
                    "message": "If the email exists, a password reset link has been sent."
                })))
            }
        }))
        .route("/auth/password/reset", post(move |State(state): State<AuthState>, Json(reset): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;

            let email = reset.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let token = reset.get("reset_token").and_then(|t| t.as_str()).unwrap_or("");
            let new_password = reset.get("new_password").and_then(|p| p.as_str()).unwrap_or("");

            if new_password.len() < 8 {
                return Err(StatusCode::BAD_REQUEST);
            }

            if let Some(user) = users.get_mut(email) {
                // In real app, verify token against stored reset token
                if token == "reset_token_789" {
                    user.password_hash = format!("hash_{}", new_password);
                    user.login_attempts = 0; // Reset failed attempts
                    user.account_locked = false; // Unlock account

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "email": email,
                        "status": "password_reset",
                        "message": "Password has been successfully reset"
                    })))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/auth/password/change", post(move |State(state): State<AuthState>, Json(change): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;

            let email = change.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let current_password = change.get("current_password").and_then(|c| c.as_str()).unwrap_or("");
            let new_password = change.get("new_password").and_then(|n| n.as_str()).unwrap_or("");

            if new_password.len() < 8 {
                return Err(StatusCode::BAD_REQUEST);
            }

            if let Some(user) = users.get_mut(email) {
                // Verify current password
                if format!("hash_{}", current_password) != user.password_hash {
                    return Err(StatusCode::UNAUTHORIZED);
                }

                user.password_hash = format!("hash_{}", new_password);

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "email": email,
                    "status": "password_changed",
                    "message": "Password has been successfully changed"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(auth_state);

    let server = TestServer::new(app).unwrap();

    // Test password reset request
    let reset_request_data = json!({"email": "reset@example.com"});
    let response = server
        .post("/auth/password/reset-request")
        .json(&reset_request_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "reset_requested");

    // Test password reset with valid token
    let reset_data = json!({
        "email": "reset@example.com",
        "reset_token": "reset_token_789",
        "new_password": "newsecurepassword123"
    });
    let response = server.post("/auth/password/reset").json(&reset_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "password_reset");

    // Test password change
    let change_data = json!({
        "email": "reset@example.com",
        "current_password": "newsecurepassword123",
        "new_password": "evenmoressecurepassword456"
    });
    let response = server
        .post("/auth/password/change")
        .json(&change_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "password_changed");

    // Test password reset with invalid token
    let invalid_reset_data = json!({
        "email": "reset@example.com",
        "reset_token": "invalid_token",
        "new_password": "anotherpassword"
    });
    let response = server
        .post("/auth/password/reset")
        .json(&invalid_reset_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test password change with wrong current password
    let wrong_change_data = json!({
        "email": "reset@example.com",
        "current_password": "wrongpassword",
        "new_password": "newpassword123"
    });
    let response = server
        .post("/auth/password/change")
        .json(&wrong_change_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}
