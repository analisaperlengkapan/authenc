// Advanced Session Management Tests
// Testing session lifecycle, security, concurrent sessions, and session policies

use axum::{
    Router,
    extract::{Json, State},
    http::{StatusCode, header::HeaderMap},
    routing::{delete, get, post},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct SessionState {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    users: Arc<Mutex<HashMap<String, User>>>,
    session_policies: Arc<Mutex<HashMap<String, SessionPolicy>>>,
    refresh_tokens: Arc<Mutex<HashMap<String, RefreshToken>>>,
    session_events: Arc<Mutex<HashMap<String, Vec<SessionEvent>>>>,
}

#[derive(Clone)]
struct Session {
    id: String,
    user_id: String,
    token: String,
    created_at: String,
    expires_at: String,
    last_activity: String,
    ip_address: String,
    user_agent: String,
    device_fingerprint: Option<String>,
    is_active: bool,
    max_age_seconds: u64,
    idle_timeout_seconds: u64,
}

#[derive(Clone)]
struct User {
    id: String,
    email: String,
    max_concurrent_sessions: u32,
    session_timeout_minutes: u32,
    require_device_fingerprint: bool,
}

#[derive(Clone)]
struct SessionPolicy {
    id: String,
    name: String,
    max_sessions_per_user: u32,
    session_timeout_minutes: u32,
    idle_timeout_minutes: u32,
    require_mfa: bool,
    allowed_ip_ranges: Vec<String>,
    blocked_user_agents: Vec<String>,
    device_fingerprint_required: bool,
}

#[derive(Clone)]
struct RefreshToken {
    token: String,
    user_id: String,
    session_id: String,
    issued_at: String,
    expires_at: String,
    is_revoked: bool,
    used_count: u32,
}

#[derive(Clone)]
struct SessionEvent {
    id: String,
    session_id: String,
    event_type: String,
    description: String,
    timestamp: String,
    ip_address: String,
    user_agent: String,
    metadata: HashMap<String, String>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            users: Arc::new(Mutex::new(HashMap::new())),
            session_policies: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            session_events: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_session_creation_and_validation() {
    let session_state = SessionState::new();

    // Pre-populate with test user
    {
        let mut users = session_state.users.lock().await;
        users.insert(
            "user_123".to_string(),
            User {
                id: "user_123".to_string(),
                email: "test@example.com".to_string(),
                max_concurrent_sessions: 5,
                session_timeout_minutes: 480, // 8 hours
                require_device_fingerprint: false,
            },
        );
    }

    let app =
        Router::new()
            .route(
                "/sessions",
                post(
                    move |State(state): State<SessionState>,
                          Json(create): Json<serde_json::Value>| async move {
                        let mut sessions = state.sessions.lock().await;
                        let users = state.users.lock().await;
                        let mut session_events = state.session_events.lock().await;

                        let user_id = create.get("user_id").and_then(|u| u.as_str()).unwrap_or("");
                        let ip_address = create
                            .get("ip_address")
                            .and_then(|i| i.as_str())
                            .unwrap_or("127.0.0.1");
                        let user_agent = create
                            .get("user_agent")
                            .and_then(|u| u.as_str())
                            .unwrap_or("TestAgent/1.0");
                        let device_fingerprint =
                            create.get("device_fingerprint").and_then(|d| d.as_str());

                        if !users.contains_key(user_id) {
                            return Err(StatusCode::NOT_FOUND);
                        }

                        let user = users.get(user_id).unwrap();

                        // Check concurrent session limit
                        let user_sessions: Vec<_> = sessions
                            .values()
                            .filter(|s| s.user_id == user_id && s.is_active)
                            .collect();

                        if user_sessions.len() >= user.max_concurrent_sessions as usize {
                            return Err(StatusCode::TOO_MANY_REQUESTS);
                        }

                        let session_id = format!("session_{}", sessions.len() + 1);
                        let now = "2024-12-01T12:00:00Z".to_string();
                        let expires_at = "2024-12-01T20:00:00Z".to_string(); // 8 hours later

                        let session = Session {
                            id: session_id.clone(),
                            user_id: user_id.to_string(),
                            token: format!("token_{}", session_id),
                            created_at: now.clone(),
                            expires_at: expires_at.clone(),
                            last_activity: now.clone(),
                            ip_address: ip_address.to_string(),
                            user_agent: user_agent.to_string(),
                            device_fingerprint: device_fingerprint.map(|s| s.to_string()),
                            is_active: true,
                            max_age_seconds: user.session_timeout_minutes as u64 * 60,
                            idle_timeout_seconds: 3600, // 1 hour idle timeout
                        };

                        sessions.insert(session_id.clone(), session);

                        // Log session creation event
                        let event_count = session_events.len();
                        session_events
                            .entry(session_id.clone())
                            .or_insert_with(Vec::new)
                            .push(SessionEvent {
                                id: format!("event_{}", event_count + 1),
                                session_id: session_id.clone(),
                                event_type: "session_created".to_string(),
                                description: "New session created".to_string(),
                                timestamp: now,
                                ip_address: ip_address.to_string(),
                                user_agent: user_agent.to_string(),
                                metadata: HashMap::new(),
                            });

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "session_id": session_id,
                            "token": format!("token_{}", session_id),
                            "expires_at": expires_at,
                            "max_age_seconds": user.session_timeout_minutes * 60,
                            "status": "created"
                        })))
                    },
                ),
            )
            .route(
                "/sessions/{session_id}/validate",
                post(
                    move |State(state): State<SessionState>,
                          axum::extract::Path(session_id): axum::extract::Path<String>,
                          Json(validate): Json<serde_json::Value>| async move {
                        let mut sessions = state.sessions.lock().await;
                        let mut session_events = state.session_events.lock().await;

                        let token = validate.get("token").and_then(|t| t.as_str()).unwrap_or("");
                        let ip_address = validate
                            .get("ip_address")
                            .and_then(|i| i.as_str())
                            .unwrap_or("");
                        let user_agent = validate
                            .get("user_agent")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");

                        if let Some(session) = sessions.get_mut(&session_id) {
                            if !session.is_active {
                                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                    "valid": false,
                                    "reason": "session_inactive"
                                })));
                            }

                            if session.token != token {
                                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                    "valid": false,
                                    "reason": "invalid_token"
                                })));
                            }

                            // Check if session expired
                            let now = "2024-12-01T12:30:00Z".to_string();
                            if now > session.expires_at {
                                session.is_active = false;
                                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                    "valid": false,
                                    "reason": "session_expired"
                                })));
                            }

                            // Update last activity
                            session.last_activity = now.clone();
                            session.ip_address = ip_address.to_string();
                            session.user_agent = user_agent.to_string();

                            // Log validation event
                            let event_count = session_events.len();
                            session_events
                                .entry(session_id.clone())
                                .or_insert_with(Vec::new)
                                .push(SessionEvent {
                                    id: format!("event_{}", event_count + 1),
                                    session_id: session_id.clone(),
                                    event_type: "session_validated".to_string(),
                                    description: "Session validation successful".to_string(),
                                    timestamp: now,
                                    ip_address: ip_address.to_string(),
                                    user_agent: user_agent.to_string(),
                                    metadata: HashMap::new(),
                                });

                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "valid": true,
                                "session_id": session_id,
                                "user_id": session.user_id,
                                "expires_at": session.expires_at,
                                "last_activity": session.last_activity
                            })))
                        } else {
                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "valid": false,
                                "reason": "session_not_found"
                            })))
                        }
                    },
                ),
            )
            .with_state(session_state);

    let server = TestServer::new(app).unwrap();

    // Test session creation
    let create_data = json!({
        "user_id": "user_123",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "device_fingerprint": "fp_123456"
    });
    let response = server.post("/sessions").json(&create_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let session_id = body["session_id"].as_str().unwrap();
    let token = body["token"].as_str().unwrap();

    // Test session validation
    let validate_data = json!({
        "token": token,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    });
    let response = server
        .post(&format!("/sessions/{}/validate", session_id))
        .json(&validate_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["valid"], true);
    assert_eq!(body["session_id"], session_id);

    // Test invalid token
    let invalid_validate_data = json!({
        "token": "invalid_token",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0"
    });
    let response = server
        .post(&format!("/sessions/{}/validate", session_id))
        .json(&invalid_validate_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["valid"], false);
    assert_eq!(body["reason"], "invalid_token");
}

#[tokio::test]
async fn test_session_policies_and_limits() {
    let session_state = SessionState::new();

    // Pre-populate with test data
    {
        let mut users = session_state.users.lock().await;
        let mut session_policies = session_state.session_policies.lock().await;

        users.insert(
            "user_limited".to_string(),
            User {
                id: "user_limited".to_string(),
                email: "limited@example.com".to_string(),
                max_concurrent_sessions: 2, // Limited to 2 concurrent sessions
                session_timeout_minutes: 60,
                require_device_fingerprint: false,
            },
        );

        session_policies.insert(
            "policy_strict".to_string(),
            SessionPolicy {
                id: "policy_strict".to_string(),
                name: "Strict Security Policy".to_string(),
                max_sessions_per_user: 1,
                session_timeout_minutes: 30,
                idle_timeout_minutes: 15,
                require_mfa: true,
                allowed_ip_ranges: vec!["192.168.1.0/24".to_string()],
                blocked_user_agents: vec!["Bot/1.0".to_string()],
                device_fingerprint_required: true,
            },
        );
    }

    let app = Router::new()
        .route("/sessions/policy/check", post(move |State(state): State<SessionState>, Json(check): Json<serde_json::Value>| async move {
            let session_policies = state.session_policies.lock().await;
            let sessions = state.sessions.lock().await;

            let user_id = check.get("user_id").and_then(|u| u.as_str()).unwrap_or("");
            let ip_address = check.get("ip_address").and_then(|i| i.as_str()).unwrap_or("");
            let user_agent = check.get("user_agent").and_then(|u| u.as_str()).unwrap_or("");
            let policy_id = check.get("policy_id").and_then(|p| p.as_str()).unwrap_or("");

            let policy = session_policies.get(policy_id);
            if policy.is_none() {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "allowed": false,
                    "reason": "policy_not_found"
                })));
            }

            let policy = policy.unwrap();

            // Check concurrent session limit
            let user_sessions: Vec<_> = sessions.values()
                .filter(|s| s.user_id == user_id && s.is_active)
                .collect();

            if user_sessions.len() >= policy.max_sessions_per_user as usize {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "allowed": false,
                    "reason": "max_sessions_exceeded",
                    "current_sessions": user_sessions.len(),
                    "max_allowed": policy.max_sessions_per_user
                })));
            }

            // Check IP range (simplified)
            let allowed_ip = policy.allowed_ip_ranges.is_empty() ||
                policy.allowed_ip_ranges.iter().any(|range| ip_address.starts_with("192.168.1."));

            if !allowed_ip {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "allowed": false,
                    "reason": "ip_not_allowed"
                })));
            }

            // Check blocked user agents
            let blocked_ua = policy.blocked_user_agents.iter()
                .any(|blocked| user_agent.contains(blocked));

            if blocked_ua {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "allowed": false,
                    "reason": "user_agent_blocked"
                })));
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "allowed": true,
                "policy_id": policy_id,
                "max_sessions": policy.max_sessions_per_user,
                "session_timeout_minutes": policy.session_timeout_minutes,
                "idle_timeout_minutes": policy.idle_timeout_minutes
            })))
        }))
        .route("/sessions/user/{user_id}/active", get(move |State(state): State<SessionState>, axum::extract::Path(user_id): axum::extract::Path<String>| async move {
            let sessions = state.sessions.lock().await;

            let user_sessions: Vec<serde_json::Value> = sessions.values()
                .filter(|s| s.user_id == user_id && s.is_active)
                .map(|s| json!({
                    "session_id": s.id,
                    "created_at": s.created_at,
                    "last_activity": s.last_activity,
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent,
                    "expires_at": s.expires_at
                }))
                .collect();

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "active_sessions": user_sessions,
                "total_active": user_sessions.len()
            })))
        }))
        .route("/sessions/{session_id}/extend", post(move |State(state): State<SessionState>, axum::extract::Path(session_id): axum::extract::Path<String>| async move {
            let mut sessions = state.sessions.lock().await;

            if let Some(session) = sessions.get_mut(&session_id) {
                if !session.is_active {
                    return Err(StatusCode::BAD_REQUEST);
                }

                // Extend session by 1 hour
                session.expires_at = "2024-12-01T21:00:00Z".to_string();
                session.last_activity = "2024-12-01T13:00:00Z".to_string();

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "session_id": session_id,
                    "extended": true,
                    "new_expires_at": session.expires_at,
                    "message": "Session extended successfully"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(session_state);

    let server = TestServer::new(app).unwrap();

    // Test policy check - allowed
    let policy_check = json!({
        "user_id": "user_limited",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0",
        "policy_id": "policy_strict"
    });
    let response = server
        .post("/sessions/policy/check")
        .json(&policy_check)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], true);

    // Test policy check - blocked IP
    let blocked_policy_check = json!({
        "user_id": "user_limited",
        "ip_address": "10.0.0.100",
        "user_agent": "Mozilla/5.0",
        "policy_id": "policy_strict"
    });
    let response = server
        .post("/sessions/policy/check")
        .json(&blocked_policy_check)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "ip_not_allowed");

    // Test policy check - blocked user agent
    let blocked_ua_check = json!({
        "user_id": "user_limited",
        "ip_address": "192.168.1.100",
        "user_agent": "Bot/1.0",
        "policy_id": "policy_strict"
    });
    let response = server
        .post("/sessions/policy/check")
        .json(&blocked_ua_check)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "user_agent_blocked");

    // Test getting active sessions (should be empty initially)
    let response = server.get("/sessions/user/user_limited/active").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_active"], 0);
}

#[tokio::test]
async fn test_refresh_tokens_and_rotation() {
    let session_state = SessionState::new();

    let app = Router::new()
        .route("/tokens/refresh", post(move |State(state): State<SessionState>, Json(refresh): Json<serde_json::Value>| async move {
            let mut refresh_tokens = state.refresh_tokens.lock().await;
            let mut sessions = state.sessions.lock().await;

            let refresh_token = refresh.get("refresh_token").and_then(|t| t.as_str()).unwrap_or("");
            let session_id = refresh.get("session_id").and_then(|s| s.as_str()).unwrap_or("");

            if let Some(token_info) = refresh_tokens.get_mut(refresh_token) {
                if token_info.is_revoked {
                    return Err(StatusCode::UNAUTHORIZED);
                }

                if token_info.session_id != session_id {
                    return Err(StatusCode::UNAUTHORIZED);
                }

                // Check if refresh token expired
                let now = "2024-12-01T13:00:00Z".to_string();
                if now > token_info.expires_at {
                    token_info.is_revoked = true;
                    return Err(StatusCode::UNAUTHORIZED);
                }

                // Generate new tokens
                let new_access_token = format!("access_token_new_{}", token_info.used_count + 1);
                let new_refresh_token = format!("refresh_token_new_{}", token_info.used_count + 1);

                // Clone needed data before modifying
                let user_id = token_info.user_id.clone();
                let used_count = token_info.used_count;

                // Revoke old refresh token
                token_info.is_revoked = true;
                token_info.used_count += 1;

                // Create new refresh token
                refresh_tokens.insert(new_refresh_token.clone(), RefreshToken {
                    token: new_refresh_token.clone(),
                    user_id: user_id,
                    session_id: session_id.to_string(),
                    issued_at: now.clone(),
                    expires_at: "2024-12-08T13:00:00Z".to_string(),
                    is_revoked: false,
                    used_count: 0,
                });

                // Update session
                if let Some(session) = sessions.get_mut(session_id) {
                    session.last_activity = now.clone();
                    session.expires_at = "2024-12-01T21:00:00Z".to_string();
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "access_token": new_access_token,
                    "refresh_token": new_refresh_token,
                    "expires_in": 28800, // 8 hours
                    "token_type": "Bearer",
                    "session_extended": true
                })))
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }))
        .route("/tokens/revoke", post(move |State(state): State<SessionState>, Json(revoke): Json<serde_json::Value>| async move {
            let mut refresh_tokens = state.refresh_tokens.lock().await;
            let mut sessions = state.sessions.lock().await;

            let token = revoke.get("token").and_then(|t| t.as_str()).unwrap_or("");
            let revoke_session = revoke.get("revoke_session").and_then(|r| r.as_bool()).unwrap_or(false);

            if let Some(token_info) = refresh_tokens.get_mut(token) {
                token_info.is_revoked = true;

                if revoke_session {
                    if let Some(session) = sessions.get_mut(&token_info.session_id) {
                        session.is_active = false;
                    }
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "token": token,
                    "revoked": true,
                    "session_revoked": revoke_session,
                    "message": "Token revoked successfully"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/tokens/family/{user_id}/revoke", post(move |State(state): State<SessionState>, axum::extract::Path(user_id): axum::extract::Path<String>| async move {
            let mut refresh_tokens = state.refresh_tokens.lock().await;
            let mut sessions = state.sessions.lock().await;

            let mut revoked_count = 0;
            let mut tokens_to_revoke = Vec::new();

            // Find all refresh tokens for the user
            for (token, token_info) in refresh_tokens.iter() {
                if token_info.user_id == user_id && !token_info.is_revoked {
                    tokens_to_revoke.push(token.clone());
                }
            }

            // Revoke all tokens and their sessions
            for token in tokens_to_revoke {
                if let Some(token_info) = refresh_tokens.get_mut(&token) {
                    token_info.is_revoked = true;
                    if let Some(session) = sessions.get_mut(&token_info.session_id) {
                        session.is_active = false;
                    }
                    revoked_count += 1;
                }
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "tokens_revoked": revoked_count,
                "sessions_revoked": revoked_count,
                "message": format!("Revoked {} tokens and their associated sessions", revoked_count)
            })))
        }))
        .with_state(session_state.clone());

    let server = TestServer::new(app).unwrap();

    // Pre-populate with a refresh token
    {
        let mut refresh_tokens = session_state.refresh_tokens.lock().await;
        refresh_tokens.insert(
            "refresh_token_123".to_string(),
            RefreshToken {
                token: "refresh_token_123".to_string(),
                user_id: "user_123".to_string(),
                session_id: "session_123".to_string(),
                issued_at: "2024-12-01T12:00:00Z".to_string(),
                expires_at: "2024-12-08T12:00:00Z".to_string(),
                is_revoked: false,
                used_count: 0,
            },
        );
    }

    // Test token refresh
    let refresh_data = json!({
        "refresh_token": "refresh_token_123",
        "session_id": "session_123"
    });
    let response = server.post("/tokens/refresh").json(&refresh_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");

    // Test token revocation
    let revoke_data = json!({
        "token": "refresh_token_123",
        "revoke_session": true
    });
    let response = server.post("/tokens/revoke").json(&revoke_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["revoked"], true);
    assert_eq!(body["session_revoked"], true);

    // Test family revocation
    let response = server.post("/tokens/family/user_123/revoke").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["tokens_revoked"].as_u64().is_some());
}

#[tokio::test]
async fn test_session_events_and_audit() {
    let session_state = SessionState::new();

    let app = Router::new()
        .route("/sessions/{session_id}/events", get(move |State(state): State<SessionState>, axum::extract::Path(session_id): axum::extract::Path<String>| async move {
            let session_events = state.session_events.lock().await;

            if let Some(events) = session_events.get(&session_id) {
                let event_list: Vec<serde_json::Value> = events.iter()
                    .map(|event| json!({
                        "id": event.id,
                        "event_type": event.event_type,
                        "description": event.description,
                        "timestamp": event.timestamp,
                        "ip_address": event.ip_address,
                        "user_agent": event.user_agent,
                        "metadata": event.metadata
                    }))
                    .collect();

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "session_id": session_id,
                    "events": event_list,
                    "total_events": event_list.len()
                })))
            } else {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "session_id": session_id,
                    "events": [],
                    "total_events": 0
                })))
            }
        }))
        .route("/sessions/events/search", post(move |State(state): State<SessionState>, Json(search): Json<serde_json::Value>| async move {
            let session_events = state.session_events.lock().await;

            let event_type = search.get("event_type").and_then(|e| e.as_str());
            let user_id = search.get("user_id").and_then(|u| u.as_str());
            let ip_address = search.get("ip_address").and_then(|i| i.as_str());
            let from_date = search.get("from_date").and_then(|f| f.as_str()).unwrap_or("");
            let to_date = search.get("to_date").and_then(|t| t.as_str()).unwrap_or("9999-12-31T23:59:59Z");

            let mut matching_events = Vec::new();

            for (session_id, events) in session_events.iter() {
                for event in events {
                    // Apply filters
                    if let Some(et) = event_type {
                        if event.event_type != et {
                            continue;
                        }
                    }

                    if event.timestamp.as_str() < from_date || event.timestamp.as_str() > to_date {
                        continue;
                    }

                    if let Some(ip) = ip_address {
                        if event.ip_address != *ip {
                            continue;
                        }
                    }

                    matching_events.push(json!({
                        "session_id": session_id,
                        "event_id": event.id,
                        "event_type": event.event_type,
                        "description": event.description,
                        "timestamp": event.timestamp,
                        "ip_address": event.ip_address,
                        "user_agent": event.user_agent
                    }));
                }
            }

            // Sort by timestamp (most recent first)
            matching_events.sort_by(|a, b| {
                b["timestamp"].as_str().unwrap_or("").cmp(a["timestamp"].as_str().unwrap_or(""))
            });

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "events": matching_events,
                "total_found": matching_events.len(),
                "filters_applied": {
                    "event_type": event_type,
                    "ip_address": ip_address,
                    "date_range": format!("{} to {}", from_date, to_date)
                }
            })))
        }))
        .route("/sessions/security/violations", get(move |State(state): State<SessionState>| async move {
            let session_events = state.session_events.lock().await;

            let mut violations = Vec::new();

            for (session_id, events) in session_events.iter() {
                for event in events {
                    match event.event_type.as_str() {
                        "suspicious_activity" | "failed_login" | "session_hijacking_attempt" => {
                            violations.push(json!({
                                "session_id": session_id,
                                "event_id": event.id,
                                "violation_type": event.event_type,
                                "description": event.description,
                                "timestamp": event.timestamp,
                                "ip_address": event.ip_address,
                                "severity": if event.event_type == "session_hijacking_attempt" { "high" } else { "medium" }
                            }));
                        }
                        _ => {}
                    }
                }
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "security_violations": violations,
                "total_violations": violations.len(),
                "high_severity": violations.iter().filter(|v| v["severity"] == "high").count(),
                "medium_severity": violations.iter().filter(|v| v["severity"] == "medium").count()
            })))
        }))
        .with_state(session_state.clone());

    let server = TestServer::new(app).unwrap();

    // Pre-populate with some session events
    {
        let mut session_events = session_state.session_events.lock().await;
        session_events.insert(
            "session_123".to_string(),
            vec![
                SessionEvent {
                    id: "event_1".to_string(),
                    session_id: "session_123".to_string(),
                    event_type: "session_created".to_string(),
                    description: "New session created".to_string(),
                    timestamp: "2024-12-01T12:00:00Z".to_string(),
                    ip_address: "192.168.1.100".to_string(),
                    user_agent: "Mozilla/5.0".to_string(),
                    metadata: HashMap::new(),
                },
                SessionEvent {
                    id: "event_2".to_string(),
                    session_id: "session_123".to_string(),
                    event_type: "suspicious_activity".to_string(),
                    description: "Multiple failed login attempts detected".to_string(),
                    timestamp: "2024-12-01T12:15:00Z".to_string(),
                    ip_address: "192.168.1.100".to_string(),
                    user_agent: "Mozilla/5.0".to_string(),
                    metadata: HashMap::from([("failed_attempts".to_string(), "5".to_string())]),
                },
            ],
        );
    }

    // Test getting session events
    let response = server.get("/sessions/session_123/events").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_events"], 2);

    // Test searching events
    let search_data = json!({
        "event_type": "suspicious_activity",
        "from_date": "2024-12-01T00:00:00Z",
        "to_date": "2024-12-01T23:59:59Z"
    });
    let response = server
        .post("/sessions/events/search")
        .json(&search_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_found"], 1);
    assert_eq!(body["events"][0]["event_type"], "suspicious_activity");

    // Test security violations
    let response = server.get("/sessions/security/violations").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["total_violations"].as_u64().unwrap() >= 1);
}
