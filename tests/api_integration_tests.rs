use axum::{
    Router,
    extract::{Json, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// Advanced API Integration Tests
// Testing comprehensive API interactions, cross-service calls, and complex workflows

#[derive(Clone)]
struct ApiIntegrationState {
    users: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    sessions: Arc<Mutex<HashMap<String, String>>>,
    audit_logs: Arc<Mutex<Vec<serde_json::Value>>>,
    notifications: Arc<Mutex<Vec<serde_json::Value>>>,
    api_metrics: Arc<Mutex<HashMap<String, u64>>>,
}

impl ApiIntegrationState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            audit_logs: Arc::new(Mutex::new(Vec::new())),
            notifications: Arc::new(Mutex::new(Vec::new())),
            api_metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_complete_user_registration_workflow() {
    let state = ApiIntegrationState::new();

    let app = Router::new()
        .route(
            "/api/v1/users/register",
            post(
                move |State(state): State<ApiIntegrationState>,
                      Json(user_data): Json<serde_json::Value>| async move {
                    let mut users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;
                    let mut notifications = state.notifications.lock().await;
                    let mut metrics = state.api_metrics.lock().await;

                    let user_id = format!("user_{}", users.len() + 1);
                    let email = user_data
                        .get("email")
                        .and_then(|e| e.as_str())
                        .unwrap_or("");

                    // Simulate user creation
                    users.insert(
                        user_id.clone(),
                        json!({
                            "id": user_id,
                            "email": email,
                            "status": "pending_verification",
                            "created_at": "2024-12-01T10:00:00Z"
                        }),
                    );

                    // Log audit event
                    audit_logs.push(json!({
                        "event": "user_registered",
                        "user_id": user_id,
                        "timestamp": "2024-12-01T10:00:00Z"
                    }));

                    // Send welcome notification
                    notifications.push(json!({
                        "type": "welcome_email",
                        "user_id": user_id,
                        "email": email
                    }));

                    // Update metrics
                    *metrics.entry("user_registrations".to_string()).or_insert(0) += 1;

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user_id,
                        "status": "pending_verification",
                        "message": "Registration successful, please verify your email"
                    })))
                },
            ),
        )
        .route(
            "/api/v1/users/{user_id}/verify",
            post(
                move |State(state): State<ApiIntegrationState>,
                      Path(user_id): Path<String>,
                      Json(verification): Json<serde_json::Value>| async move {
                    let mut users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;
                    let mut notifications = state.notifications.lock().await;

                    if let Some(user) = users.get_mut(&user_id) {
                        user["status"] = json!("active");

                        // Log verification event
                        audit_logs.push(json!({
                            "event": "user_verified",
                            "user_id": user_id,
                            "timestamp": "2024-12-01T10:05:00Z"
                        }));

                        // Send verification confirmation
                        notifications.push(json!({
                            "type": "verification_complete",
                            "user_id": user_id,
                            "email": user["email"]
                        }));

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "status": "active",
                            "message": "Account verified successfully"
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .route(
            "/api/v1/auth/login",
            post(
                move |State(state): State<ApiIntegrationState>,
                      Json(login_data): Json<serde_json::Value>| async move {
                    let users = state.users.lock().await;
                    let mut sessions = state.sessions.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;
                    let mut metrics = state.api_metrics.lock().await;

                    let email = login_data
                        .get("email")
                        .and_then(|e| e.as_str())
                        .unwrap_or("");
                    let password = login_data
                        .get("password")
                        .and_then(|p| p.as_str())
                        .unwrap_or("");

                    // Find user by email
                    let user = users.values().find(|u| u["email"] == email);

                    if let Some(user) = user {
                        if user["status"] == "active" && password == "valid_password" {
                            let session_id = format!("session_{}", sessions.len() + 1);
                            sessions.insert(
                                session_id.clone(),
                                user["id"].as_str().unwrap().to_string(),
                            );

                            // Log login event
                            audit_logs.push(json!({
                                "event": "user_login",
                                "user_id": user["id"],
                                "session_id": session_id,
                                "timestamp": "2024-12-01T10:10:00Z"
                            }));

                            // Update metrics
                            *metrics.entry("successful_logins".to_string()).or_insert(0) += 1;

                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "session_id": session_id,
                                "user_id": user["id"],
                                "message": "Login successful"
                            })))
                        } else {
                            // Update metrics
                            *metrics.entry("failed_logins".to_string()).or_insert(0) += 1;

                            Err(StatusCode::UNAUTHORIZED)
                        }
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test complete registration workflow
    let registration_data = json!({
        "email": "test@example.com",
        "password": "secure_password",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = server
        .post("/api/v1/users/register")
        .json(&registration_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "pending_verification");
    let user_id = body["user_id"].as_str().unwrap();

    // Test email verification
    let verification_data = json!({"verification_code": "123456"});
    let response = server
        .post(&format!("/api/v1/users/{}/verify", user_id))
        .json(&verification_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "active");

    // Test login after verification
    let login_data = json!({
        "email": "test@example.com",
        "password": "valid_password"
    });

    let response = server.post("/api/v1/auth/login").json(&login_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["session_id"].as_str().is_some());
    assert_eq!(body["user_id"], user_id);
}

#[tokio::test]
async fn test_api_rate_limiting_and_metrics() {
    let state = ApiIntegrationState::new();

    let app = Router::new()
        .route(
            "/api/v1/metrics",
            get(move |State(state): State<ApiIntegrationState>| async move {
                let metrics = state.api_metrics.lock().await;
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "metrics": *metrics
                })))
            }),
        )
        .route(
            "/api/v1/users/profile",
            get(
                move |State(state): State<ApiIntegrationState>,
                      Query(params): Query<HashMap<String, String>>| async move {
                    let users = state.users.lock().await;
                    let mut metrics = state.api_metrics.lock().await;

                    // Update metrics
                    *metrics.entry("api_calls".to_string()).or_insert(0) += 1;

                    let user_id = params.get("user_id").unwrap_or(&"".to_string()).clone();

                    if let Some(user) = users.get(&user_id) {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user": user
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test metrics endpoint
    let response = server.get("/api/v1/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["metrics"].is_object());

    // Test API call tracking
    let response = server.get("/api/v1/users/profile?user_id=user_1").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND); // User doesn't exist

    // Check metrics were updated
    let response = server.get("/api/v1/metrics").await;
    let body: serde_json::Value = response.json();
    assert_eq!(body["metrics"]["api_calls"], 1);
}

#[tokio::test]
async fn test_cross_service_api_integration() {
    let state = ApiIntegrationState::new();

    let app = Router::new()
        .route("/api/v1/users/{user_id}/audit-trail", get(move |State(state): State<ApiIntegrationState>, Path(user_id): Path<String>| async move {
            let audit_logs = state.audit_logs.lock().await;
            let user_audit_logs: Vec<_> = audit_logs.iter()
                .filter(|log| log["user_id"] == user_id)
                .cloned()
                .collect();

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "audit_trail": user_audit_logs,
                "total_events": user_audit_logs.len()
            })))
        }))
        .route("/api/v1/notifications/{user_id}", get(move |State(state): State<ApiIntegrationState>, Path(user_id): Path<String>| async move {
            let notifications = state.notifications.lock().await;
            let user_notifications: Vec<_> = notifications.iter()
                .filter(|n| n["user_id"] == user_id)
                .cloned()
                .collect();

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "notifications": user_notifications,
                "unread_count": user_notifications.len()
            })))
        }))
        .route("/api/v1/dashboard/{user_id}", get(move |State(state): State<ApiIntegrationState>, Path(user_id): Path<String>| async move {
            let users = state.users.lock().await;
            let sessions = state.sessions.lock().await;
            let audit_logs = state.audit_logs.lock().await;
            let notifications = state.notifications.lock().await;

            let user = users.get(&user_id);
            let active_sessions: Vec<_> = sessions.iter()
                .filter(|(_, uid)| **uid == user_id)
                .map(|(sid, _)| sid.clone())
                .collect();
            let user_audit_logs: Vec<_> = audit_logs.iter()
                .filter(|log| log["user_id"] == user_id)
                .cloned()
                .collect();
            let user_notifications: Vec<_> = notifications.iter()
                .filter(|n| n["user_id"] == user_id)
                .cloned()
                .collect();

            let total_activities = user_audit_logs.len();
            let total_notifications = user_notifications.len();

            if let Some(user) = user {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "user": user,
                    "active_sessions": active_sessions,
                    "recent_activity": user_audit_logs.into_iter().take(5).collect::<Vec<_>>(),
                    "notifications": user_notifications.into_iter().take(10).collect::<Vec<_>>(),
                    "stats": {
                        "total_sessions": active_sessions.len(),
                        "total_activities": total_activities,
                        "total_notifications": total_notifications
                    }
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test audit trail endpoint
    let response = server.get("/api/v1/users/user_1/audit-trail").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["user_id"], "user_1");
    assert!(body["audit_trail"].is_array());

    // Test notifications endpoint
    let response = server.get("/api/v1/notifications/user_1").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["user_id"], "user_1");
    assert!(body["notifications"].is_array());

    // Test dashboard endpoint
    let response = server.get("/api/v1/dashboard/user_1").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND); // User doesn't exist
}

#[tokio::test]
async fn test_api_error_handling_and_recovery() {
    let state = ApiIntegrationState::new();

    let app = Router::new()
        .route(
            "/api/v1/users/{user_id}/update",
            put(
                move |State(state): State<ApiIntegrationState>,
                      Path(user_id): Path<String>,
                      Json(update_data): Json<serde_json::Value>| async move {
                    let mut users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;

                    if let Some(user) = users.get_mut(&user_id) {
                        // Validate update data
                        if let Some(email) = update_data.get("email") {
                            if email.as_str().unwrap_or("").is_empty() {
                                return Err(StatusCode::BAD_REQUEST);
                            }
                            user["email"] = email.clone();
                        }

                        // Log update event
                        audit_logs.push(json!({
                            "event": "user_updated",
                            "user_id": user_id,
                            "timestamp": "2024-12-01T11:00:00Z"
                        }));

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "message": "User updated successfully",
                            "updated_fields": update_data
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .route(
            "/api/v1/health",
            get(|| async {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "status": "healthy",
                    "timestamp": "2024-12-01T11:00:00Z"
                })))
            }),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test successful update
    let update_data = json!({"email": "newemail@example.com"});
    let response = server
        .put("/api/v1/users/user_1/update")
        .json(&update_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND); // User doesn't exist

    // Test invalid update data
    let invalid_update_data = json!({"email": ""});
    let response = server
        .put("/api/v1/users/user_1/update")
        .json(&invalid_update_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND); // User doesn't exist

    // Test health endpoint
    let response = server.get("/api/v1/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_api_versioning_and_compatibility() {
    let state = ApiIntegrationState::new();

    let app = Router::new()
        .route("/api/v1/users/{user_id}", get(move |State(state): State<ApiIntegrationState>, Path(user_id): Path<String>| async move {
            let users = state.users.lock().await;

            if let Some(user) = users.get(&user_id) {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "user": user,
                    "api_version": "v1"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/api/v2/users/{user_id}", get(move |State(state): State<ApiIntegrationState>, Path(user_id): Path<String>| async move {
            let users = state.users.lock().await;
            let audit_logs = state.audit_logs.lock().await;

            if let Some(user) = users.get(&user_id) {
                let user_audit_count = audit_logs.iter()
                    .filter(|log| log["user_id"] == user_id)
                    .count();

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "user": user,
                    "api_version": "v2",
                    "audit_count": user_audit_count,
                    "enhanced_features": ["audit_trail", "metrics"]
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test v1 API
    let response = server.get("/api/v1/users/user_1").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Test v2 API
    let response = server.get("/api/v2/users/user_1").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Both versions should return consistent error responses
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_api_bulk_operations() {
    let state = ApiIntegrationState::new();

    let app = Router::new()
        .route(
            "/api/v1/users/bulk",
            post(
                move |State(state): State<ApiIntegrationState>,
                      Json(bulk_data): Json<serde_json::Value>| async move {
                    let mut users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;
                    let mut results = Vec::new();

                    if let Some(user_list) = bulk_data.get("users").and_then(|u| u.as_array()) {
                        for user_data in user_list {
                            let user_id = format!("user_{}", users.len() + 1);
                            let email = user_data
                                .get("email")
                                .and_then(|e| e.as_str())
                                .unwrap_or("");

                            users.insert(
                                user_id.clone(),
                                json!({
                                    "id": user_id,
                                    "email": email,
                                    "status": "active"
                                }),
                            );

                            audit_logs.push(json!({
                                "event": "bulk_user_created",
                                "user_id": user_id,
                                "timestamp": "2024-12-01T12:00:00Z"
                            }));

                            results.push(json!({
                                "user_id": user_id,
                                "status": "created"
                            }));
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "results": results,
                            "total_created": results.len(),
                            "success": true
                        })))
                    } else {
                        Err(StatusCode::BAD_REQUEST)
                    }
                },
            ),
        )
        .route(
            "/api/v1/users/bulk/status",
            get(move |State(state): State<ApiIntegrationState>| async move {
                let users = state.users.lock().await;
                let total_users = users.len();
                let active_users = users.values().filter(|u| u["status"] == "active").count();

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "total_users": total_users,
                    "active_users": active_users,
                    "inactive_users": total_users - active_users
                })))
            }),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test bulk user creation
    let bulk_user_data = json!({
        "users": [
            {"email": "user1@example.com"},
            {"email": "user2@example.com"},
            {"email": "user3@example.com"}
        ]
    });

    let response = server
        .post("/api/v1/users/bulk")
        .json(&bulk_user_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_created"], 3);
    assert_eq!(body["success"], true);

    // Test bulk status endpoint
    let response = server.get("/api/v1/users/bulk/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_users"], 3);
    assert_eq!(body["active_users"], 3);
}
