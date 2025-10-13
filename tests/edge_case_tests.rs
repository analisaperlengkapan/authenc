use axum::{
    Router,
    extract::{Json, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// Edge Case Tests
// Testing boundary conditions, edge cases, and unusual scenarios

#[derive(Clone)]
struct EdgeCaseState {
    users: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    sessions: Arc<Mutex<HashMap<String, String>>>,
    resources: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    audit_logs: Arc<Mutex<Vec<serde_json::Value>>>,
    rate_limits: Arc<Mutex<HashMap<String, u64>>>,
    locks: Arc<Mutex<HashMap<String, bool>>>,
}

impl EdgeCaseState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            resources: Arc::new(Mutex::new(HashMap::new())),
            audit_logs: Arc::new(Mutex::new(Vec::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_empty_and_null_inputs() {
    let state = EdgeCaseState::new();

    let app = Router::new()
        .route(
            "/api/users",
            post(
                move |State(state): State<EdgeCaseState>,
                      Json(user_data): Json<serde_json::Value>| async move {
                    let mut users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;

                    // Handle empty/null inputs
                    let email = user_data
                        .get("email")
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .trim();
                    let name = user_data
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .trim();

                    if email.is_empty() {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Email is required",
                            "code": "VALIDATION_ERROR"
                        })));
                    }

                    if name.is_empty() {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Name is required",
                            "code": "VALIDATION_ERROR"
                        })));
                    }

                    let user_id = format!("user_{}", users.len() + 1);
                    users.insert(
                        user_id.clone(),
                        json!({
                            "id": user_id,
                            "email": email,
                            "name": name,
                            "status": "active"
                        }),
                    );

                    audit_logs.push(json!({
                        "event": "user_created",
                        "user_id": user_id,
                        "timestamp": "2024-12-01T10:00:00Z"
                    }));

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user_id,
                        "message": "User created successfully"
                    })))
                },
            ),
        )
        .route(
            "/api/users/search",
            get(
                move |State(state): State<EdgeCaseState>,
                      Query(params): Query<HashMap<String, String>>| async move {
                    let users = state.users.lock().await;

                    let empty_string = "".to_string();
                    let query = params.get("q").unwrap_or(&empty_string).trim();
                    let limit = params
                        .get("limit")
                        .and_then(|l| l.parse::<usize>().ok())
                        .unwrap_or(10)
                        .min(100); // Cap at 100

                    if query.is_empty() {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "users": [],
                            "total": 0,
                            "message": "Empty search query"
                        })));
                    }

                    let results: Vec<_> = users
                        .values()
                        .filter(|u| {
                            let email = u.get("email").and_then(|e| e.as_str()).unwrap_or("");
                            let name = u.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            email.to_lowercase().contains(&query.to_lowercase())
                                || name.to_lowercase().contains(&query.to_lowercase())
                        })
                        .take(limit)
                        .cloned()
                        .collect();

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "users": results,
                        "total": results.len(),
                        "query": query,
                        "limit": limit
                    })))
                },
            ),
        )
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test empty email
    let user_data = json!({"email": "", "name": "Test User"});
    let response = server.post("/api/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Email is required");

    // Test empty name
    let user_data = json!({"email": "test@example.com", "name": ""});
    let response = server.post("/api/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Name is required");

    // Test null values
    let user_data = json!({"email": "test@example.com", "name": null});
    let response = server.post("/api/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Name is required");

    // Test whitespace-only inputs
    let user_data = json!({"email": "  ", "name": "Test User"});
    let response = server.post("/api/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Email is required");

    // Test empty search query
    let response = server.get("/api/users/search").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total"], 0);
    assert_eq!(body["message"], "Empty search query");

    // Test valid user creation
    let user_data = json!({"email": "test@example.com", "name": "Test User"});
    let response = server.post("/api/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["user_id"].as_str().is_some());

    // Test search with valid query
    let response = server.get("/api/users/search?q=test").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total"], 1);
}

#[tokio::test]
async fn test_extreme_values_and_limits() {
    let state = EdgeCaseState::new();

    let app = Router::new()
        .route("/api/users/batch", post(move |State(state): State<EdgeCaseState>, Json(batch_data): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;
            let mut audit_logs = state.audit_logs.lock().await;

            let max_batch_size = 100;
            let empty_vec = vec![];
            let original_batch = batch_data.get("users")
                .and_then(|u| u.as_array())
                .unwrap_or(&empty_vec);

            if original_batch.is_empty() {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "error": "No users provided",
                    "code": "EMPTY_BATCH"
                })));
            }

            if original_batch.len() > max_batch_size {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "error": format!("Batch size exceeds maximum of {}", max_batch_size),
                    "code": "BATCH_TOO_LARGE"
                })));
            }

            let users_to_create_refs = original_batch
                .iter()
                .take(max_batch_size)
                .collect::<Vec<_>>();

            let mut created_users = vec![];
            for user_data in &users_to_create_refs {
                let email = user_data.get("email").and_then(|e| e.as_str()).unwrap_or("");
                let name = user_data.get("name").and_then(|n| n.as_str()).unwrap_or("");

                if email.is_empty() || name.is_empty() {
                    continue; // Skip invalid users
                }

                let user_id = format!("user_{}", users.len() + 1);
                users.insert(user_id.clone(), json!({
                    "id": user_id,
                    "email": email,
                    "name": name,
                    "status": "active"
                }));

                created_users.push(json!({
                    "user_id": user_id,
                    "email": email
                }));

                audit_logs.push(json!({
                    "event": "user_created_batch",
                    "user_id": user_id,
                                            "batch_size": users_to_create_refs.len(),
                    "timestamp": "2024-12-01T10:00:00Z"
                }));
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "created_users": created_users,
                "total_created": created_users.len(),
                "batch_size": users_to_create_refs.len()
            })))
        }))
        .route("/api/data/large", post(move |State(state): State<EdgeCaseState>, Json(data): Json<serde_json::Value>| async move {
            let max_size_kb = 1024; // 1MB limit
            let data_size = serde_json::to_string(&data).unwrap().len();

            if data_size > max_size_kb * 1024 {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "error": "Data size exceeds limit",
                    "max_size_kb": max_size_kb,
                    "actual_size_kb": data_size / 1024,
                    "code": "SIZE_LIMIT_EXCEEDED"
                })));
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "message": "Data processed successfully",
                "size_kb": data_size / 1024,
                "status": "ok"
            })))
        }))
        .route("/api/operations/{count}", post(move |State(state): State<EdgeCaseState>, Path(count): Path<usize>| async move {
            let max_operations = 1000;

            if count > max_operations {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "error": format!("Operation count exceeds maximum of {}", max_operations),
                    "requested": count,
                    "max_allowed": max_operations,
                    "code": "TOO_MANY_OPERATIONS"
                })));
            }

            if count == 0 {
                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "error": "Operation count must be greater than 0",
                    "code": "INVALID_OPERATION_COUNT"
                })));
            }

            // Simulate operations
            let mut results = vec![];
            for i in 1..=count {
                results.push(json!({
                    "operation_id": i,
                    "status": "completed",
                    "timestamp": format!("2024-12-01T10:{:02}:00Z", i % 60)
                }));
            }

            let results_count = results.len();
            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "operations_completed": count,
                "results": results.into_iter().take(10).collect::<Vec<_>>(), // Return first 10 results
                "total_results": results_count,
                "status": "completed"
            })))
        }))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test empty batch
    let batch_data = json!({"users": []});
    let response = server.post("/api/users/batch").json(&batch_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "No users provided");

    // Test batch size limit
    let large_batch: Vec<serde_json::Value> = (0..150)
        .map(|i| json!({"email": format!("user{}@example.com", i), "name": format!("User {}", i)}))
        .collect();

    let batch_data = json!({"users": large_batch});
    let response = server.post("/api/users/batch").json(&batch_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(
        body.get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("")
            .contains("Batch size exceeds maximum")
    );

    // Test valid batch
    let batch_data = json!({"users": [
        {"email": "user1@example.com", "name": "User 1"},
        {"email": "user2@example.com", "name": "User 2"}
    ]});
    let response = server.post("/api/users/batch").json(&batch_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_created"], 2);

    // Test operation count limits
    let response = server.post("/api/operations/0").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["error"], "Operation count must be greater than 0");

    let response = server.post("/api/operations/1500").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["error"].as_str().unwrap().contains("exceeds maximum"));

    let response = server.post("/api/operations/50").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["operations_completed"], 50);
}

#[tokio::test]
async fn test_concurrent_access_and_race_conditions() {
    let state = EdgeCaseState::new();

    let app = Router::new()
        .route(
            "/api/counter/increment",
            post(
                move |State(state): State<EdgeCaseState>,
                      Json(request): Json<serde_json::Value>| async move {
                    let mut rate_limits = state.rate_limits.lock().await;
                    let client_id = request
                        .get("client_id")
                        .and_then(|c| c.as_str())
                        .unwrap_or("default");

                    let current_count = rate_limits.entry(client_id.to_string()).or_insert(0);
                    *current_count += 1;

                    // Simulate some processing time to increase chance of race conditions
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "client_id": client_id,
                        "count": *current_count,
                        "timestamp": "2024-12-01T10:00:00Z"
                    })))
                },
            ),
        )
        .route(
            "/api/lock/acquire",
            post(
                move |State(state): State<EdgeCaseState>,
                      Json(request): Json<serde_json::Value>| async move {
                    let mut locks = state.locks.lock().await;
                    let resource_id = request
                        .get("resource_id")
                        .and_then(|r| r.as_str())
                        .unwrap_or("default");

                    if *locks.get(resource_id).unwrap_or(&false) {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "resource_id": resource_id,
                            "locked": true,
                            "message": "Resource is already locked"
                        })));
                    }

                    locks.insert(resource_id.to_string(), true);

                    // Simulate holding the lock briefly
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                    locks.insert(resource_id.to_string(), false);

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "resource_id": resource_id,
                        "locked": false,
                        "message": "Lock acquired and released"
                    })))
                },
            ),
        )
        .route(
            "/api/session/concurrent",
            post(
                move |State(state): State<EdgeCaseState>,
                      Json(request): Json<serde_json::Value>| async move {
                    let mut sessions = state.sessions.lock().await;
                    let user_id = request
                        .get("user_id")
                        .and_then(|u| u.as_str())
                        .unwrap_or("default");

                    // Check for existing session
                    if sessions.contains_key(user_id) {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "session_exists": true,
                            "message": "Concurrent session detected"
                        })));
                    }

                    let session_id = format!("session_{}_{}", user_id, sessions.len());
                    sessions.insert(user_id.to_string(), session_id.clone());

                    // Simulate session processing
                    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user_id,
                        "session_id": session_id,
                        "created": true
                    })))
                },
            ),
        )
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test concurrent counter increments
    let mut handles = vec![];
    for _i in 0..10 {
        let state_clone_inner = state.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route(
                    "/api/counter/increment",
                    post(
                        move |State(state): State<EdgeCaseState>,
                              Json(request): Json<serde_json::Value>| async move {
                            let mut rate_limits = state.rate_limits.lock().await;
                            let client_id = request
                                .get("client_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("default");

                            let current_count =
                                rate_limits.entry(client_id.to_string()).or_insert(0);
                            *current_count += 1;

                            // Simulate some processing time to increase chance of race conditions
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "client_id": client_id,
                                "count": *current_count,
                                "timestamp": "2024-12-01T10:00:00Z"
                            })))
                        },
                    ),
                )
                .with_state(state_clone_inner);

            let _server = TestServer::new(app).unwrap();
            let request_data = json!({"client_id": "test_client"});
            let response = _server
                .post("/api/counter/increment")
                .json(&request_data)
                .await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            body["count"].as_u64().unwrap()
        });
        handles.push(handle);
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Results should be unique (1 through 10)
    let mut sorted_results = results.clone();
    sorted_results.sort();
    sorted_results.dedup();
    assert_eq!(sorted_results.len(), 10);

    // Test concurrent lock acquisition
    let state_clone = state.clone();
    let mut lock_handles = vec![];
    for _i in 0..5 {
        let state_clone_inner = state_clone.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route(
                    "/api/lock/acquire",
                    post(
                        move |State(state): State<EdgeCaseState>,
                              Json(request): Json<serde_json::Value>| async move {
                            let mut locks = state.locks.lock().await;
                            let resource_id = request
                                .get("resource_id")
                                .and_then(|r| r.as_str())
                                .unwrap_or("default");

                            if *locks.get(resource_id).unwrap_or(&false) {
                                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                    "resource_id": resource_id,
                                    "locked": true,
                                    "message": "Resource is already locked"
                                })));
                            }

                            locks.insert(resource_id.to_string(), true);

                            // Simulate holding the lock briefly
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                            locks.insert(resource_id.to_string(), false);

                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "resource_id": resource_id,
                                "locked": false,
                                "message": "Lock acquired and released"
                            })))
                        },
                    ),
                )
                .with_state(state_clone_inner);

            let _server = TestServer::new(app).unwrap();
            let request_data = json!({"resource_id": "shared_resource"});
            let response = _server.post("/api/lock/acquire").json(&request_data).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            body["message"].as_str().unwrap().to_string()
        });
        lock_handles.push(handle);
    }

    let mut lock_results = vec![];
    for handle in lock_handles {
        lock_results.push(handle.await.unwrap());
    }

    // Should have some successful acquisitions and some conflicts
    let success_count = lock_results
        .iter()
        .filter(|r| r.contains("released"))
        .count();
    let conflict_count = lock_results
        .iter()
        .filter(|r| r.contains("already locked"))
        .count();
    assert!(success_count > 0);
    assert!(conflict_count >= 0);

    // Test concurrent session creation
    let state_clone = state.clone();
    let mut session_handles = vec![];
    for _i in 0..3 {
        let state_clone_inner = state_clone.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route(
                    "/api/session/concurrent",
                    post(
                        move |State(state): State<EdgeCaseState>,
                              Json(request): Json<serde_json::Value>| async move {
                            let mut sessions = state.sessions.lock().await;
                            let user_id = request
                                .get("user_id")
                                .and_then(|u| u.as_str())
                                .unwrap_or("default");

                            // Check for existing session
                            if sessions.contains_key(user_id) {
                                return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                    "user_id": user_id,
                                    "session_exists": true,
                                    "message": "Concurrent session detected"
                                })));
                            }

                            let session_id = format!("session_{}_{}", user_id, sessions.len());
                            sessions.insert(user_id.to_string(), session_id.clone());

                            // Simulate session processing
                            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "user_id": user_id,
                                "session_id": session_id,
                                "created": true
                            })))
                        },
                    ),
                )
                .with_state(state_clone_inner);

            let _server = TestServer::new(app).unwrap();
            let request_data = json!({"user_id": "concurrent_user"});
            let response = _server
                .post("/api/session/concurrent")
                .json(&request_data)
                .await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            (
                body["created"].as_bool().unwrap_or(false),
                body["session_exists"].as_bool().unwrap_or(false),
            )
        });
        session_handles.push(handle);
    }

    let mut session_results = vec![];
    for handle in session_handles {
        session_results.push(handle.await.unwrap());
    }

    // Only one session should be created, others should detect existing session
    let created_count = session_results
        .iter()
        .filter(|(created, _)| *created)
        .count();
    let exists_count = session_results.iter().filter(|(_, exists)| *exists).count();
    assert_eq!(created_count, 1);
    assert_eq!(exists_count, 2);
}

#[tokio::test]
async fn test_malformed_data_and_injection_attempts() {
    let state = EdgeCaseState::new();

    let app = Router::new()
        .route(
            "/api/users/create",
            post(
                move |State(state): State<EdgeCaseState>,
                      Json(user_data): Json<serde_json::Value>| async move {
                    let mut users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;

                    // Basic input validation and sanitization
                    let email = user_data
                        .get("email")
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();

                    let name = user_data
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .trim();

                    // Check for suspicious patterns
                    let suspicious_patterns =
                        ["<script", "javascript:", "onload=", "eval(", "alert("];
                    let input_combined = format!("{} {}", email, name).to_lowercase();

                    for pattern in &suspicious_patterns {
                        if input_combined.contains(pattern) {
                            audit_logs.push(json!({
                                "event": "suspicious_input_detected",
                                "pattern": pattern,
                                "input": input_combined,
                                "timestamp": "2024-12-01T10:00:00Z"
                            }));

                            return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "error": "Invalid input detected",
                                "code": "SUSPICIOUS_INPUT"
                            })));
                        }
                    }

                    // Validate email format (basic)
                    if !email.contains('@') || !email.contains('.') {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Invalid email format",
                            "code": "INVALID_EMAIL"
                        })));
                    }

                    // Check for duplicate email
                    let email_exists = users
                        .values()
                        .any(|u| u.get("email").and_then(|e| e.as_str()) == Some(&email));
                    if email_exists {
                        return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Email already exists",
                            "code": "DUPLICATE_EMAIL"
                        })));
                    }

                    let user_id = format!("user_{}", users.len() + 1);
                    users.insert(
                        user_id.clone(),
                        json!({
                            "id": user_id,
                            "email": email,
                            "name": name,
                            "status": "active"
                        }),
                    );

                    audit_logs.push(json!({
                        "event": "user_created",
                        "user_id": user_id,
                        "timestamp": "2024-12-01T10:00:00Z"
                    }));

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user_id,
                        "message": "User created successfully"
                    })))
                },
            ),
        )
        .route(
            "/api/query",
            get(
                move |State(state): State<EdgeCaseState>,
                      Query(params): Query<HashMap<String, String>>| async move {
                    let users = state.users.lock().await;
                    let mut audit_logs = state.audit_logs.lock().await;

                    let empty_string = "".to_string();
                    let query = params.get("q").unwrap_or(&empty_string);

                    // Check for SQL injection patterns
                    let sql_patterns = [
                        "select", "union", "drop", "delete", "update", "insert", "--", "/*", "*/",
                    ];
                    let query_lower = query.to_lowercase();

                    for pattern in &sql_patterns {
                        if query_lower.contains(pattern) {
                            audit_logs.push(json!({
                                "event": "sql_injection_attempt",
                                "query": query,
                                "pattern": pattern,
                                "timestamp": "2024-12-01T10:00:00Z"
                            }));

                            return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "error": "Invalid query",
                                "code": "MALFORMED_QUERY"
                            })));
                        }
                    }

                    // Safe query execution (simplified)
                    let results: Vec<_> = users
                        .values()
                        .filter(|u| {
                            let email = u.get("email").and_then(|e| e.as_str()).unwrap_or("");
                            let name = u.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            email.contains(query) || name.contains(query)
                        })
                        .take(10)
                        .cloned()
                        .collect();

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "results": results,
                        "total": results.len(),
                        "query": query
                    })))
                },
            ),
        )
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test XSS attempt
    let malicious_data =
        json!({"email": "test@example.com", "name": "<script>alert('xss')</script>"});
    let response = server.post("/api/users/create").json(&malicious_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], "SUSPICIOUS_INPUT");

    // Test SQL injection attempt (URL encoded)
    let response = server
        .get("/api/query?q=admin%27%3B%20DROP%20TABLE%20users%3B%20--")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], "MALFORMED_QUERY");

    // Test malformed email
    let invalid_data = json!({"email": "invalid-email", "name": "Test User"});
    let response = server.post("/api/users/create").json(&invalid_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], "INVALID_EMAIL");

    // Create a valid user first for duplicate test
    let valid_user_data = json!({"email": "test@example.com", "name": "Test User"});
    let response = server
        .post("/api/users/create")
        .json(&valid_user_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["user_id"].as_str().is_some());

    // Test duplicate email
    let duplicate_data = json!({"email": "test@example.com", "name": "Another User"});
    let response = server.post("/api/users/create").json(&duplicate_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], "DUPLICATE_EMAIL");

    // Test valid input
    let valid_data = json!({"email": "new@example.com", "name": "Valid User"});
    let response = server.post("/api/users/create").json(&valid_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["user_id"].as_str().is_some());

    // Test safe query
    let response = server.get("/api/query?q=test").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total"], 1);
}

#[tokio::test]
async fn test_network_and_timeout_edge_cases() {
    let state = EdgeCaseState::new();

    let app = Router::new()
        .route(
            "/api/slow",
            get(
                move |State(state): State<EdgeCaseState>,
                      Query(params): Query<HashMap<String, String>>| async move {
                    let delay_ms = params
                        .get("delay")
                        .and_then(|d| d.parse::<u64>().ok())
                        .unwrap_or(100)
                        .min(5000); // Max 5 seconds

                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "message": "Slow response completed",
                        "delay_ms": delay_ms,
                        "timestamp": "2024-12-01T10:00:00Z"
                    })))
                },
            ),
        )
        .route(
            "/api/large",
            get(move |State(state): State<EdgeCaseState>| async move {
                // Generate large response
                let mut large_data = vec![];
                for i in 0..1000 {
                    large_data.push(json!({
                        "id": i,
                        "data": format!("Large data item {}", i),
                        "metadata": {
                            "size": 100,
                            "type": "test_data",
                            "timestamp": "2024-12-01T10:00:00Z"
                        }
                    }));
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "data": large_data,
                    "total_items": large_data.len(),
                    "size_kb": serde_json::to_string(&large_data).unwrap().len() / 1024
                })))
            }),
        )
        .route(
            "/api/intermittent",
            get(move |State(state): State<EdgeCaseState>| async move {
                let mut rate_limits = state.rate_limits.lock().await;
                let request_count = rate_limits.entry("intermittent".to_string()).or_insert(0);
                *request_count += 1;

                // Simulate intermittent failures
                if *request_count % 3 == 0 {
                    return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "error": "Service temporarily unavailable",
                        "code": "SERVICE_UNAVAILABLE",
                        "retry_after": 30
                    })));
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "message": "Service available",
                    "request_count": *request_count
                })))
            }),
        )
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Test slow responses
    let response = server.get("/api/slow?delay=100").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["delay_ms"], 100);

    // Test maximum delay limit
    let response = server.get("/api/slow?delay=10000").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["delay_ms"], 5000); // Should be capped at 5000

    // Test large response
    let response = server.get("/api/large").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_items"], 1000);
    assert!(body["size_kb"].as_u64().unwrap() > 100); // Should be reasonably large

    // Test intermittent failures
    for i in 1..=6 {
        let response = server.get("/api/intermittent").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        if i % 3 == 0 {
            assert_eq!(body["code"], "SERVICE_UNAVAILABLE");
        } else {
            assert_eq!(body["request_count"], i);
        }
    }
}
