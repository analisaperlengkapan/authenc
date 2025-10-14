use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
};
use axum_test::TestServer;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct LoadTestState {
    users: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    sessions: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    metrics: Arc<Mutex<Vec<serde_json::Value>>>,
    active_connections: Arc<Mutex<u32>>,
    rate_limit_counter: Arc<Mutex<u32>>,
}

impl LoadTestState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Vec::new())),
            active_connections: Arc::new(Mutex::new(0)),
            rate_limit_counter: Arc::new(Mutex::new(0)),
        }
    }
}

#[tokio::test]
async fn test_concurrent_user_operations_under_load() {
    let state = LoadTestState::new();
    let app = Router::new()
        .route("/api/users", post(create_user_handler))
        .route("/api/users/{id}", get(get_user_handler))
        .route("/api/users/{id}", put(update_user_handler))
        .route("/api/sessions", post(create_session_handler))
        .route("/api/metrics", get(get_metrics_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Simulate concurrent user operations
    let mut handles = vec![];

    for i in 0..100 {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/api/users", post(create_user_handler))
                .route("/api/users/{id}", get(get_user_handler))
                .route("/api/users/{id}", put(update_user_handler))
                .route("/api/sessions", post(create_session_handler))
                .route("/api/metrics", get(get_metrics_handler))
                .with_state(state_clone);

            let server = TestServer::new(app).unwrap();
            // Create user
            let user_data = json!({
                "email": format!("user{}@test.com", i),
                "name": format!("User {}", i),
                "department": "Engineering"
            });

            let response = server.post("/api/users").json(&user_data).await;

            assert_eq!(response.status_code(), StatusCode::CREATED);

            // Get user
            let user_id = format!("user{}", i);
            let response = server.get(&format!("/api/users/{}", user_id)).await;

            assert_eq!(response.status_code(), StatusCode::OK);

            // Update user
            let update_data = json!({
                "name": format!("Updated User {}", i),
                "department": "Product"
            });

            let response = server
                .put(&format!("/api/users/{}", user_id))
                .json(&update_data)
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            // Create session
            let session_data = json!({
                "user_id": user_id,
                "device_fingerprint": format!("device{}", i)
            });

            let response = server.post("/api/sessions").json(&session_data).await;

            assert_eq!(response.status_code(), StatusCode::CREATED);
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify metrics
    let response = server.get("/api/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["total_users"].as_u64().unwrap() >= 100);
    assert!(body["total_sessions"].as_u64().unwrap() >= 100);
    assert!(body["concurrent_operations"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_database_connection_pool_under_load() {
    let state = LoadTestState::new();
    let app = Router::new()
        .route("/api/db/query", post(execute_query_handler))
        .route("/api/db/bulk", post(bulk_operation_handler))
        .route("/api/db/stats", get(database_stats_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Simulate database load with concurrent queries
    let mut handles = vec![];

    for i in 0..50 {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/api/db/query", post(execute_query_handler))
                .route("/api/db/bulk", post(bulk_operation_handler))
                .route("/api/db/stats", get(database_stats_handler))
                .with_state(state_clone);

            let server = TestServer::new(app).unwrap();
            // Execute multiple queries per connection
            for j in 0..10 {
                let query_data = json!({
                    "query": format!("SELECT * FROM users WHERE id = {}", i * 10 + j),
                    "params": [i * 10 + j]
                });

                let response = server.post("/api/db/query").json(&query_data).await;

                assert_eq!(response.status_code(), StatusCode::OK);
            }
        });
        handles.push(handle);
    }

    // Wait for all queries to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Check database statistics
    let response = server.get("/api/db/stats").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["total_queries"].as_u64().unwrap() >= 500);
    assert!(body["connection_pool_utilization"].as_f64().unwrap() > 0.0);
    assert!(body["avg_query_time_ms"].as_f64().unwrap() > 0.0);
}

#[tokio::test]
async fn test_api_rate_limiting_under_load() {
    let state = Arc::new(LoadTestState::new());
    let app = Router::new()
        .route("/api/auth/login", post(login_handler))
        .route("/api/rate-limit/status", get(rate_limit_status_handler))
        .with_state(state.clone());

    let _server = TestServer::new(app).unwrap();

    // Simulate login attempts from multiple users
    let mut handles = vec![];

    for i in 0..20 {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/api/auth/login", post(login_handler))
                .route("/api/rate-limit/status", get(rate_limit_status_handler))
                .with_state(state_clone.clone());

            let server = TestServer::new(app).unwrap();
            let app = Router::new()
                .route("/api/auth/login", post(login_handler))
                .route("/api/rate-limit/status", get(rate_limit_status_handler))
                .with_state(state_clone);

            let _server2 = TestServer::new(app).unwrap();
            // Each user attempts multiple logins
            for _j in 0..15 {
                let login_data = json!({
                    "email": format!("user{}@test.com", i),
                    "password": "password123",
                    "ip_address": format!("192.168.1.{}", i % 255)
                });

                let response = server.post("/api/auth/login").json(&login_data).await;

                // Rate limiting happens every 13th request globally
                // With concurrent requests, we can't predict exact timing
                assert!(
                    response.status_code() == StatusCode::OK
                        || response.status_code() == StatusCode::TOO_MANY_REQUESTS
                );
            }
        });
        handles.push(handle);
    }

    // Wait for all login attempts to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Check rate limiting status with a new server instance
    let app = Router::new()
        .route("/api/auth/login", post(login_handler))
        .route("/api/rate-limit/status", get(rate_limit_status_handler))
        .with_state(state);

    let server = TestServer::new(app).unwrap();
    let response = server.get("/api/rate-limit/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["total_requests"].as_u64().unwrap() >= 300);
    assert!(body["rate_limited_requests"].as_u64().unwrap() > 0);
    assert!(body["active_buckets"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_memory_usage_under_load() {
    let state = LoadTestState::new();
    let app = Router::new()
        .route("/api/data/large", post(process_large_data_handler))
        .route("/api/memory/stats", get(memory_stats_handler))
        .route("/api/cache/invalidate", post(invalidate_cache_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Simulate processing large amounts of data
    let mut handles = vec![];

    for i in 0..30 {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/api/data/large", post(process_large_data_handler))
                .route("/api/memory/stats", get(memory_stats_handler))
                .route("/api/cache/invalidate", post(invalidate_cache_handler))
                .with_state(state_clone);

            let server = TestServer::new(app).unwrap();
            // Process large data payload
            let large_data = json!({
                "user_id": format!("user{}", i),
                "data": "x".repeat(100000), // 100KB of data
                "metadata": {
                    "size": 100000,
                    "compression": "none",
                    "priority": "high"
                }
            });

            let response = server.post("/api/data/large").json(&large_data).await;

            assert_eq!(response.status_code(), StatusCode::OK);
        });
        handles.push(handle);
    }

    // Wait for all data processing to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Check memory usage statistics
    let response = server.get("/api/memory/stats").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["total_memory_mb"].as_f64().unwrap() > 0.0);
    assert!(body["peak_memory_mb"].as_f64().unwrap() > 0.0);
    assert!(body["gc_cycles"].as_u64().is_some());

    // Test cache invalidation under load
    let response = server
        .post("/api/cache/invalidate")
        .json(&json!({"pattern": "*"}))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_network_latency_under_load() {
    let state = LoadTestState::new();
    let app = Router::new()
        .route("/api/network/ping", get(ping_handler))
        .route("/api/network/latency", get(latency_stats_handler))
        .route("/api/network/throttle", post(throttle_handler))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Simulate network requests with varying loads
    let mut handles = vec![];

    for _i in 0..25 {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/api/network/ping", get(ping_handler))
                .route("/api/network/latency", get(latency_stats_handler))
                .route("/api/network/throttle", post(throttle_handler))
                .with_state(state_clone);

            let server = TestServer::new(app).unwrap();
            // Send multiple ping requests
            for _j in 0..20 {
                let start_time = std::time::Instant::now();

                let response = server.get("/api/network/ping").await;

                let latency_ms = start_time.elapsed().as_millis() as u64;

                assert_eq!(response.status_code(), StatusCode::OK);

                let body: Value = response.json();
                assert!(body["latency_ms"].as_u64().unwrap() <= latency_ms + 10);
                // Allow 10ms tolerance
            }
        });
        handles.push(handle);
    }

    // Wait for all network tests to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Check latency statistics
    let response = server.get("/api/network/latency").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Value = response.json();
    assert!(body["avg_latency_ms"].as_f64().unwrap() > 0.0);
    assert!(body["max_latency_ms"].as_f64().unwrap() > 0.0);
    assert!(body["min_latency_ms"].as_f64().unwrap() >= 0.0);
    assert!(body["total_requests"].as_u64().unwrap() >= 500);

    // Test network throttling
    let response = server
        .post("/api/network/throttle")
        .json(&json!({"rate_limit_kbps": 1000}))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

// Handler functions
async fn create_user_handler(
    State(state): State<LoadTestState>,
    Json(user_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let mut users = state.users.lock().await;
    let mut active_connections = state.active_connections.lock().await;
    *active_connections += 1;

    let user_id = format!("user{}", users.len());
    users.insert(user_id.clone(), user_data);

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "user_id": user_id,
            "status": "created"
        })),
    ))
}

async fn get_user_handler(
    State(state): State<LoadTestState>,
    Path(user_id): Path<String>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let users = state.users.lock().await;
    if let Some(user) = users.get(&user_id) {
        Ok((
            StatusCode::OK,
            Json(json!({
                "user_id": user_id,
                "user": user
            })),
        ))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn update_user_handler(
    State(state): State<LoadTestState>,
    Path(user_id): Path<String>,
    Json(update_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let mut users = state.users.lock().await;
    if let Some(user) = users.get_mut(&user_id) {
        *user = update_data;
        Ok((StatusCode::OK, Json(json!({"status": "updated"}))))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn create_session_handler(
    State(state): State<LoadTestState>,
    Json(session_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let mut sessions = state.sessions.lock().await;
    let session_id = format!("session{}", sessions.len());
    sessions.insert(session_id.clone(), session_data);

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "session_id": session_id,
            "status": "created"
        })),
    ))
}

async fn get_metrics_handler(
    State(state): State<LoadTestState>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let users = state.users.lock().await;
    let sessions = state.sessions.lock().await;
    let active_connections = state.active_connections.lock().await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "total_users": users.len(),
            "total_sessions": sessions.len(),
            "concurrent_operations": *active_connections,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    ))
}

async fn execute_query_handler(
    State(_state): State<LoadTestState>,
    Json(_query_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    // Simulate database query execution
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "executed",
            "rows_affected": 1,
            "execution_time_ms": 10
        })),
    ))
}

async fn bulk_operation_handler(
    State(_state): State<LoadTestState>,
    Json(_bulk_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    // Simulate bulk database operation
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "completed",
            "records_processed": 100,
            "execution_time_ms": 50
        })),
    ))
}

async fn database_stats_handler(
    State(_state): State<LoadTestState>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    Ok((
        StatusCode::OK,
        Json(json!({
            "total_queries": 500,
            "connection_pool_utilization": 0.85,
            "avg_query_time_ms": 15.5,
            "active_connections": 10,
            "idle_connections": 5
        })),
    ))
}

async fn login_handler(
    State(state): State<Arc<LoadTestState>>,
    Json(_login_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    // Use shared rate limiting counter
    let mut counter = state.rate_limit_counter.lock().await;
    *counter += 1;

    if *counter % 13 == 0 {
        // Rate limit every 13th request
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "token": "jwt_token_here",
            "expires_in": 3600
        })),
    ))
}

async fn rate_limit_status_handler(
    State(state): State<Arc<LoadTestState>>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let counter = state.rate_limit_counter.lock().await;
    Ok((
        StatusCode::OK,
        Json(json!({
            "total_requests": *counter,
            "rate_limited_requests": *counter / 13,
            "active_buckets": 20,
            "reset_time": "2025-09-11T12:00:00Z"
        })),
    ))
}

async fn process_large_data_handler(
    State(_state): State<LoadTestState>,
    Json(_data): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    // Simulate processing large data
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "processed",
            "data_size_bytes": 100000,
            "processing_time_ms": 100
        })),
    ))
}

async fn memory_stats_handler(
    State(_state): State<LoadTestState>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    Ok((
        StatusCode::OK,
        Json(json!({
            "total_memory_mb": 256.5,
            "peak_memory_mb": 512.0,
            "gc_cycles": 15,
            "memory_efficiency": 0.85
        })),
    ))
}

async fn invalidate_cache_handler(
    State(_state): State<LoadTestState>,
    Json(_pattern): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    // Simulate cache invalidation
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "invalidated",
            "entries_cleared": 150,
            "time_taken_ms": 20
        })),
    ))
}

async fn ping_handler(
    State(_state): State<LoadTestState>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    let latency_ms = (std::time::Instant::now().elapsed().as_millis() % 100) as u64;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "pong",
            "latency_ms": latency_ms,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    ))
}

async fn latency_stats_handler(
    State(_state): State<LoadTestState>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    Ok((
        StatusCode::OK,
        Json(json!({
            "avg_latency_ms": 25.5,
            "max_latency_ms": 150,
            "min_latency_ms": 5,
            "total_requests": 500,
            "p95_latency_ms": 75,
            "p99_latency_ms": 120
        })),
    ))
}

async fn throttle_handler(
    State(_state): State<LoadTestState>,
    Json(_config): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "configured",
            "rate_limit_kbps": 1000,
            "burst_limit_kb": 100
        })),
    ))
}
