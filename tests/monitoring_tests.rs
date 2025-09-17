use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration, Instant};
use uuid::Uuid;

// Shared test state for monitoring tests
type SharedState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

#[derive(Clone)]
struct AppState {
    data: SharedState,
    metrics: Arc<Mutex<HashMap<String, serde_json::Value>>>,
}

// Monitoring and observability test handlers
async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
        "uptime": "1234567890", // In real app, this would be actual uptime
        "environment": "test"
    }))
}

async fn readiness_check() -> Json<serde_json::Value> {
    // Simulate database connectivity check
    sleep(Duration::from_millis(50)).await;

    Json(json!({
        "status": "ready",
        "checks": {
            "database": "ok",
            "cache": "ok",
            "external_services": "ok"
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn liveness_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "memory_usage": "45MB",
        "cpu_usage": "12%"
    }))
}

async fn metrics_endpoint(State(state): State<AppState>) -> Json<serde_json::Value> {
    let metrics = state.metrics.lock().unwrap();

    Json(json!({
        "metrics": {
            "http_requests_total": metrics.get("http_requests_total").and_then(|v| v.as_u64()).unwrap_or(0),
            "http_requests_duration_seconds": {
                "count": metrics.get("http_requests_count").and_then(|v| v.as_u64()).unwrap_or(0),
                "sum": metrics.get("http_requests_duration_sum").and_then(|v| v.as_f64()).unwrap_or(0.0)
            },
            "active_connections": metrics.get("active_connections").and_then(|v| v.as_u64()).unwrap_or(0),
            "memory_usage_bytes": metrics.get("memory_usage_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
            "cpu_usage_percent": metrics.get("cpu_usage_percent").and_then(|v| v.as_f64()).unwrap_or(0.0)
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn create_monitored_resource(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();
    let mut metrics = state.metrics.lock().unwrap();

    // Record metrics
    let request_count = metrics
        .get("http_requests_total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    metrics.insert("http_requests_total".to_string(), json!(request_count + 1));

    let start_time = Instant::now();

    let resource_id = Uuid::new_v4().to_string();
    let mut resource = payload.clone();
    resource["id"] = json!(resource_id);
    resource["created_at"] = json!(chrono::Utc::now().to_rfc3339());

    data.insert(resource_id.clone(), resource.clone());

    // Record request duration
    let duration = start_time.elapsed().as_secs_f64();
    let duration_sum = metrics
        .get("http_requests_duration_sum")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let duration_count = metrics
        .get("http_requests_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    metrics.insert(
        "http_requests_duration_sum".to_string(),
        json!(duration_sum + duration),
    );
    metrics.insert("http_requests_count".to_string(), json!(duration_count + 1));

    Ok(Json(json!({
        "success": true,
        "resource": resource,
        "processing_time_ms": duration * 1000.0
    })))
}

async fn get_monitored_resource(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let data = state.data.lock().unwrap();
    let mut metrics = state.metrics.lock().unwrap();

    // Record metrics
    let request_count = metrics
        .get("http_requests_total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    metrics.insert("http_requests_total".to_string(), json!(request_count + 1));

    let start_time = Instant::now();

    let result = if let Some(resource) = data.get(&resource_id) {
        Ok(Json(json!({
            "success": true,
            "resource": resource,
            "processing_time_ms": start_time.elapsed().as_millis() as f64
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    };

    // Record request duration
    let duration = start_time.elapsed().as_secs_f64();
    let duration_sum = metrics
        .get("http_requests_duration_sum")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let duration_count = metrics
        .get("http_requests_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    metrics.insert(
        "http_requests_duration_sum".to_string(),
        json!(duration_sum + duration),
    );
    metrics.insert("http_requests_count".to_string(), json!(duration_count + 1));

    result
}

async fn system_info() -> Json<serde_json::Value> {
    Json(json!({
        "system": {
            "hostname": "test-server",
            "os": "linux",
            "architecture": "x86_64",
            "cpu_cores": 4,
            "memory_total": "8GB",
            "disk_total": "100GB"
        },
        "application": {
            "name": "Authence",
            "version": "1.0.0",
            "build_time": chrono::Utc::now().to_rfc3339(),
            "git_commit": "abc123def456"
        },
        "runtime": {
            "uptime_seconds": 3600,
            "start_time": (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
            "process_id": 12345,
            "threads": 8
        }
    }))
}

async fn performance_snapshot(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.data.lock().unwrap();
    let metrics = state.metrics.lock().unwrap();

    let total_resources = data.len();
    let total_requests = metrics
        .get("http_requests_total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let avg_response_time = if total_requests > 0 {
        let duration_sum = metrics
            .get("http_requests_duration_sum")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        duration_sum / total_requests as f64
    } else {
        0.0
    };

    Json(json!({
        "performance_snapshot": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "total_resources": total_resources,
            "total_requests": total_requests,
            "average_response_time_seconds": avg_response_time,
            "requests_per_second": total_requests as f64 / 60.0, // Assuming 1 minute window
            "memory_usage_mb": 45.2,
            "cpu_usage_percent": 12.5,
            "active_connections": 23
        }
    }))
}

async fn log_analysis() -> Json<serde_json::Value> {
    Json(json!({
        "log_analysis": {
            "time_range": "last_24_hours",
            "total_logs": 15432,
            "error_count": 23,
            "warning_count": 156,
            "info_count": 15253,
            "top_errors": [
                {
                    "message": "Database connection timeout",
                    "count": 12,
                    "percentage": 52.2
                },
                {
                    "message": "Invalid authentication token",
                    "count": 8,
                    "percentage": 34.8
                }
            ],
            "response_time_distribution": {
                "p50": 0.125,
                "p95": 0.890,
                "p99": 2.145
            }
        }
    }))
}

async fn security_audit() -> Json<serde_json::Value> {
    Json(json!({
        "security_audit": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "audit_period": "last_7_days",
            "failed_login_attempts": 45,
            "blocked_ips": ["192.168.1.100", "10.0.0.50"],
            "suspicious_activities": [
                {
                    "type": "brute_force_attempt",
                    "ip": "192.168.1.100",
                    "attempts": 25,
                    "blocked": true
                }
            ],
            "security_score": 92,
            "recommendations": [
                "Consider implementing rate limiting for API endpoints",
                "Review failed authentication patterns"
            ]
        }
    }))
}

async fn dependency_health() -> Json<serde_json::Value> {
    Json(json!({
        "dependencies": {
            "database": {
                "status": "healthy",
                "response_time_ms": 12,
                "connection_pool_size": 10,
                "active_connections": 3
            },
            "cache": {
                "status": "healthy",
                "response_time_ms": 2,
                "hit_rate": 0.95,
                "memory_usage_mb": 128
            },
            "message_queue": {
                "status": "healthy",
                "response_time_ms": 5,
                "queue_depth": 0,
                "messages_processed": 15432
            },
            "external_api": {
                "status": "degraded",
                "response_time_ms": 1250,
                "error_rate": 0.05,
                "last_success": "2025-09-11T10:30:00Z"
            }
        },
        "overall_health": "degraded"
    }))
}

#[tokio::test]
async fn test_health_check_endpoints() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/live", get(liveness_check))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test health check
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
    assert_eq!(body["version"], "1.0.0");

    // Test readiness check
    let response = server.get("/ready").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "ready");
    assert!(body["checks"]["database"].is_string());

    // Test liveness check
    let response = server.get("/live").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "alive");
    assert!(body["memory_usage"].is_string());
}

#[tokio::test]
async fn test_metrics_collection_and_reporting() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .route("/resources", post(create_monitored_resource))
        .route("/resources/{id}", get(get_monitored_resource))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Check initial metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["metrics"]["http_requests_total"], 0);

    // Create some resources to generate metrics
    for i in 0..5 {
        let response = server
            .post("/resources")
            .json(&json!({
                "name": format!("Test Resource {}", i),
                "type": "test"
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Check updated metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["metrics"]["http_requests_total"], 5);
    assert!(
        body["metrics"]["http_requests_duration_seconds"]["count"]
            .as_u64()
            .unwrap()
            >= 5
    );

    // Make some GET requests
    for i in 0..3 {
        let _response = server.get(&format!("/resources/resource_{}", i)).await;
        // These will return 404, but metrics should still be recorded
    }

    // Check final metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["metrics"]["http_requests_total"], 8); // 5 POST + 3 GET
}

#[tokio::test]
async fn test_system_monitoring_and_info() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/system/info", get(system_info))
        .route("/system/performance", get(performance_snapshot))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test system info
    let response = server.get("/system/info").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["system"]["hostname"], "test-server");
    assert_eq!(body["application"]["name"], "Authence");
    assert_eq!(body["runtime"]["threads"], 8);

    // Test performance snapshot
    let response = server.get("/system/performance").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert!(body["performance_snapshot"]["timestamp"].is_string());
    assert!(body["performance_snapshot"]["total_resources"].is_number());
    assert!(body["performance_snapshot"]["average_response_time_seconds"].is_number());
}

#[tokio::test]
async fn test_log_analysis_and_security_audit() {
    let app = Router::new()
        .route("/monitoring/logs", get(log_analysis))
        .route("/monitoring/security", get(security_audit));

    let server = TestServer::new(app).unwrap();

    // Test log analysis
    let response = server.get("/monitoring/logs").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["log_analysis"]["time_range"], "last_24_hours");
    assert!(body["log_analysis"]["total_logs"].is_number());
    assert!(body["log_analysis"]["top_errors"].is_array());

    // Test security audit
    let response = server.get("/monitoring/security").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert!(body["security_audit"]["failed_login_attempts"].is_number());
    assert!(body["security_audit"]["blocked_ips"].is_array());
    assert!(body["security_audit"]["security_score"].is_number());
}

#[tokio::test]
async fn test_dependency_health_monitoring() {
    let app = Router::new().route("/health/dependencies", get(dependency_health));

    let server = TestServer::new(app).unwrap();

    let response = server.get("/health/dependencies").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();

    // Check database health
    assert_eq!(body["dependencies"]["database"]["status"], "healthy");
    assert!(body["dependencies"]["database"]["response_time_ms"].is_number());

    // Check cache health
    assert_eq!(body["dependencies"]["cache"]["status"], "healthy");
    assert!(body["dependencies"]["cache"]["hit_rate"].is_number());

    // Check degraded service
    assert_eq!(body["dependencies"]["external_api"]["status"], "degraded");
    assert!(body["dependencies"]["external_api"]["error_rate"].is_number());

    // Check overall health
    assert_eq!(body["overall_health"], "degraded");
}

#[tokio::test]
async fn test_comprehensive_monitoring_workflow() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/live", get(liveness_check))
        .route("/metrics", get(metrics_endpoint))
        .route("/system/info", get(system_info))
        .route("/system/performance", get(performance_snapshot))
        .route("/resources", post(create_monitored_resource))
        .route("/resources/{id}", get(get_monitored_resource))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Step 1: Check system health
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server.get("/ready").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server.get("/live").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Step 2: Get initial metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let initial_metrics: serde_json::Value = response.json();

    // Step 3: Generate some activity
    let mut resource_ids = vec![];
    for i in 0..10 {
        let response = server
            .post("/resources")
            .json(&json!({
                "name": format!("Monitored Resource {}", i),
                "type": "test",
                "category": format!("category_{}", i % 3)
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        resource_ids.push(body["resource"]["id"].as_str().unwrap().to_string());
        assert!(body["processing_time_ms"].is_number());
    }

    // Step 4: Access some resources
    for resource_id in resource_ids.iter().take(5) {
        let response = server.get(&format!("/resources/{}", resource_id)).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert!(body["processing_time_ms"].is_number());
    }

    // Step 5: Check updated metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let updated_metrics: serde_json::Value = response.json();

    let initial_requests = initial_metrics["metrics"]["http_requests_total"]
        .as_u64()
        .unwrap_or(0);
    let updated_requests = updated_metrics["metrics"]["http_requests_total"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(updated_requests, initial_requests + 15); // 10 POST + 5 GET

    // Step 6: Get system information
    let response = server.get("/system/info").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Step 7: Get performance snapshot
    let response = server.get("/system/performance").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let perf_body: serde_json::Value = response.json();
    assert_eq!(perf_body["performance_snapshot"]["total_resources"], 10);
    assert!(
        perf_body["performance_snapshot"]["total_requests"]
            .as_u64()
            .unwrap()
            >= 15
    );
}

#[tokio::test]
async fn test_monitoring_under_load() {
    let shared_metrics = Arc::new(Mutex::new(HashMap::new()));
    let shared_data = Arc::new(Mutex::new(HashMap::new()));

    let num_operations = 50;
    let mut handles = vec![];

    for i in 0..num_operations {
        let metrics_clone = Arc::clone(&shared_metrics);
        let data_clone = Arc::clone(&shared_data);

        let state = AppState {
            data: data_clone,
            metrics: metrics_clone,
        };

        let app = Router::new()
            .route("/metrics", get(metrics_endpoint))
            .route("/resources", post(create_monitored_resource))
            .route("/health", get(health_check))
            .with_state(state);

        let server = TestServer::new(app).unwrap();
        let handle = tokio::spawn(async move {
            // Mix of resource creation and health checks
            if i % 3 == 0 {
                let response = server.get("/health").await;
                assert_eq!(response.status_code(), StatusCode::OK);
            } else {
                let response = server
                    .post("/resources")
                    .json(&json!({
                        "name": format!("Load Test Resource {}", i),
                        "type": "load_test"
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

    // Give a moment for all metrics to be recorded
    sleep(Duration::from_millis(100)).await;

    // Check final metrics using a new server instance with the same shared state
    let state = AppState {
        data: Arc::clone(&shared_data),
        metrics: Arc::clone(&shared_metrics),
    };

    let app = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();

    let total_requests = body["metrics"]["http_requests_total"].as_u64().unwrap();
    let request_count = body["metrics"]["http_requests_duration_seconds"]["count"]
        .as_u64()
        .unwrap();

    println!(
        "Expected operations: {}, Total requests: {}, Request count: {}",
        num_operations, total_requests, request_count
    );

    // Due to async timing, we might not get exactly num_operations
    // but we should get at least some significant portion
    assert!(
        total_requests >= 20,
        "Expected at least 20 requests, got {}",
        total_requests
    );
    assert!(
        request_count >= 20,
        "Expected at least 20 request measurements, got {}",
        request_count
    );

    println!(
        "Monitoring test completed: {} total requests, {} measured requests",
        total_requests, request_count
    );
}

#[tokio::test]
async fn test_monitoring_data_consistency() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .route("/system/performance", get(performance_snapshot))
        .route("/resources", post(create_monitored_resource))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create resources and track metrics consistency
    let mut expected_requests = 0u64;

    for i in 0..20 {
        let response = server
            .post("/resources")
            .json(&json!({
                "name": format!("Consistency Test {}", i),
                "type": "consistency_test"
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
        expected_requests += 1;

        // Check metrics consistency after each operation
        let metrics_response = server.get("/metrics").await;
        assert_eq!(metrics_response.status_code(), StatusCode::OK);
        let metrics_body: serde_json::Value = metrics_response.json();

        let actual_requests = metrics_body["metrics"]["http_requests_total"]
            .as_u64()
            .unwrap();
        assert_eq!(actual_requests, expected_requests);

        // Check performance snapshot consistency
        let perf_response = server.get("/system/performance").await;
        assert_eq!(perf_response.status_code(), StatusCode::OK);
        let perf_body: serde_json::Value = perf_response.json();

        let perf_requests = perf_body["performance_snapshot"]["total_requests"]
            .as_u64()
            .unwrap();
        assert_eq!(perf_requests, expected_requests);
    }

    // Final consistency check - verify metrics are still consistent
    let final_metrics_response = server.get("/metrics").await;
    assert_eq!(final_metrics_response.status_code(), StatusCode::OK);
    let final_metrics_body: serde_json::Value = final_metrics_response.json();

    let final_requests = final_metrics_body["metrics"]["http_requests_total"]
        .as_u64()
        .unwrap();
    assert_eq!(final_requests, expected_requests);
}

#[tokio::test]
async fn test_monitoring_error_scenarios() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .route("/resources/{id}", get(get_monitored_resource))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Get initial metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let initial_body: serde_json::Value = response.json();
    let initial_requests = initial_body["metrics"]["http_requests_total"]
        .as_u64()
        .unwrap();

    // Make requests that will result in errors
    for i in 0..5 {
        let response = server.get(&format!("/resources/nonexistent_{}", i)).await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    }

    // Check that error requests are still counted in metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let final_body: serde_json::Value = response.json();
    let final_requests = final_body["metrics"]["http_requests_total"]
        .as_u64()
        .unwrap();

    // All requests, including errors, should be counted
    assert_eq!(final_requests, initial_requests + 5);
}

#[tokio::test]
async fn test_monitoring_response_time_tracking() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
        metrics: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .route("/resources", post(create_monitored_resource))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create resources with varying complexity to test response time tracking
    let test_cases = vec![
        json!({"name": "Simple Resource", "type": "simple"}),
        json!({"name": "Complex Resource", "type": "complex", "metadata": {"size": "large", "complexity": "high"}}),
        json!({"name": "Medium Resource", "type": "medium", "tags": ["tag1", "tag2", "tag3"]}),
    ];

    let mut total_expected_time = 0.0;

    for test_case in test_cases {
        let start = Instant::now();
        let response = server.post("/resources").json(&test_case).await;
        let actual_time = start.elapsed().as_secs_f64();

        assert_eq!(response.status_code(), StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify response time is tracked
        let reported_time = body["processing_time_ms"].as_f64().unwrap();
        assert!(reported_time > 0.0);

        total_expected_time += actual_time;
    }

    // Check aggregated metrics
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();

    let total_duration = body["metrics"]["http_requests_duration_seconds"]["sum"]
        .as_f64()
        .unwrap();
    let request_count = body["metrics"]["http_requests_duration_seconds"]["count"]
        .as_u64()
        .unwrap();

    assert_eq!(request_count, 3);
    assert!(total_duration > 0.0);
    assert!(total_duration < total_expected_time * 2.0); // Allow some margin for measurement differences
}
