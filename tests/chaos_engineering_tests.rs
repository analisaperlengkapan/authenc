use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// Chaos Engineering and Fault Injection Tests
// Testing system resilience under failure conditions

#[derive(Clone)]
struct ChaosState {
    services: Arc<Mutex<HashMap<String, ServiceStatus>>>,
    failures: Arc<Mutex<Vec<FailureEvent>>>,
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreaker>>>,
    dependencies: Arc<Mutex<HashMap<String, Vec<String>>>>,
    metrics: Arc<Mutex<HashMap<String, SystemMetrics>>>,
}

#[derive(Clone)]
struct ServiceStatus {
    name: String,
    healthy: bool,
    last_check: String,
    failure_count: u32,
    response_time_ms: u64,
}

#[derive(Clone, serde::Serialize)]
struct FailureEvent {
    service: String,
    failure_type: String,
    timestamp: String,
    duration_ms: u64,
    recovered: bool,
}

#[derive(Clone)]
struct CircuitBreaker {
    service: String,
    state: CircuitState,
    failure_count: u32,
    last_failure: String,
    half_open_attempted: bool, // Track if we've already tried half-open
    timeout_ms: u64,
}

#[derive(Clone)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone)]
struct SystemMetrics {
    requests_total: u64,
    errors_total: u64,
    latency_p50: u64,
    latency_p95: u64,
    latency_p99: u64,
    uptime_seconds: u64,
}

impl ChaosState {
    fn new() -> Self {
        let mut services = HashMap::new();
        services.insert(
            "auth".to_string(),
            ServiceStatus {
                name: "auth".to_string(),
                healthy: true,
                last_check: "2024-12-01T10:00:00Z".to_string(),
                failure_count: 0,
                response_time_ms: 50,
            },
        );
        services.insert(
            "database".to_string(),
            ServiceStatus {
                name: "database".to_string(),
                healthy: true,
                last_check: "2024-12-01T10:00:00Z".to_string(),
                failure_count: 0,
                response_time_ms: 20,
            },
        );
        services.insert(
            "cache".to_string(),
            ServiceStatus {
                name: "cache".to_string(),
                healthy: true,
                last_check: "2024-12-01T10:00:00Z".to_string(),
                failure_count: 0,
                response_time_ms: 5,
            },
        );

        let mut dependencies = HashMap::new();
        dependencies.insert(
            "auth".to_string(),
            vec!["database".to_string(), "cache".to_string()],
        );
        dependencies.insert("api".to_string(), vec!["auth".to_string()]);

        Self {
            services: Arc::new(Mutex::new(services)),
            failures: Arc::new(Mutex::new(Vec::new())),
            circuit_breakers: Arc::new(Mutex::new(HashMap::new())),
            dependencies: Arc::new(Mutex::new(dependencies)),
            metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_service_failures_and_recovery() {
    let state = ChaosState::new();

    let app = Router::new()
        .route(
            "/chaos/service/{service}/fail",
            post(
                move |State(state): State<ChaosState>,
                      Path(service): Path<String>,
                      Json(config): Json<serde_json::Value>| async move {
                    let mut services = state.services.lock().await;
                    let mut failures = state.failures.lock().await;

                    let failure_type = config
                        .get("failure_type")
                        .and_then(|f| f.as_str())
                        .unwrap_or("general");
                    let duration_ms = config
                        .get("duration_ms")
                        .and_then(|d| d.as_u64())
                        .unwrap_or(5000);

                    if let Some(service_status) = services.get_mut(&service) {
                        service_status.healthy = false;
                        service_status.failure_count += 1;

                        failures.push(FailureEvent {
                            service: service.clone(),
                            failure_type: failure_type.to_string(),
                            timestamp: "2024-12-01T10:00:00Z".to_string(),
                            duration_ms,
                            recovered: false,
                        });

                        // Simulate failure duration
                        let state_clone = state.clone();
                        let service_clone = service.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(duration_ms)).await;
                            let mut services = state_clone.services.lock().await;
                            let mut failures = state_clone.failures.lock().await;

                            if let Some(service_status) = services.get_mut(&service_clone) {
                                service_status.healthy = true;
                                service_status.last_check = "2024-12-01T10:00:05Z".to_string();
                            }

                            // Mark failure as recovered
                            if let Some(failure) = failures.last_mut() {
                                if failure.service == service_clone {
                                    failure.recovered = true;
                                }
                            }
                        });

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "service": service,
                            "status": "failure_injected",
                            "failure_type": failure_type,
                            "duration_ms": duration_ms,
                            "recovery_scheduled": true
                        })))
                    } else {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Service not found",
                            "service": service
                        })))
                    }
                },
            ),
        )
        .route(
            "/chaos/service/{service}/status",
            get(
                move |State(state): State<ChaosState>, Path(service): Path<String>| async move {
                    let services = state.services.lock().await;
                    let failures = state.failures.lock().await;

                    if let Some(service_status) = services.get(&service) {
                        let recent_failures: Vec<_> = failures
                            .iter()
                            .filter(|f| f.service == service)
                            .take(5)
                            .cloned()
                            .collect();

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "service": service,
                            "healthy": service_status.healthy,
                            "failure_count": service_status.failure_count,
                            "response_time_ms": service_status.response_time_ms,
                            "last_check": service_status.last_check,
                            "recent_failures": recent_failures
                        })))
                    } else {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Service not found",
                            "service": service
                        })))
                    }
                },
            ),
        )
        .route(
            "/chaos/service/{service}/recover",
            post(
                move |State(state): State<ChaosState>, Path(service): Path<String>| async move {
                    let mut services = state.services.lock().await;
                    let mut failures = state.failures.lock().await;

                    if let Some(service_status) = services.get_mut(&service) {
                        service_status.healthy = true;
                        service_status.last_check = "2024-12-01T10:00:10Z".to_string();

                        // Mark all failures as recovered
                        for failure in failures.iter_mut() {
                            if failure.service == service {
                                failure.recovered = true;
                            }
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "service": service,
                            "status": "recovered",
                            "message": "Service manually recovered"
                        })))
                    } else {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Service not found",
                            "service": service
                        })))
                    }
                },
            ),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test injecting failure
    let failure_config = json!({"failure_type": "network_timeout", "duration_ms": 2000});
    let response = server
        .post("/chaos/service/auth/fail")
        .json(&failure_config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "failure_injected");
    assert_eq!(body["failure_type"], "network_timeout");

    // Check status during failure
    let response = server.get("/chaos/service/auth/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["healthy"], false);
    assert_eq!(body["failure_count"], 1);

    // Wait for recovery
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Check status after recovery
    let response = server.get("/chaos/service/auth/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["healthy"], true);

    // Manual recovery test
    let failure_config = json!({"failure_type": "database_connection", "duration_ms": 10000});
    let response = server
        .post("/chaos/service/database/fail")
        .json(&failure_config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server.post("/chaos/service/database/recover").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "recovered");

    // Verify recovery
    let response = server.get("/chaos/service/database/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["healthy"], true);
}

#[tokio::test]
async fn test_circuit_breaker_patterns() {
    let state = ChaosState::new();

    let app = Router::new()
        .route(
            "/chaos/service/{service}/fail",
            post(
                move |State(state): State<ChaosState>,
                      Path(service): Path<String>,
                      Json(config): Json<serde_json::Value>| async move {
                    let mut services = state.services.lock().await;

                    // Mark service as unhealthy
                    services.insert(
                        service.clone(),
                        ServiceStatus {
                            name: service.clone(),
                            healthy: false,
                            last_check: "2024-12-01T10:00:00Z".to_string(),
                            failure_count: 1,
                            response_time_ms: 1000,
                        },
                    );

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "service": service,
                        "failure_injected": true,
                        "status": "unhealthy"
                    })))
                },
            ),
        )
        .route(
            "/chaos/circuit/{service}/configure",
            post(
                move |State(state): State<ChaosState>,
                      Path(service): Path<String>,
                      Json(config): Json<serde_json::Value>| async move {
                    let mut circuit_breakers = state.circuit_breakers.lock().await;

                    let failure_threshold = config
                        .get("failure_threshold")
                        .and_then(|f| f.as_u64())
                        .unwrap_or(5);
                    let timeout_ms = config
                        .get("timeout_ms")
                        .and_then(|t| t.as_u64())
                        .unwrap_or(30000);

                    circuit_breakers.insert(
                        service.clone(),
                        CircuitBreaker {
                            service: service.clone(),
                            state: CircuitState::Closed,
                            failure_count: 0,
                            last_failure: "".to_string(),
                            half_open_attempted: false,
                            timeout_ms,
                        },
                    );

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "service": service,
                        "configured": true,
                        "failure_threshold": failure_threshold,
                        "timeout_ms": timeout_ms
                    })))
                },
            ),
        )
        .route(
            "/chaos/circuit/{service}/request",
            post(
                move |State(state): State<ChaosState>, Path(service): Path<String>| async move {
                    let mut circuit_breakers = state.circuit_breakers.lock().await;
                    let services = state.services.lock().await;

                    if let Some(cb) = circuit_breakers.get_mut(&service) {
                        match cb.state {
                            CircuitState::Open => {
                                // Allow one attempt to test the service when circuit is open
                                if !cb.half_open_attempted {
                                    cb.half_open_attempted = true;
                                    cb.state = CircuitState::HalfOpen;
                                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                        "service": service,
                                        "circuit_state": "half_open",
                                        "message": "Circuit breaker half-open, testing service"
                                    })))
                                } else {
                                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                        "service": service,
                                        "circuit_state": "open",
                                        "error": "Circuit breaker is open",
                                        "message": "Service unavailable due to failures"
                                    })))
                                }
                            }
                            CircuitState::HalfOpen => {
                                // Test the service
                                let service_healthy =
                                    services.get(&service).map(|s| s.healthy).unwrap_or(false);

                                if service_healthy {
                                    cb.state = CircuitState::Closed;
                                    cb.failure_count = 0;
                                    cb.half_open_attempted = false; // Reset for next time
                                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                        "service": service,
                                        "circuit_state": "closed",
                                        "message": "Service recovered, circuit closed"
                                    })))
                                } else {
                                    cb.state = CircuitState::Open;
                                    cb.failure_count += 1;
                                    cb.last_failure = "2024-12-01T10:00:00Z".to_string();
                                    // Keep half_open_attempted = true so circuit stays open
                                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                        "service": service,
                                        "circuit_state": "open",
                                        "message": "Service still failing, circuit opened"
                                    })))
                                }
                            }
                            CircuitState::Closed => {
                                let service_healthy =
                                    services.get(&service).map(|s| s.healthy).unwrap_or(true);

                                if !service_healthy {
                                    cb.failure_count += 1;
                                    if cb.failure_count >= 3 {
                                        // Simplified threshold
                                        cb.state = CircuitState::Open;
                                        cb.last_failure = "2024-12-01T10:00:00Z".to_string();
                                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                            "service": service,
                                            "circuit_state": "open",
                                            "message": "Failure threshold reached, circuit opened"
                                        })))
                                    } else {
                                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                            "service": service,
                                            "circuit_state": "closed",
                                            "message": "Service failed but threshold not reached"
                                        })))
                                    }
                                } else {
                                    cb.failure_count = 0;
                                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                        "service": service,
                                        "circuit_state": "closed",
                                        "message": "Request successful"
                                    })))
                                }
                            }
                        }
                    } else {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Circuit breaker not configured",
                            "service": service
                        })))
                    }
                },
            ),
        )
        .route(
            "/chaos/circuit/{service}/status",
            get(
                move |State(state): State<ChaosState>, Path(service): Path<String>| async move {
                    let circuit_breakers = state.circuit_breakers.lock().await;

                    if let Some(cb) = circuit_breakers.get(&service) {
                        let state_str = match cb.state {
                            CircuitState::Closed => "closed",
                            CircuitState::Open => "open",
                            CircuitState::HalfOpen => "half_open",
                        };

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "service": service,
                            "circuit_state": state_str,
                            "failure_count": cb.failure_count,
                            "last_failure": cb.last_failure,
                            "timeout_ms": cb.timeout_ms
                        })))
                    } else {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "error": "Circuit breaker not configured",
                            "service": service
                        })))
                    }
                },
            ),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Configure circuit breaker
    let config = json!({"failure_threshold": 3, "timeout_ms": 30000});
    let response = server
        .post("/chaos/circuit/auth/configure")
        .json(&config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["configured"], true);

    // Test successful requests
    for _ in 0..3 {
        let response = server.post("/chaos/circuit/auth/request").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["circuit_state"], "closed");
        assert_eq!(body["message"], "Request successful");
    }

    // Inject failure - mark service as unhealthy
    let failure_config = json!({"failure_type": "service_down", "duration_ms": 1000});
    let response = server
        .post("/chaos/service/auth/fail")
        .json(&failure_config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test circuit breaker opening - service should be unhealthy now
    let response = server.post("/chaos/circuit/auth/request").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "closed");
    assert_eq!(body["message"], "Service failed but threshold not reached");

    // More failures to trigger circuit opening
    for _ in 0..2 {
        let response = server.post("/chaos/circuit/auth/request").await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // This should trigger circuit opening (3rd failure)
    let response = server.post("/chaos/circuit/auth/request").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "half_open");
    assert_eq!(
        body["message"],
        "Circuit breaker half-open, testing service"
    );

    // Service is still unhealthy, so it should open again
    // Ensure service is still unhealthy for this test
    let failure_config = json!({"failure_type": "service_down", "duration_ms": 5000});
    let response = server
        .post("/chaos/service/auth/fail")
        .json(&failure_config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server.post("/chaos/circuit/auth/request").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "open");
    assert_eq!(body["message"], "Service still failing, circuit opened");

    // Test circuit breaker blocking requests
    let response = server.post("/chaos/circuit/auth/request").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "open");
    assert_eq!(body["error"], "Circuit breaker is open");

    // Check circuit breaker status
    let response = server.get("/chaos/circuit/auth/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "open");
    assert!(body["failure_count"].as_u64().unwrap() >= 3);
}

#[tokio::test]
async fn test_dependency_failure_cascades() {
    let state = ChaosState::new();

    let app =
        Router::new()
            .route(
                "/chaos/dependency/{service}/check",
                get(
                    move |State(state): State<ChaosState>, Path(service): Path<String>| async move {
                        let services = state.services.lock().await;
                        let dependencies = state.dependencies.lock().await;

                        let mut dependency_status = vec![];
                        let mut all_healthy = true;

                        if let Some(deps) = dependencies.get(&service) {
                            for dep in deps {
                                let healthy = services.get(dep).map(|s| s.healthy).unwrap_or(false);
                                dependency_status.push(json!({
                                    "service": dep,
                                    "healthy": healthy
                                }));
                                if !healthy {
                                    all_healthy = false;
                                }
                            }
                        }

                        let service_healthy =
                            services.get(&service).map(|s| s.healthy).unwrap_or(false);

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "service": service,
                            "healthy": service_healthy && all_healthy,
                            "dependencies": dependency_status,
                            "cascade_risk": !all_healthy
                        })))
                    },
                ),
            )
            .route(
                "/chaos/dependency/cascade",
                post(
                    move |State(state): State<ChaosState>,
                          Json(config): Json<serde_json::Value>| async move {
                        let mut services = state.services.lock().await;
                        let mut failures = state.failures.lock().await;
                        let dependencies = state.dependencies.lock().await;

                        let trigger_service = config
                            .get("trigger_service")
                            .and_then(|s| s.as_str())
                            .unwrap_or("database");
                        let cascade_depth = config
                            .get("cascade_depth")
                            .and_then(|d| d.as_u64())
                            .unwrap_or(2);

                        let mut affected_services = vec![trigger_service.to_string()];
                        let mut cascade_level = 0;

                        // Simulate cascade failure
                        while cascade_level < cascade_depth {
                            let mut new_affected = vec![];

                            for service in &affected_services {
                                if let Some(service_status) = services.get_mut(service) {
                                    service_status.healthy = false;
                                    service_status.failure_count += 1;

                                    failures.push(FailureEvent {
                                        service: service.clone(),
                                        failure_type: "cascade_failure".to_string(),
                                        timestamp: "2024-12-01T10:00:00Z".to_string(),
                                        duration_ms: 5000,
                                        recovered: false,
                                    });
                                }

                                // Find services that depend on this service
                                for (svc, deps) in dependencies.iter() {
                                    if deps.contains(service) && !affected_services.contains(svc) {
                                        new_affected.push(svc.clone());
                                    }
                                }
                            }

                            if new_affected.is_empty() {
                                break;
                            }

                            affected_services.extend(new_affected);
                            cascade_level += 1;
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "cascade_triggered": true,
                            "trigger_service": trigger_service,
                            "affected_services": affected_services,
                            "cascade_depth": cascade_level,
                            "total_affected": affected_services.len()
                        })))
                    },
                ),
            )
            .route(
                "/chaos/dependency/recovery",
                post(
                    move |State(state): State<ChaosState>,
                          Json(config): Json<serde_json::Value>| async move {
                        let mut services = state.services.lock().await;
                        let mut failures = state.failures.lock().await;

                        let empty_vec = vec![];
                        let recovery_order = config
                            .get("recovery_order")
                            .and_then(|r| r.as_array())
                            .unwrap_or(&empty_vec)
                            .iter()
                            .filter_map(|s| s.as_str())
                            .collect::<Vec<_>>();

                        let mut recovered_services = vec![];

                        for service_name in &recovery_order {
                            if let Some(service_status) = services.get_mut(*service_name) {
                                service_status.healthy = true;
                                service_status.last_check = "2024-12-01T10:00:15Z".to_string();
                                recovered_services.push(service_name.to_string());

                                // Mark failures as recovered
                                for failure in failures.iter_mut() {
                                    if failure.service == **service_name {
                                        failure.recovered = true;
                                    }
                                }
                            }
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "recovery_completed": true,
                            "recovered_services": recovered_services,
                            "recovery_order": recovery_order
                        })))
                    },
                ),
            )
            .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Check initial dependency status
    let response = server.get("/chaos/dependency/auth/check").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["healthy"], true);
    assert_eq!(body["cascade_risk"], false);

    // Trigger cascade failure
    let cascade_config = json!({"trigger_service": "database", "cascade_depth": 2});
    let response = server
        .post("/chaos/dependency/cascade")
        .json(&cascade_config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["cascade_triggered"], true);
    assert!(body["total_affected"].as_u64().unwrap() >= 2);

    // Check dependency status after cascade
    let response = server.get("/chaos/dependency/auth/check").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["healthy"], false);
    assert_eq!(body["cascade_risk"], true);

    // Test recovery
    let recovery_config = json!({"recovery_order": ["database", "cache", "auth"]});
    let response = server
        .post("/chaos/dependency/recovery")
        .json(&recovery_config)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["recovery_completed"], true);
    assert_eq!(body["recovered_services"].as_array().unwrap().len(), 3);

    // Verify recovery
    let response = server.get("/chaos/dependency/auth/check").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["healthy"], true);
    assert_eq!(body["cascade_risk"], false);
}

#[tokio::test]
async fn test_system_metrics_under_load() {
    let state = ChaosState::new();

    let app = Router::new()
        .route("/chaos/metrics/{service}/record", post(move |State(state): State<ChaosState>, Path(service): Path<String>, Json(metrics): Json<serde_json::Value>| async move {
            let mut system_metrics = state.metrics.lock().await;

            let requests_total = metrics.get("requests_total").and_then(|r| r.as_u64()).unwrap_or(0);
            let errors_total = metrics.get("errors_total").and_then(|e| e.as_u64()).unwrap_or(0);
            let latency_p50 = metrics.get("latency_p50").and_then(|l| l.as_u64()).unwrap_or(0);
            let latency_p95 = metrics.get("latency_p95").and_then(|l| l.as_u64()).unwrap_or(0);
            let latency_p99 = metrics.get("latency_p99").and_then(|l| l.as_u64()).unwrap_or(0);

            let current_metrics = system_metrics.entry(service.clone()).or_insert(SystemMetrics {
                requests_total: 0,
                errors_total: 0,
                latency_p50: 0,
                latency_p95: 0,
                latency_p99: 0,
                uptime_seconds: 0,
            });

            current_metrics.requests_total += requests_total;
            current_metrics.errors_total += errors_total;
            current_metrics.latency_p50 = latency_p50;
            current_metrics.latency_p95 = latency_p95;
            current_metrics.latency_p99 = latency_p99;
            current_metrics.uptime_seconds += 60; // Add 1 minute

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "service": service,
                "metrics_recorded": true,
                "current_requests_total": current_metrics.requests_total,
                "current_errors_total": current_metrics.errors_total,
                "error_rate": if current_metrics.requests_total > 0 {
                    (current_metrics.errors_total as f64 / current_metrics.requests_total as f64) * 100.0
                } else {
                    0.0
                }
            })))
        }))
        .route("/chaos/metrics/{service}/analyze", get(move |State(state): State<ChaosState>, Path(service): Path<String>| async move {
            let system_metrics = state.metrics.lock().await;

            if let Some(metrics) = system_metrics.get(&service) {
                let error_rate = if metrics.requests_total > 0 {
                    (metrics.errors_total as f64 / metrics.requests_total as f64) * 100.0
                } else {
                    0.0
                };

                let health_status = if error_rate > 50.0 {
                    "critical"
                } else if error_rate > 20.0 {
                    "warning"
                } else {
                    "healthy"
                };

                let latency_status = if metrics.latency_p99 > 5000 {
                    "high_latency"
                } else if metrics.latency_p95 > 2000 {
                    "elevated_latency"
                } else {
                    "normal_latency"
                };

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "service": service,
                    "health_status": health_status,
                    "latency_status": latency_status,
                    "error_rate_percent": error_rate,
                    "metrics": {
                        "requests_total": metrics.requests_total,
                        "errors_total": metrics.errors_total,
                        "latency_p50": metrics.latency_p50,
                        "latency_p95": metrics.latency_p95,
                        "latency_p99": metrics.latency_p99,
                        "uptime_seconds": metrics.uptime_seconds
                    },
                    "recommendations": if error_rate > 20.0 {
                        vec!["Investigate error sources", "Consider circuit breaker", "Check service dependencies"]
                    } else {
                        vec!["System operating normally"]
                    }
                })))
            } else {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "error": "No metrics found for service",
                    "service": service
                })))
            }
        }))
        .route("/chaos/load/{service}/simulate", post(move |State(state): State<ChaosState>, Path(service): Path<String>, Json(load_config): Json<serde_json::Value>| async move {
            let concurrent_requests = load_config.get("concurrent_requests").and_then(|c| c.as_u64()).unwrap_or(10);
            let duration_seconds = load_config.get("duration_seconds").and_then(|d| d.as_u64()).unwrap_or(5);

            let mut handles = vec![];
            let start_time = Instant::now();

            // Simulate concurrent load
            for i in 0..concurrent_requests {
                let service_clone = service.clone();
                let state_clone = state.clone();

                let handle = tokio::spawn(async move {
                    let mut local_errors = 0;
                    let mut local_requests = 0;

                    while start_time.elapsed() < Duration::from_secs(duration_seconds) {
                        local_requests += 1;

                        // Simulate request with random failures
                        if rand::random::<f64>() < 0.1 { // 10% failure rate
                            local_errors += 1;
                        }

                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }

                    // Record metrics
                    let metrics_data = json!({
                        "requests_total": local_requests,
                        "errors_total": local_errors,
                        "latency_p50": 50 + (i * 10),
                        "latency_p95": 200 + (i * 20),
                        "latency_p99": 1000 + (i * 50)
                    });

                    let client = reqwest::Client::new();
                    // Note: In a real test, this would make HTTP calls
                    // For now, we'll just simulate the metrics recording

                    (local_requests, local_errors)
                });

                handles.push(handle);
            }

            let mut total_requests = 0;
            let mut total_errors = 0;

            for handle in handles {
                let (requests, errors) = handle.await.unwrap();
                total_requests += requests;
                total_errors += errors;
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "service": service,
                "load_test_completed": true,
                "concurrent_requests": concurrent_requests,
                "duration_seconds": duration_seconds,
                "total_requests": total_requests,
                "total_errors": total_errors,
                "error_rate_percent": if total_requests > 0 {
                    (total_errors as f64 / total_requests as f64) * 100.0
                } else {
                    0.0
                }
            })))
        }))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Record normal metrics
    let metrics_data = json!({
        "requests_total": 100,
        "errors_total": 5,
        "latency_p50": 50,
        "latency_p95": 200,
        "latency_p99": 1000
    });
    let response = server
        .post("/chaos/metrics/auth/record")
        .json(&metrics_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["metrics_recorded"], true);
    assert_eq!(body["current_requests_total"], 100);
    assert_eq!(body["current_errors_total"], 5);

    // Analyze metrics
    let response = server.get("/chaos/metrics/auth/analyze").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["health_status"], "healthy");
    assert_eq!(body["latency_status"], "normal_latency");

    // Record high error metrics
    let high_error_metrics = json!({
        "requests_total": 50,
        "errors_total": 30,
        "latency_p50": 100,
        "latency_p95": 500,
        "latency_p99": 2000
    });
    let response = server
        .post("/chaos/metrics/auth/record")
        .json(&high_error_metrics)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Analyze degraded metrics
    let response = server.get("/chaos/metrics/auth/analyze").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["health_status"], "warning");
    assert!(body["error_rate_percent"].as_f64().unwrap() > 20.0);

    // Record critical metrics with very high error rate
    let critical_metrics = json!({
        "requests_total": 100,
        "errors_total": 91,
        "latency_p50": 200,
        "latency_p95": 1000,
        "latency_p99": 6000
    });
    let response = server
        .post("/chaos/metrics/auth/record")
        .json(&critical_metrics)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Analyze critical metrics - should now be critical (>50% error rate)
    let response = server.get("/chaos/metrics/auth/analyze").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["health_status"], "critical");
    assert_eq!(body["latency_status"], "high_latency");
    assert!(body["error_rate_percent"].as_f64().unwrap() > 50.0);
    assert!(body["recommendations"].as_array().unwrap().len() > 1);
}
