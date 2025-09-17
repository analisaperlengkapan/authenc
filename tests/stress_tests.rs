use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, Method, Request, StatusCode},
    middleware,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration, Instant};
use uuid::Uuid;

// Shared test state for stress tests
type SharedState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

#[derive(Clone)]
struct AppState {
    data: SharedState,
}

// Stress test handlers
async fn create_resource(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();
    let resource_id = Uuid::new_v4().to_string();

    let mut resource = payload.clone();
    resource["id"] = json!(resource_id);
    resource["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    resource["version"] = json!(1);

    data.insert(resource_id.clone(), resource.clone());

    Ok(Json(json!({
        "success": true,
        "resource": resource
    })))
}

async fn get_resource(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let data = state.data.lock().unwrap();

    if let Some(resource) = data.get(&resource_id) {
        Ok(Json(json!({
            "success": true,
            "resource": resource
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn update_resource(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    if let Some(resource) = data.get_mut(&resource_id) {
        // Update fields
        if let Some(name) = payload.get("name") {
            resource["name"] = name.clone();
        }
        if let Some(description) = payload.get("description") {
            resource["description"] = description.clone();
        }

        // Increment version
        let current_version = resource["version"].as_u64().unwrap_or(1);
        resource["version"] = json!(current_version + 1);
        resource["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

        Ok(Json(json!({
            "success": true,
            "resource": resource
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn delete_resource(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    if data.remove(&resource_id).is_some() {
        Ok(Json(json!({
            "success": true,
            "message": "Resource deleted successfully"
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn list_resources(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let data = state.data.lock().unwrap();
    let mut resources: Vec<&serde_json::Value> = data.values().collect();

    // Apply filters
    if let Some(status_filter) = params.get("status") {
        resources = resources
            .into_iter()
            .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some(status_filter))
            .collect();
    }

    // Apply sorting (simple by creation time)
    resources.sort_by(|a, b| {
        let a_time = a.get("created_at").and_then(|t| t.as_str()).unwrap_or("");
        let b_time = b.get("created_at").and_then(|t| t.as_str()).unwrap_or("");
        b_time.cmp(a_time) // Reverse chronological
    });

    // Apply pagination
    let page = params
        .get("page")
        .and_then(|p| p.parse::<usize>().ok())
        .unwrap_or(1);
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(50);
    let offset = (page - 1) * limit;

    let total = resources.len();
    resources = resources.into_iter().skip(offset).take(limit).collect();

    Json(json!({
        "success": true,
        "resources": resources,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) / limit
        }
    }))
}

async fn bulk_create_resources(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    if let Some(resources) = payload.get("resources").and_then(|r| r.as_array()) {
        let mut created_resources = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for (index, resource_payload) in resources.iter().enumerate() {
            let resource_id = Uuid::new_v4().to_string();

            let mut resource = resource_payload.clone();
            resource["id"] = json!(resource_id);
            resource["created_at"] = json!(chrono::Utc::now().to_rfc3339());
            resource["version"] = json!(1);

            data.insert(resource_id.clone(), resource.clone());
            created_resources.push(resource);
        }

        Ok(Json(json!({
            "success": true,
            "created": created_resources.len(),
            "resources": created_resources
        })))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn resource_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.data.lock().unwrap();

    let total_resources = data.len();
    let active_resources = data
        .values()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("active"))
        .count();
    let inactive_resources = data
        .values()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("inactive"))
        .count();

    let avg_version = if total_resources > 0 {
        data.values()
            .map(|r| r.get("version").and_then(|v| v.as_u64()).unwrap_or(1))
            .sum::<u64>() as f64
            / total_resources as f64
    } else {
        0.0
    };

    Json(json!({
        "success": true,
        "stats": {
            "total_resources": total_resources,
            "active_resources": active_resources,
            "inactive_resources": inactive_resources,
            "average_version": avg_version
        }
    }))
}

async fn simulate_slow_operation(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // Simulate variable response times
    let delay_ms = params
        .get("delay")
        .and_then(|d| d.parse::<u64>().ok())
        .unwrap_or(100);

    sleep(Duration::from_millis(delay_ms)).await;

    Json(json!({
        "success": true,
        "message": "Operation completed",
        "delay_ms": delay_ms,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn simulate_failure(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let should_fail = params
        .get("fail")
        .and_then(|f| f.parse::<bool>().ok())
        .unwrap_or(false);

    if should_fail {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(json!({
        "success": true,
        "message": "Operation succeeded"
    })))
}

async fn memory_intensive_operation(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut large_data = Vec::new();

    // Simulate memory-intensive operation
    for i in 0..10000 {
        large_data.push(json!({
            "id": i,
            "data": format!("Large data item {}", i),
            "timestamp": chrono::Utc::now().to_rfc3339()
        }));
    }

    // Process the data (simulate CPU work)
    let processed_count = large_data.len();
    let total_size = large_data
        .iter()
        .map(|item| item.to_string().len())
        .sum::<usize>();

    Json(json!({
        "success": true,
        "processed_items": processed_count,
        "total_size_bytes": total_size,
        "average_item_size": total_size as f64 / processed_count as f64
    }))
}

#[tokio::test]
async fn test_high_concurrency_resource_operations() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/resources", post(create_resource).get(list_resources))
        .route(
            "/resources/{id}",
            get(get_resource)
                .put(update_resource)
                .delete(delete_resource),
        )
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Test with 100 concurrent operations
    let num_operations = 100;
    let mut handles = vec![];

    let start_time = Instant::now();

    for i in 0..num_operations {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            // Create resource
            let create_response = server_clone
                .post("/resources")
                .json(&json!({
                    "name": format!("Concurrent Resource {}", i),
                    "description": format!("Description for resource {}", i),
                    "status": "active"
                }))
                .await;

            assert_eq!(create_response.status_code(), StatusCode::OK);
            let resource_id = create_response.json::<serde_json::Value>()["resource"]["id"]
                .as_str()
                .unwrap()
                .to_string();

            // Immediately read the resource
            let get_response = server_clone
                .get(&format!("/resources/{}", resource_id))
                .await;

            assert_eq!(get_response.status_code(), StatusCode::OK);

            // Update the resource
            let update_response = server_clone
                .put(&format!("/resources/{}", resource_id))
                .json(&json!({
                    "name": format!("Updated Concurrent Resource {}", i)
                }))
                .await;

            assert_eq!(update_response.status_code(), StatusCode::OK);

            resource_id
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    let mut resource_ids = vec![];
    for handle in handles {
        resource_ids.push(handle.await.unwrap());
    }

    let duration = start_time.elapsed();
    println!(
        "Completed {} concurrent operations in {:?}",
        num_operations, duration
    );

    // Verify all resources were created
    assert_eq!(resource_ids.len(), num_operations);

    // Verify all resources can still be retrieved
    for resource_id in resource_ids.iter().take(10) {
        // Check first 10
        let response = server.get(&format!("/resources/{}", resource_id)).await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Check final stats
    let response = server.get("/resources?limit=1000").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), num_operations);
}

#[tokio::test]
async fn test_bulk_operations_under_load() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/resources/bulk", post(bulk_create_resources))
        .route("/resources", get(list_resources))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Test bulk creation with large datasets
    let mut bulk_data = Vec::new();
    for i in 0..500 {
        bulk_data.push(json!({
            "name": format!("Bulk Resource {}", i),
            "description": format!("Bulk description {}", i),
            "status": if i % 2 == 0 { "active" } else { "inactive" },
            "category": format!("category_{}", i % 10)
        }));
    }

    let start_time = Instant::now();

    let response = server
        .post("/resources/bulk")
        .json(&json!({
            "resources": bulk_data
        }))
        .await;

    let duration = start_time.elapsed();
    println!("Bulk created 500 resources in {:?}", duration);

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["created"], 500);

    // Test filtering and pagination under load
    let response = server.get("/resources?status=active&page=1&limit=50").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), 50);
    assert_eq!(body["pagination"]["total"], 250); // Half should be active
}

#[tokio::test]
async fn test_memory_and_cpu_stress() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/stress/memory", get(memory_intensive_operation))
        .route("/stress/cpu", get(simulate_slow_operation))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Test memory-intensive operations
    let mut memory_handles = vec![];

    for i in 0..10 {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let response = server_clone.get("/stress/memory").await;
            let duration = start.elapsed();

            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            assert_eq!(body["processed_items"], 10000);

            duration
        });
        memory_handles.push(handle);
    }

    // Wait for memory operations
    for handle in memory_handles {
        let duration = handle.await.unwrap();
        println!("Memory operation completed in {:?}", duration);
    }

    // Test CPU-intensive operations with different delays
    let cpu_delays = vec![50, 100, 200, 500, 1000];
    let mut cpu_handles = vec![];

    for delay in cpu_delays {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let response = server_clone
                .get(&format!("/stress/cpu?delay={}", delay))
                .await;
            let actual_duration = start.elapsed();

            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            assert_eq!(body["delay_ms"], delay);

            // Allow some tolerance for timing
            assert!(actual_duration >= Duration::from_millis(delay));
            assert!(actual_duration < Duration::from_millis(delay + 100));

            actual_duration
        });
        cpu_handles.push(handle);
    }

    // Wait for CPU operations
    for handle in cpu_handles {
        let duration = handle.await.unwrap();
        println!("CPU operation completed in {:?}", duration);
    }
}

#[tokio::test]
async fn test_failure_recovery_and_resilience() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/unstable", get(simulate_failure))
        .route("/resources", post(create_resource).get(list_resources))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Test failure scenarios
    let failure_scenarios = vec![
        (true, StatusCode::INTERNAL_SERVER_ERROR),
        (false, StatusCode::OK),
        (true, StatusCode::INTERNAL_SERVER_ERROR),
        (false, StatusCode::OK),
    ];

    for (should_fail, expected_status) in failure_scenarios {
        let response = server.get(&format!("/unstable?fail={}", should_fail)).await;

        assert_eq!(response.status_code(), expected_status);
    }

    // Test that system remains functional after failures
    for i in 0..5 {
        let response = server
            .post("/resources")
            .json(&json!({
                "name": format!("Recovery Test Resource {}", i),
                "status": "active"
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Verify resources were created despite previous failures
    let response = server.get("/resources").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_resource_versioning_and_conflict_resolution() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/resources", post(create_resource))
        .route("/resources/{id}", get(get_resource).put(update_resource))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Create initial resource
    let response = server
        .post("/resources")
        .json(&json!({
            "name": "Version Test Resource",
            "description": "Initial description",
            "status": "active"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let json_response = response.json::<serde_json::Value>();
    let resource_id = json_response["resource"]["id"].as_str().unwrap();

    // Verify initial version
    let response = server.get(&format!("/resources/{}", resource_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resource"]["version"], 1);

    // Update resource multiple times
    for i in 1..=5 {
        let response = server
            .put(&format!("/resources/{}", resource_id))
            .json(&json!({
                "name": format!("Version Test Resource v{}", i + 1),
                "description": format!("Updated description v{}", i + 1)
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["resource"]["version"], i + 1);
    }

    // Verify final version
    let response = server.get(&format!("/resources/{}", resource_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resource"]["version"], 6);
    assert_eq!(body["resource"]["name"], "Version Test Resource v6");
}

#[tokio::test]
async fn test_data_consistency_under_extreme_load() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/resources", post(create_resource).get(list_resources))
        .route("/resources/stats", get(resource_stats))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Create resources with extreme concurrency
    let num_resources = 1000;
    let mut handles = vec![];

    let start_time = Instant::now();

    for i in 0..num_resources {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            let response = server_clone
                .post("/resources")
                .json(&json!({
                    "name": format!("Stress Resource {}", i),
                    "description": format!("Stress test resource {}", i),
                    "status": if i % 3 == 0 { "active" } else if i % 3 == 1 { "inactive" } else { "pending" }
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
        });
        handles.push(handle);
    }

    // Wait for all creations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let creation_duration = start_time.elapsed();
    println!(
        "Created {} resources in {:?}",
        num_resources, creation_duration
    );

    // Verify data consistency
    let response = server.get("/resources?limit=2000").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), num_resources);

    // Check statistics
    let response = server.get("/resources/stats").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["stats"]["total_resources"], num_resources);
    assert_eq!(body["stats"]["active_resources"], 334); // 1000 / 3 = 333.333, so 334 active
    assert_eq!(body["stats"]["inactive_resources"], 333);
}

#[tokio::test]
async fn test_rate_limiting_under_load() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/resources", post(create_resource).get(list_resources))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Simulate rapid requests (in a real app, rate limiting would kick in)
    let num_requests = 200;
    let mut handles = vec![];

    let start_time = Instant::now();

    for i in 0..num_requests {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            let response = server_clone
                .post("/resources")
                .json(&json!({
                    "name": format!("Rate Limit Test {}", i),
                    "status": "active"
                }))
                .await;

            // In a real rate-limited system, some requests would be rejected
            // For this test, we expect all to succeed since there's no rate limiting
            assert_eq!(response.status_code(), StatusCode::OK);
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let duration = start_time.elapsed();
    println!("Processed {} requests in {:?}", num_requests, duration);

    // Verify all resources were created
    let response = server.get("/resources?limit=1000").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), num_requests);
}

#[tokio::test]
async fn test_long_running_operations_and_timeouts() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/slow", get(simulate_slow_operation))
        .route("/resources", post(create_resource).get(list_resources))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Test various operation durations
    let test_delays = vec![100, 500, 1000, 2000, 5000];

    for delay in test_delays {
        let start = Instant::now();
        let response = server.get(&format!("/slow?delay={}", delay)).await;
        let actual_duration = start.elapsed();

        assert_eq!(response.status_code(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["delay_ms"], delay);

        // Verify the operation took at least the expected time
        assert!(actual_duration >= Duration::from_millis(delay));
        println!(
            "Operation with {}ms delay took {:?}",
            delay, actual_duration
        );
    }

    // Test that system remains responsive during long operations
    let mut concurrent_handles = vec![];

    // Start a long-running operation
    let app_clone = app.clone();
    let long_op_handle = tokio::spawn(async move {
        let server_clone = TestServer::new(app_clone).unwrap();
        let response = server_clone.get("/slow?delay=3000").await;
        assert_eq!(response.status_code(), StatusCode::OK);
    });

    // Start multiple short operations concurrently
    for i in 0..5 {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            let response = server_clone
                .post("/resources")
                .json(&json!({
                    "name": format!("Concurrent Resource {}", i),
                    "status": "active"
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
        });
        concurrent_handles.push(handle);
    }

    // Wait for short operations to complete
    for handle in concurrent_handles {
        handle.await.unwrap();
    }

    // Wait for long operation to complete
    long_op_handle.await.unwrap();

    // Verify all operations succeeded
    let response = server.get("/resources").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_resource_cleanup_and_garbage_collection() {
    let state = AppState {
        data: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/resources", post(create_resource).get(list_resources))
        .route("/resources/{id}", get(get_resource).delete(delete_resource))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Create resources
    let mut resource_ids = vec![];
    for i in 0..50 {
        let response = server
            .post("/resources")
            .json(&json!({
                "name": format!("Cleanup Test Resource {}", i),
                "status": "active"
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let resource_id = response.json::<serde_json::Value>()["resource"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        resource_ids.push(resource_id);
    }

    // Verify all resources exist
    let response = server.get("/resources?limit=1000").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), 50);

    // Delete half of the resources
    for resource_id in resource_ids.iter().take(25) {
        let response = server.delete(&format!("/resources/{}", resource_id)).await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Verify remaining resources
    let response = server.get("/resources?limit=1000").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["resources"].as_array().unwrap().len(), 25);

    // Verify deleted resources are gone
    for resource_id in resource_ids.iter().take(25) {
        let response = server.get(&format!("/resources/{}", resource_id)).await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    }

    // Verify remaining resources still exist
    for resource_id in resource_ids.iter().skip(25) {
        let response = server.get(&format!("/resources/{}", resource_id)).await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
}
