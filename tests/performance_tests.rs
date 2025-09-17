// Performance and load testing for Authence
// Tests for performance benchmarks, load handling, and stress testing

use axum::{
    extract::{Json, Path, Query},
    http::StatusCode,
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;

#[tokio::test]
async fn test_response_time_performance() {
    // Test API response time performance
    let app = Router::new()
        .route(
            "/api/v1/fast",
            axum::routing::get(|| async move { Json(json!({"message": "fast response"})) }),
        )
        .route(
            "/api/v1/medium",
            axum::routing::get(|| async move {
                sleep(Duration::from_millis(50)).await;
                Json(json!({"message": "medium response"}))
            }),
        )
        .route(
            "/api/v1/slow",
            axum::routing::get(|| async move {
                sleep(Duration::from_millis(200)).await;
                Json(json!({"message": "slow response"}))
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test fast endpoint performance
    let start = Instant::now();
    let response = server.get("/api/v1/fast").await;
    let duration = start.elapsed();
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(
        duration < Duration::from_millis(10),
        "Fast endpoint should respond in < 10ms, took {:?}",
        duration
    );

    // Test medium endpoint performance
    let start = Instant::now();
    let response = server.get("/api/v1/medium").await;
    let duration = start.elapsed();
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(
        duration < Duration::from_millis(100),
        "Medium endpoint should respond in < 100ms, took {:?}",
        duration
    );

    // Test slow endpoint performance
    let start = Instant::now();
    let response = server.get("/api/v1/slow").await;
    let duration = start.elapsed();
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(
        duration < Duration::from_millis(300),
        "Slow endpoint should respond in < 300ms, took {:?}",
        duration
    );
}

#[tokio::test]
async fn test_concurrent_load_handling() {
    // Test handling of concurrent requests
    use std::sync::atomic::{AtomicUsize, Ordering};

    let request_counter = Arc::new(AtomicUsize::new(0));
    let active_requests = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let app = Router::new().route(
        "/api/v1/load/test",
        axum::routing::get({
            let request_counter = Arc::clone(&request_counter);
            let active_requests = Arc::clone(&active_requests);
            let max_concurrent = Arc::clone(&max_concurrent);
            move || async move {
                let current_active = active_requests.fetch_add(1, Ordering::SeqCst) + 1;
                let total_requests = request_counter.fetch_add(1, Ordering::SeqCst);

                // Update max concurrent
                let mut current_max = max_concurrent.load(Ordering::SeqCst);
                while current_active > current_max {
                    match max_concurrent.compare_exchange(
                        current_max,
                        current_active,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(new_max) => current_max = new_max,
                    }
                }

                // Simulate processing time
                sleep(Duration::from_millis(10)).await;

                active_requests.fetch_sub(1, Ordering::SeqCst);

                Json(json!({
                    "request_id": total_requests,
                    "concurrent_active": current_active,
                    "max_concurrent": max_concurrent.load(Ordering::SeqCst)
                }))
            }
        }),
    );

    let app_clone = app.clone();
    let _server = TestServer::new(app_clone).unwrap();

    // Test with 50 concurrent requests
    let num_requests = 50;
    let mut handles = vec![];

    let start_time = Instant::now();

    for i in 0..num_requests {
        let app_clone = app.clone();
        let handle = tokio::spawn(async move {
            let server = TestServer::new(app_clone).unwrap();
            let response = server.get("/api/v1/load/test").await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            (i, body)
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let total_time = start_time.elapsed();

    // Verify all requests completed
    assert_eq!(results.len(), num_requests);

    // Check that we had concurrent execution
    let max_concurrent_seen = results
        .iter()
        .map(|(_, body)| body["max_concurrent"].as_u64().unwrap())
        .max()
        .unwrap();

    assert!(
        max_concurrent_seen > 1,
        "Should have had concurrent requests, max was {}",
        max_concurrent_seen
    );

    // Check performance metrics
    let avg_response_time = total_time / num_requests as u32;
    assert!(
        avg_response_time < Duration::from_millis(100),
        "Average response time should be < 100ms, was {:?}",
        avg_response_time
    );

    // Verify request counter
    let final_count = request_counter.load(Ordering::SeqCst);
    assert_eq!(final_count, num_requests);
}

#[tokio::test]
async fn test_memory_usage_under_load() {
    // Test memory usage patterns under load
    let data_store = Arc::new(Mutex::new(Vec::new()));

    let app = Router::new()
        .route(
            "/api/v1/memory/test",
            axum::routing::post({
                let data_store = Arc::clone(&data_store);
                move |Json(payload): Json<serde_json::Value>| async move {
                    let data = payload.get("data").and_then(|v| v.as_str()).unwrap_or("");

                    let mut store = data_store.lock().await;
                    store.push(data.to_string());

                    // Simulate memory-intensive operation
                    let processed_data = data.chars().rev().collect::<String>();
                    sleep(Duration::from_millis(5)).await;

                    Json(json!({
                        "stored_items": store.len(),
                        "processed": processed_data,
                        "memory_estimate": data.len() * store.len()
                    }))
                }
            }),
        )
        .route(
            "/api/v1/memory/cleanup",
            axum::routing::post({
                let data_store = Arc::clone(&data_store);
                move || async move {
                    let mut store = data_store.lock().await;
                    let cleaned_count = store.len();
                    store.clear();

                    Json(json!({"cleaned_items": cleaned_count}))
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test memory usage with increasing load
    let mut memory_estimates = vec![];

    for i in 0..20 {
        let data_size = 100 * (i + 1); // Increasing data size
        let test_data = "x".repeat(data_size);

        let response = server
            .post("/api/v1/memory/test")
            .json(&json!({"data": test_data}))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        memory_estimates.push(body["memory_estimate"].as_u64().unwrap());
    }

    // Verify memory estimates are reasonable (should increase but not exponentially)
    for i in 1..memory_estimates.len() {
        let growth_ratio = memory_estimates[i] as f64 / memory_estimates[i - 1] as f64;
        assert!(
            growth_ratio < 5.0,
            "Memory growth ratio too high: {} at step {}",
            growth_ratio,
            i
        );
    }

    // Cleanup
    let response = server.post("/api/v1/memory/cleanup").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["cleaned_items"], 20);
}

#[tokio::test]
async fn test_database_connection_pooling() {
    // Test database connection pool performance
    use std::sync::atomic::{AtomicUsize, Ordering};

    let connection_pool = Arc::new(Mutex::new(Vec::new()));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let total_queries = Arc::new(AtomicUsize::new(0));

    let app = Router::new().route(
        "/api/v1/db/query",
        axum::routing::get({
            let connection_pool = Arc::clone(&connection_pool);
            let active_connections = Arc::clone(&active_connections);
            let total_queries = Arc::clone(&total_queries);
            move |Query(params): Query<HashMap<String, String>>| async move {
                let query_type = params.get("type").map_or("select", |v| v);

                // Simulate connection pool behavior
                let mut pool = connection_pool.lock().await;
                let connection_id = if pool.is_empty() {
                    // Create new connection
                    let new_id = pool.len();
                    pool.push(format!("conn_{}", new_id));
                    new_id
                } else {
                    // Reuse existing connection
                    pool.len() - 1
                };

                let active_count = active_connections.fetch_add(1, Ordering::SeqCst);
                let query_count = total_queries.fetch_add(1, Ordering::SeqCst);

                // Simulate query execution time
                let query_time = match query_type {
                    "select" => 5,
                    "insert" => 10,
                    "update" => 15,
                    "delete" => 20,
                    _ => 5,
                };
                sleep(Duration::from_millis(query_time)).await;

                active_connections.fetch_sub(1, Ordering::SeqCst);

                Json(json!({
                    "connection_id": connection_id,
                    "query_type": query_type,
                    "active_connections": active_count + 1,
                    "total_queries": query_count + 1,
                    "pool_size": pool.len(),
                    "execution_time_ms": query_time
                }))
            }
        }),
    );

    let app_clone = app.clone();
    let _server = TestServer::new(app_clone).unwrap();

    // Test connection pool with concurrent queries
    let num_queries = 30;
    let mut handles = vec![];

    let start_time = Instant::now();

    for i in 0..num_queries {
        let app_clone = app.clone();
        let query_type = match i % 4 {
            0 => "select",
            1 => "insert",
            2 => "update",
            _ => "delete",
        };

        let handle = tokio::spawn(async move {
            let server = TestServer::new(app_clone).unwrap();
            let response = server
                .get(&format!("/api/v1/db/query?type={}", query_type))
                .await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            (i, body)
        });
        handles.push(handle);
    }

    // Wait for all queries to complete
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let total_time = start_time.elapsed();

    // Analyze results
    let mut connection_usage = HashMap::new();
    let mut query_types = HashMap::new();

    for (_, body) in &results {
        let conn_id = body["connection_id"].as_u64().unwrap();
        *connection_usage.entry(conn_id).or_insert(0) += 1;

        let q_type = body["query_type"].as_str().unwrap();
        *query_types.entry(q_type).or_insert(0) += 1;
    }

    // Verify connection reuse
    let unique_connections = connection_usage.len();
    assert!(
        unique_connections <= 10,
        "Should reuse connections, but used {} unique connections",
        unique_connections
    );

    // Verify query distribution
    assert!(query_types.contains_key("select"));
    assert!(query_types.contains_key("insert"));
    assert!(query_types.contains_key("update"));
    assert!(query_types.contains_key("delete"));

    // Performance check
    let avg_query_time = total_time / num_queries as u32;
    assert!(
        avg_query_time < Duration::from_millis(50),
        "Average query time should be < 50ms, was {:?}",
        avg_query_time
    );
}

#[tokio::test]
async fn test_caching_performance() {
    // Test caching layer performance
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cache = Arc::new(Mutex::new(HashMap::new()));
    let cache_hits = Arc::new(AtomicUsize::new(0));
    let cache_misses = Arc::new(AtomicUsize::new(0));
    let db_queries = Arc::new(AtomicUsize::new(0));

    let app = Router::new()
        .route(
            "/api/v1/cache/{key}",
            axum::routing::get({
                let cache = Arc::clone(&cache);
                let cache_hits = Arc::clone(&cache_hits);
                let cache_misses = Arc::clone(&cache_misses);
                let db_queries = Arc::clone(&db_queries);
                move |Path(key): Path<String>| async move {
                    let mut cache_store = cache.lock().await;

                    if let Some(cached_value) = cache_store.get(&key) {
                        cache_hits.fetch_add(1, Ordering::SeqCst);
                        return Json(json!({
                            "key": key,
                            "value": cached_value,
                            "source": "cache",
                            "cache_hits": cache_hits.load(Ordering::SeqCst),
                            "cache_misses": cache_misses.load(Ordering::SeqCst)
                        }));
                    }

                    // Cache miss - simulate DB query
                    cache_misses.fetch_add(1, Ordering::SeqCst);
                    db_queries.fetch_add(1, Ordering::SeqCst);

                    sleep(Duration::from_millis(20)).await; // Simulate DB query time

                    let value = format!("data_for_{}", key);
                    cache_store.insert(key.clone(), value.clone());

                    Json(json!({
                        "key": key,
                        "value": value,
                        "source": "database",
                        "cache_hits": cache_hits.load(Ordering::SeqCst),
                        "cache_misses": cache_misses.load(Ordering::SeqCst),
                        "db_queries": db_queries.load(Ordering::SeqCst)
                    }))
                }
            }),
        )
        .route(
            "/api/v1/cache/stats",
            axum::routing::get({
                let cache_hits = Arc::clone(&cache_hits);
                let cache_misses = Arc::clone(&cache_misses);
                let db_queries = Arc::clone(&db_queries);
                move || async move {
                    let hits = cache_hits.load(Ordering::SeqCst);
                    let misses = cache_misses.load(Ordering::SeqCst);
                    let queries = db_queries.load(Ordering::SeqCst);
                    let total_requests = hits + misses;
                    let hit_rate = if total_requests > 0 {
                        (hits as f64 / total_requests as f64) * 100.0
                    } else {
                        0.0
                    };

                    Json(json!({
                        "cache_hits": hits,
                        "cache_misses": misses,
                        "db_queries": queries,
                        "total_requests": total_requests,
                        "hit_rate_percent": hit_rate
                    }))
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test cache performance with repeated requests
    let keys = vec!["user1", "user2", "user3", "user1", "user2", "user1"];

    let start_time = Instant::now();
    let mut responses = vec![];

    for key in keys {
        let response = server.get(&format!("/api/v1/cache/{}", key)).await;
        assert_eq!(response.status_code(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        responses.push(body);
    }

    let total_time = start_time.elapsed();

    // Verify caching behavior
    let cache_responses = responses.iter().filter(|r| r["source"] == "cache").count();
    let db_responses = responses
        .iter()
        .filter(|r| r["source"] == "database")
        .count();

    assert_eq!(
        db_responses, 3,
        "Should have 3 database queries for 3 unique keys"
    );
    assert_eq!(
        cache_responses, 3,
        "Should have 3 cache hits for repeated keys"
    );

    // Get final stats
    let response = server.get("/api/v1/cache/stats").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let stats: serde_json::Value = response.json();
    let hit_rate = stats["hit_rate_percent"].as_f64().unwrap();

    assert!(
        hit_rate > 30.0,
        "Cache hit rate should be > 30%, was {:.2}%",
        hit_rate
    );

    // Performance check
    let avg_response_time = total_time / responses.len() as u32;
    assert!(
        avg_response_time < Duration::from_millis(30),
        "Average response time should be < 30ms, was {:?}",
        avg_response_time
    );
}

#[tokio::test]
async fn test_api_throttling_and_quotas() {
    // Test API throttling and quota management

    let request_counts = Arc::new(Mutex::new(HashMap::new()));
    let quota_limits = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route(
            "/api/v1/quota/test",
            axum::routing::get({
                let request_counts = Arc::clone(&request_counts);
                let quota_limits = Arc::clone(&quota_limits);
                move |headers: axum::http::HeaderMap| async move {
                    let user_id = headers
                        .get("x-user-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("anonymous");

                    let mut counts = request_counts.lock().await;
                    let mut limits = quota_limits.lock().await;

                    let user_count = counts.entry(user_id.to_string()).or_insert(0);
                    let user_limit = limits.entry(user_id.to_string()).or_insert(10); // 10 requests per user

                    *user_count += 1;

                    if *user_count > *user_limit {
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(json!({
                                "error": "Quota exceeded",
                                "requests_used": *user_count,
                                "limit": *user_limit
                            })),
                        );
                    }

                    (
                        StatusCode::OK,
                        Json(json!({
                            "message": "Request allowed",
                            "requests_used": *user_count,
                            "limit": *user_limit,
                            "remaining": *user_limit - *user_count
                        })),
                    )
                }
            }),
        )
        .route(
            "/api/v1/quota/reset",
            axum::routing::post({
                let request_counts = Arc::clone(&request_counts);
                move |headers: axum::http::HeaderMap| async move {
                    let user_id = headers
                        .get("x-user-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("anonymous");

                    let mut counts = request_counts.lock().await;
                    let reset_count = counts.remove(user_id).unwrap_or(0);

                    Json(json!({"reset_requests": reset_count}))
                }
            }),
        );

    let server = TestServer::new(app).unwrap();

    // Test quota enforcement
    let user_id = "test_user";

    // Make requests up to the limit
    for i in 1..=10 {
        let response = server
            .get("/api/v1/quota/test")
            .add_header("x-user-id", user_id)
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["requests_used"], i);
        assert_eq!(body["remaining"], 10 - i);
    }

    // Next request should be rejected
    let response = server
        .get("/api/v1/quota/test")
        .add_header("x-user-id", user_id)
        .await;

    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value = response.json();
    assert_eq!(body["requests_used"], 11);
    assert_eq!(body["limit"], 10);

    // Reset quota
    let response = server
        .post("/api/v1/quota/reset")
        .add_header("x-user-id", user_id)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["reset_requests"], 11);

    // Test that quota is reset
    let response = server
        .get("/api/v1/quota/test")
        .add_header("x-user-id", user_id)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["requests_used"], 1);
}

#[tokio::test]
async fn test_error_rate_and_circuit_breaker() {
    // Test error rate monitoring and circuit breaker pattern
    use std::sync::atomic::{AtomicUsize, Ordering};

    let error_count = Arc::new(AtomicUsize::new(0));
    let success_count = Arc::new(AtomicUsize::new(0));
    let circuit_open = Arc::new(AtomicUsize::new(0)); // 0 = closed, 1 = open

    let app = Router::new()
        .route("/api/v1/circuit/{action}", axum::routing::get({
            let error_count = Arc::clone(&error_count);
            let success_count = Arc::clone(&success_count);
            let circuit_open = Arc::clone(&circuit_open);
            move |Path(action): Path<String>| async move {
                let is_open = circuit_open.load(Ordering::SeqCst) == 1;

                match action.as_str() {
                    "success" => {
                        success_count.fetch_add(1, Ordering::SeqCst);

                        // Close circuit if it was open and we have success
                        if is_open {
                            circuit_open.store(0, Ordering::SeqCst);
                        }

                        (StatusCode::OK, Json(json!({
                            "result": "success",
                            "circuit_state": if is_open { "closed" } else { "closed" },
                            "success_count": success_count.load(Ordering::SeqCst),
                            "error_count": error_count.load(Ordering::SeqCst)
                        })))
                    }
                    "error" => {
                        let errors = error_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let successes = success_count.load(Ordering::SeqCst);

                        // Open circuit if error rate > 50%
                        let total_requests = errors + successes;
                        if total_requests >= 10 && (errors as f64 / total_requests as f64) > 0.5 {
                            circuit_open.store(1, Ordering::SeqCst);
                        }

                        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                            "error": "Simulated error",
                            "circuit_state": if circuit_open.load(Ordering::SeqCst) == 1 { "open" } else { "closed" },
                            "success_count": successes,
                            "error_count": errors
                        })))
                    }
                    _ => (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid action"})))
                }
            }
        }));

    let server = TestServer::new(app).unwrap();

    // Test normal operation
    for _ in 0..5 {
        let response = server.get("/api/v1/circuit/success").await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Introduce errors to trigger circuit breaker
    for _ in 0..10 {
        let _response = server.get("/api/v1/circuit/error").await;
        // Don't assert status code here as it might change when circuit opens
    }

    // Circuit should now be open, but success requests close it
    let response = server.get("/api/v1/circuit/success").await;
    assert_eq!(response.status_code(), StatusCode::OK); // Success request closes the circuit

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "closed");

    // Circuit should now be closed
    let response = server.get("/api/v1/circuit/success").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["circuit_state"], "closed");
}
