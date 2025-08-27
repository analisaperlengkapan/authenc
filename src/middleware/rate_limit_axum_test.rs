use super::rate_limit_axum::{RateLimitConfig, RateLimiterState};
use axum::{
    body::Body,
    http::Request,
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn test_rate_limiting() {
    // Configure rate limiting to allow 2 requests per minute for testing
    let config = RateLimitConfig {
        requests_per_minute: 2,
        excluded_paths: vec!["/health".to_string()],
    };
    
    let state = Arc::new(RateLimiterState::new(config));
    
    let app = Router::new()
        .route("/test", get(|| async { "Hello, world!" }))
        .route("/health", get(|| async { "OK" }))
        .with_state(state);
    
    // First request should succeed
    let response = app
        .clone()
        .oneshot(
            Request::get("/test")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    
    // Second request should succeed
    let response = app
        .clone()
        .oneshot(
            Request::get("/test")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    
    // Third request should be rate limited
    let response = app
        .clone()
        .oneshot(
            Request::get("/test")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
    
    // Health check should not be rate limited
    let response = app
        .clone()
        .oneshot(
            Request::get("/health")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}
