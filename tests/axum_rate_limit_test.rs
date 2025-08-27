#![cfg(test)]

use authenc::middleware::rate_limit_axum::{RateLimitConfig, RateLimiterState};

#[tokio::test]
async fn test_rate_limiter_state() {
    // Configure rate limiting to allow 2 requests per minute for testing
    let config = RateLimitConfig {
        requests_per_minute: 2,
        excluded_paths: vec!["/health".to_string()],
        enabled: true,
    };

    let state = RateLimiterState::new(config);

    // Test IP address
    let test_ip = "127.0.0.1";

    // First request should succeed
    assert!(state.check_rate_limit("/test", test_ip).is_ok());

    // Second request should succeed
    assert!(state.check_rate_limit("/test", test_ip).is_ok());

    // Third request should be rate limited
    assert!(state.check_rate_limit("/test", test_ip).is_err());

    // Health check should not be rate limited (excluded path)
    assert!(state.check_rate_limit("/health", test_ip).is_ok());

    // Different IP should not be rate limited
    assert!(state.check_rate_limit("/test", "192.168.1.1").is_ok());
}

#[tokio::test]
async fn test_rate_limit_disabled() {
    // Configure rate limiting as disabled
    let config = RateLimitConfig {
        requests_per_minute: 1,
        excluded_paths: vec![],
        enabled: false,
    };

    let state = RateLimiterState::new(config);

    // Test IP address
    let test_ip = "127.0.0.1";

    // All requests should succeed when rate limiting is disabled
    assert!(state.check_rate_limit("/test", test_ip).is_ok());
    assert!(state.check_rate_limit("/test", test_ip).is_ok());
    assert!(state.check_rate_limit("/test", test_ip).is_ok());
}
