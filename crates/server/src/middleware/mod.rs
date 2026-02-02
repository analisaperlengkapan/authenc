//! # Middleware Module
//!
//! This module contains various middleware components for the application, organized into categories:
//! - Core middleware (security, rate limiting)
//! - Authentication and authorization middleware
//! - Axum-specific middleware implementations
//!
//! ## Features
//! - `axum`: Enables Axum-specific middleware implementations
//! - `actix-web`: Enables Actix-Web-specific middleware implementations (not yet implemented)

// Axum middleware (primary implementation)

/// Authentication middleware for Axum web framework
///
/// Handles JWT token validation, user authentication, and session management.
/// Integrates with the authentication system to protect API endpoints.
/// Supports Bearer token authentication and session-based auth.
pub mod auth;

/// Rate limiting middleware for Axum
///
/// Implements rate limiting to prevent abuse and DoS attacks.
/// Supports various rate limiting strategies including sliding window,
/// fixed window, and token bucket algorithms.
/// Configurable limits per endpoint and user.
pub mod rate_limit;

/// Role-Based Access Control (RBAC) middleware for Axum
///
/// Enforces role-based permissions on API endpoints.
/// Checks user roles and permissions before allowing access to resources.
/// Integrates with the authorization system for fine-grained access control.
pub mod rbac;

/// Response compression middleware for Axum
///
/// Compresses HTTP responses to reduce bandwidth usage.
/// Supports gzip, deflate, and brotli compression algorithms.
/// Automatically negotiates compression based on client capabilities.
pub mod compression;

/// Cross-Origin Resource Sharing (CORS) middleware for Axum
///
/// Handles CORS headers for cross-origin requests.
/// Configurable allowed origins, methods, and headers.
/// Essential for web applications making cross-origin API calls.
pub mod cors;

/// Input validation middleware for Axum
///
/// Validates and sanitizes incoming request data.
/// Prevents injection attacks and malformed data.
/// Supports custom validation rules and error handling.
pub mod validation;

/// Mutual TLS (mTLS) authentication middleware
///
/// Provides client certificate validation for API endpoints.
/// Can be configured to work with reverse proxies that handle
/// TLS termination and forward certificate information via headers.
pub mod mtls;

/// Security headers middleware for Axum
///
/// Adds security-related HTTP headers to responses.
/// Implements security best practices including CSP, HSTS, and XSS protection.
/// Helps prevent common web vulnerabilities and attacks.
pub mod security_headers;

/// CSRF protection middleware for Axum
///
/// Prevents Cross-Site Request Forgery attacks.
/// Validates CSRF tokens on state-changing requests.
/// Configurable token generation and validation rules.
pub mod csrf;

/// Security monitoring and alerting middleware for Axum
///
/// Monitors requests for suspicious activity and security events.
/// Logs authentication attempts, authorization failures, and attacks.
/// Integrates with audit logging for compliance and forensics.
pub mod security_monitoring;

/// Request timeout middleware for Axum
///
/// Enforces request timeouts to prevent resource exhaustion.
/// Configurable timeout durations per endpoint.
/// Helps maintain system responsiveness and prevents hanging requests.
pub mod timeout;

/// Request logging middleware for Axum
pub mod logger;

// Re-export middleware types for easier access
pub use rate_limit::{
    RateLimitConfig, RateLimitLayer, RateLimitMiddleware, RateLimiterState, rate_limit_layer,
    rate_limit_middleware,
};

pub use compression::{ContentEncoding, compression_middleware};
pub use cors::{cors_layer, cors_middleware};
pub use csrf::{
    CsrfConfig, CsrfState, csrf_protection_middleware, generate_csrf_token_response,
};
pub use validation::{InputValidationConfig, input_validation_middleware};
pub use security_headers::security_headers_middleware;
pub use security_monitoring::{
    SecurityMonitoringConfig, SecurityMonitoringState, security_monitoring_middleware,
};
pub use timeout::{TimeoutLayer, TimeoutMiddleware};

// Re-exports for convenience
pub use auth::{AuthState, auth_middleware};

pub use rbac::{RbacLayer, rbac_middleware};
