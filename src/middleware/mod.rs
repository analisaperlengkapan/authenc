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

// ============================================================
// Security Configuration Types
// ============================================================

/// Comprehensive security configuration for the Authenc system
#[derive(Clone, Debug)]
pub struct SecurityMiddlewareConfig {
    /// Security headers configuration
    pub headers: SecurityHeadersConfig,
    /// CSRF protection configuration
    pub csrf: CsrfConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Input validation configuration
    pub input_validation: InputValidationConfig,
    /// Security monitoring configuration
    pub monitoring: SecurityMonitoringConfig,
}

impl SecurityMiddlewareConfig {
    /// Create a new security configuration with default secure settings
    pub fn secure_defaults() -> Self {
        Self {
            headers: SecurityHeadersConfig::secure(),
            csrf: CsrfConfig::default(),
            rate_limit: RateLimitConfig::default(),
            input_validation: InputValidationConfig::default(),
            monitoring: SecurityMonitoringConfig::default(),
        }
    }

    /// Create a new security configuration with development-friendly settings
    pub fn development_defaults() -> Self {
        Self {
            headers: SecurityHeadersConfig::development(),
            csrf: CsrfConfig {
                enabled: false, // Disable CSRF in development for easier testing
                ..CsrfConfig::default()
            },
            rate_limit: RateLimitConfig::default(),
            input_validation: InputValidationConfig::default(),
            monitoring: SecurityMonitoringConfig::default(),
        }
    }
}

impl Default for SecurityMiddlewareConfig {
    fn default() -> Self {
        Self::secure_defaults()
    }
}

/// Enhanced security headers configuration
#[derive(Clone, Debug)]
pub struct SecurityHeadersConfig {
    /// Whether to enable enhanced security headers
    pub enabled: bool,
    /// HSTS max age in seconds
    pub hsts_max_age: u32,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Whether to enable HSTS preload
    pub hsts_preload: bool,
    /// Content Security Policy directives
    pub csp_directives: Vec<String>,
}

impl SecurityHeadersConfig {
    /// Secure defaults for production
    pub fn secure() -> Self {
        Self {
            enabled: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: true,
            csp_directives: vec![
                "default-src 'self'".to_string(),
                "script-src 'self' 'unsafe-inline'".to_string(),
                "style-src 'self' 'unsafe-inline'".to_string(),
                "img-src 'self' data: https:".to_string(),
                "font-src 'self' data:".to_string(),
                "connect-src 'self'".to_string(),
                "media-src 'none'".to_string(),
                "object-src 'none'".to_string(),
                "frame-src 'none'".to_string(),
                "frame-ancestors 'none'".to_string(),
                "form-action 'self'".to_string(),
                "upgrade-insecure-requests".to_string(),
                "block-all-mixed-content".to_string(),
            ],
        }
    }

    /// Development-friendly settings
    pub fn development() -> Self {
        Self {
            enabled: true,
            hsts_max_age: 0, // Disable HSTS in development
            hsts_include_subdomains: false,
            hsts_preload: false,
            csp_directives: vec![
                "default-src 'self' 'unsafe-inline' 'unsafe-eval'".to_string(),
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'".to_string(),
                "style-src 'self' 'unsafe-inline'".to_string(),
                "img-src 'self' data: https:".to_string(),
                "font-src 'self' data:".to_string(),
                "connect-src 'self' ws: http: https:".to_string(),
            ],
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self::secure()
    }
}
