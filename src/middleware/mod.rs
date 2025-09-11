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
pub mod auth_middleware_axum;
pub mod rate_limit_axum;
pub mod rbac_axum;

pub mod compression_axum;
pub mod cors_axum;
pub mod input_validation_axum;
pub mod mtls_simple;
pub mod security_headers_axum;
pub mod timeout_axum;

// Re-export middleware types for easier access
pub use rate_limit_axum::{
    rate_limit_layer, rate_limit_middleware, RateLimitConfig, RateLimitLayer, RateLimitMiddleware,
    RateLimiterState,
};

pub use compression_axum::{compression_middleware, ContentEncoding};
pub use cors_axum::{cors_layer, cors_middleware};
pub use input_validation_axum::{input_validation_middleware, InputValidationConfig};
pub use security_headers_axum::security_headers_middleware;
pub use timeout_axum::{TimeoutLayer, TimeoutMiddleware};

// Re-exports for convenience
pub use auth_middleware_axum::{auth_middleware, AuthState};

pub use rbac_axum::{rbac_middleware, RbacLayer};
