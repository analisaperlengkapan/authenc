#![warn(missing_docs)]
#![warn(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Authenc
//! Authentication and authorization service with support for multiple web frameworks.
//!
//! This crate provides a comprehensive identity and access management solution
//! with enterprise-grade security features including:
//!
//! - Multi-protocol authentication (OIDC, SAML, JWT)
//! - Role-based and attribute-based access control
//! - Audit logging and compliance reporting
//! - Brute force protection and anomaly detection
//! - Multi-factor authentication support
//! - Federation and identity brokering
//! - Enterprise integrations

// Core modules
pub mod app;
pub mod config;
pub mod error;
pub mod models;
pub mod utils;
pub mod crypto;

// Framework integrations
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod axum_app;

// Database layer
#[cfg(feature = "db")]
#[cfg_attr(docsrs, doc(cfg(feature = "db")))]
pub mod database;

// HTTP layer
pub mod handlers;
pub mod middleware;

// Business logic
pub mod services;

// Security vault
pub mod vault;

// Re-export commonly used items
pub use config::AppConfig;
pub use error::{AuthencError, Result};

// Re-export async_trait for handler traits
pub use async_trait::async_trait;

// Re-export serde for (de)serialization
pub use serde::{Deserialize, Serialize};

// Re-export tracing for logging
pub use tracing::{debug, error, info, warn};

// Framework-specific re-exports
#[cfg(feature = "axum")]
pub use axum::{
    body,
    extract::{self, Json, Path, Query},
    http::{self, header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};

/// Application state shared across all requests
#[derive(Clone)]
pub struct AppState {
    /// Application configuration
    pub config: AppConfig,
}

impl AppState {
    /// Create a new application state
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }
}
