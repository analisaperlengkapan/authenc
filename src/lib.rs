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
/// Application state and initialization
pub mod app;
/// Configuration management
pub mod config;
/// Cryptographic operations and utilities
pub mod crypto;
/// Error types and handling
pub mod error;
/// Data models and structures
pub mod models;
/// Utility functions and helpers
pub mod utils;

// Framework integrations
/// Web framework integration
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod web;

// Database layer
/// Database operations and connection management
#[cfg(feature = "db")]
#[cfg_attr(docsrs, doc(cfg(feature = "db")))]
pub mod database;

// HTTP layer
/// HTTP request handlers
pub mod handlers;
/// HTTP middleware components
pub mod middleware;

// Business logic
/// Core business services and logic
pub mod services;

// Security vault
/// Secret management and vault operations
pub mod vault;

// Event system
/// Event-driven architecture for audit logging and integrations
pub mod events;

// Protocol extensions
/// Protocol mapper extensions for OIDC and SAML claim/attribute mapping
pub mod protocol;

// Custom authenticators
/// Custom authenticator support for extensible authentication flows
pub mod authenticator;

// SPI architecture
/// Service Provider Interface framework for extensibility
pub mod spi;

// Admin Console UI
/// Web-based admin interface using Leptos
#[cfg(feature = "admin_console")]
#[cfg_attr(docsrs, doc(cfg(feature = "admin_console")))]
pub mod admin_console;

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
    Router, body,
    extract::{self, Json, Path, Query},
    http::{self, HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
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
