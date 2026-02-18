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
//!
//! ## Crate Structure
//!
//! The project is organized into multiple crates:
//!
//! - `authenc-core` - Error types, configuration, and utilities
//! - `authenc-models` - Domain models and data structures
//! - `authenc-crypto` - Cryptographic operations
//! - `authenc-database` - Database persistence layer
//! - `authenc-vault` - Secret management
//! - `authenc-spi` - Service Provider Interface framework
//! - `authenc-services` - Business logic and services

// ============================================================
// Re-export sub-crates as modules for backward compatibility
// ============================================================

/// Error types and handling (from authenc-core)
pub use authenc_core::error;

/// Configuration management (from authenc-core)
pub use authenc_core::config;

/// Utility functions and helpers (from authenc-core)
pub use authenc_core::utils;

/// Data models and structures (from authenc-models)
pub use authenc_models::models;

/// Cryptographic operations and utilities (from authenc-crypto)
pub use authenc_crypto::crypto;

/// Database operations and connection management (from authenc-database)
pub use authenc_database::database;

/// Secret management and vault operations (from authenc-vault)
pub use authenc_vault::vault;

/// Service Provider Interface framework (from authenc-spi)
pub use authenc_spi::spi;

/// Protocol mapper extensions (from authenc-spi)
pub use authenc_spi::protocol;

/// Custom authenticator support (from authenc-spi)
pub use authenc_spi::authenticator;

/// Core business services and logic (from authenc-services)
pub use authenc_services::services;

/// Event-driven architecture (from authenc-services)
pub use authenc_services::events;

// ============================================================
// Modules that remain in the root crate
// ============================================================

/// Application state and initialization
pub mod app;

/// HTTP request handlers
pub mod handlers;

/// HTTP middleware components
pub mod middleware;

/// Axum web framework integration
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod axum_app;

/// Web-based admin interface
#[cfg(feature = "admin_console")]
#[cfg_attr(docsrs, doc(cfg(feature = "admin_console")))]
pub mod admin_console;

// ============================================================
// Re-export commonly used items
// ============================================================

pub use authenc_core::{AppConfig, AuthencError, Result};

// Re-export async_trait for handler traits
pub use async_trait::async_trait;

// Re-export serde for (de)serialization
pub use serde::{Deserialize, Serialize};

// Re-export tracing for logging
pub use tracing::{debug, info, warn};
pub use tracing::error as trace_error;

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
