#![warn(missing_docs)]
#![warn(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Authenc
//! Authentication and authorization service with support for multiple web frameworks.

// Core modules
pub mod app;
pub mod config;
pub mod error;
pub mod models;
pub mod utils;
pub mod crypto;

// Feature modules
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod axum_app;

#[cfg(feature = "db")]
#[cfg_attr(docsrs, doc(cfg(feature = "db")))]
pub mod database;

pub mod handlers;
pub mod middleware;
pub mod services;
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
    // Add other shared state here
}

impl AppState {
    /// Create a new application state
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }
}
