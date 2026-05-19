#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc Core
//!
//! Foundation types for the Authenc IAM system: error handling, configuration, and utilities.

/// Error types and handling
pub mod error;
/// Configuration management
pub mod config;
/// Utility functions and helpers
pub mod utils;

// Re-export commonly used items
pub use config::AppConfig;
pub use error::{AuthencError, Result};

// Re-export async_trait for convenience
pub use async_trait::async_trait;

// Re-export serde for (de)serialization
pub use serde::{Deserialize, Serialize};

// Re-export tracing for logging
pub use tracing::{debug, error, info, warn};
