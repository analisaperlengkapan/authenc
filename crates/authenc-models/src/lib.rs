#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc Models
//!
//! Domain models and data structures for the Authenc IAM system.

/// Data models and structures
pub mod models;

// Re-export commonly used model types
pub use models::*;
