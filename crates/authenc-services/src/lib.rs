#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc Services
//!
//! Business logic and services for the Authenc IAM system.

/// Core business services and logic
pub mod services;

/// Event-driven architecture for audit logging and integrations
pub mod events;

// Re-export commonly used service types
pub use services::*;
