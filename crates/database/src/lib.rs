#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc Database
//!
//! Database persistence layer for the Authenc IAM system.

/// Database operations and connection management
pub mod database;

// Re-export database types
pub use database::*;
