#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc Vault
//!
//! Secret management and vault operations for the Authenc IAM system.

/// Secret management and vault operations
pub mod vault;

// Re-export vault types
pub use vault::*;
