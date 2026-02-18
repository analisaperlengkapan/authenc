#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc Crypto
//!
//! Cryptographic operations for the Authenc IAM system.
//! Includes AES-GCM, Ed25519, ECDSA, EdDSA, post-quantum cryptography, and more.

/// Cryptographic operations and utilities
pub mod crypto;

/// Crypto utility functions (password hashing, JWT helpers)
pub mod utils;

// Re-export crypto types
pub use crypto::*;
