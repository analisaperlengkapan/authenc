#![warn(missing_docs)]
#![warn(unsafe_code)]

//! # Authenc SPI
//!
//! Service Provider Interface framework for the Authenc IAM system.

/// Service Provider Interface framework for extensibility
pub mod spi;

/// Protocol mapper extensions
pub mod protocol;

/// Custom authenticator support
pub mod authenticator;

// Re-export SPI types
pub use spi::*;
