// Utility modules

/// Cryptographic utilities for secure operations
///
/// Provides cryptographic functions including key generation,
/// encryption/decryption, and secure random number generation.
/// Used throughout the authentication platform for security operations.
pub mod crypto;

/// Cryptographic operation monitoring and security auditing
///
/// Monitors cryptographic operations for security compliance,
/// performance metrics, and anomaly detection.
/// Helps maintain security standards and detect potential attacks.
pub mod crypto_monitor;

/// Internationalization (i18n) utilities for multi-language support
///
/// Handles localization, message translation, and cultural formatting.
/// Supports multiple languages for user-facing messages and interfaces.
pub mod i18n;

/// JWT token utilities and helpers
///
/// Provides JWT token parsing, validation, and utility functions.
/// Supports both encoding and decoding of JWT tokens with various algorithms.
pub mod jwt;

/// Plugin system utilities for extensibility
///
/// Framework for loading and managing authentication plugins.
/// Enables third-party extensions and custom authentication methods.
pub mod plugin;

// Re-exports for convenience
pub use i18n::*;
