/// JWT token handling and validation utilities
///
/// This module provides secure JWT (JSON Web Token) operations including
/// token generation, validation, and claims extraction. All operations
/// use cryptographically secure algorithms and follow JWT best practices.
pub mod jwt;

/// Password hashing and verification utilities
///
/// This module provides secure password hashing using industry-standard
/// algorithms (Argon2) with configurable parameters for security and performance.
/// Includes utilities for both password hashing and verification operations.
pub mod password;

pub use jwt::*;
pub use password::*;
