use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;

/// Hash a password using Argon2 for secure storage
///
/// This function generates a cryptographically secure password hash using the
/// Argon2 password hashing algorithm with randomly generated salt. The resulting
/// hash can be safely stored in a database and later used for password verification.
///
/// # Arguments
/// * `password` - The plaintext password to hash
///
/// # Returns
/// A `Result` containing the password hash string in PHC format on success,
/// or an Argon2 error on failure
///
/// # Security Considerations
/// - Uses Argon2 with default parameters suitable for most applications
/// - Generates cryptographically secure random salt for each password
/// - Hash format includes algorithm parameters for future verification
/// - Computationally expensive to prevent brute force attacks
/// - Should be used for all password storage operations
///
/// # Example
/// ```rust
/// use authenc::utils::crypto::password::hash_password;
///
/// let hash = hash_password("my_secure_password").expect("Failed to hash password");
/// // Store the hash in database
/// ```
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verify a password against its hash
///
/// This function verifies a plaintext password against a previously computed
/// Argon2 password hash. It performs a constant-time comparison to prevent
/// timing attacks and returns whether the password matches the hash.
///
/// # Arguments
/// * `hash` - The password hash string in PHC format (from `hash_password`)
/// * `password` - The plaintext password to verify
///
/// # Returns
/// A `Result` containing `true` if the password matches, `false` otherwise,
/// or an Argon2 error if the hash format is invalid
///
/// # Security Considerations
/// - Uses constant-time comparison to prevent timing attacks
/// - Validates hash format before verification
/// - Returns boolean result to avoid information leakage
/// - Should be used for all password verification operations
/// - Failed verifications should be logged for security monitoring
///
/// # Example
/// ```rust
/// use authenc::utils::crypto::password::{hash_password, verify_password};
///
/// let hash = hash_password("my_password").unwrap();
/// let is_valid = verify_password(&hash, "my_password").unwrap();
/// assert!(is_valid);
///
/// let is_invalid = verify_password(&hash, "wrong_password").unwrap();
/// assert!(!is_invalid);
/// ```
pub fn verify_password(hash: &str, password: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
