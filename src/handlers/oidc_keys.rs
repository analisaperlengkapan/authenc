// Legacy RSA key implementation - DEPRECATED for security
// Replaced with Ed25519 in crypto/ed25519_keys.rs
use once_cell::sync::Lazy;
// use rand::thread_rng; // Removed - not needed for disabled legacy code
// use rsa::{
//     pkcs8::{EncodePrivateKey, EncodePublicKey},
//     RsaPrivateKey, RsaPublicKey,
// }; // REMOVED: Vulnerable to timing attacks (RUSTSEC-2023-0071)

// DEPRECATED: Legacy RSA implementation disabled for security
// Use crypto/ed25519_keys.rs for secure Ed25519 keys instead

// Placeholder to maintain compilation - DO NOT USE
/// DEPRECATED: Legacy RSA keypair placeholder - DISABLED FOR SECURITY
///
/// This static is a placeholder to maintain compilation compatibility.
/// The legacy RSA implementation has been disabled due to security vulnerabilities
/// (RUSTSEC-2023-0071) and timing attack risks.
///
/// # Security Warning
/// - DO NOT use this implementation
/// - Use Ed25519 keys from `crypto/ed25519_keys.rs` instead
/// - Legacy RSA is vulnerable to timing attacks
/// - This will panic if accessed
///
/// # Migration
/// Migrate to: `authenc::crypto::ed25519_keys`
#[deprecated(since = "1.0.0", note = "Use Ed25519 keys instead - RSA is insecure")]
pub static RSA_KEYPAIR: Lazy<()> = Lazy::new(|| {
    log::error!("SECURITY: Attempted to use legacy RSA keys - use Ed25519 implementation");
    ()
});

/// DEPRECATED: Get public key in PEM format - DISABLED FOR SECURITY
///
/// This function is disabled and will panic if called. The legacy RSA implementation
/// has been removed due to security vulnerabilities and timing attack risks.
///
/// # Security Warning
/// - DO NOT use this function
/// - Legacy RSA is vulnerable to timing attacks (RUSTSEC-2023-0071)
/// - This function will panic to prevent accidental use
///
/// # Migration
/// Use Ed25519 public key functions from `crypto/ed25519_keys.rs` instead:
/// ```rust
/// use authenc::crypto::ed25519_keys::get_ed25519_public_pem;
/// ```
#[deprecated(
    since = "1.0.0",
    note = "Use Ed25519 public key functions instead - RSA is insecure"
)]
pub fn get_public_pem() -> Result<String, String> {
    log::error!("SECURITY: Attempted to use legacy RSA PEM - use Ed25519 implementation");
    Err(
        "Legacy RSA PEM disabled - use Ed25519 implementation (see crypto/ed25519_keys.rs)"
            .to_string(),
    )
}

/// DEPRECATED: Get private key in PEM format - DISABLED FOR SECURITY
///
/// This function is disabled and will panic if called. The legacy RSA implementation
/// has been removed due to security vulnerabilities and timing attack risks.
///
/// # Security Warning
/// - DO NOT use this function
/// - Legacy RSA is vulnerable to timing attacks (RUSTSEC-2023-0071)
/// - Private keys should never be exposed in PEM format
/// - This function will panic to prevent accidental use
///
/// # Migration
/// Use Ed25519 signing functions from `crypto/ed25519_keys.rs` instead:
/// ```rust
/// use authenc::crypto::ed25519_keys::sign_ed25519;
/// ```
#[deprecated(
    since = "1.0.0",
    note = "Use Ed25519 signing functions instead - RSA is insecure"
)]
pub fn get_private_pem() -> Result<String, String> {
    log::error!("SECURITY: Attempted to use legacy RSA private PEM - use Ed25519 implementation");
    Err(
        "Legacy RSA private PEM disabled - use Ed25519 implementation (see crypto/ed25519_keys.rs)"
            .to_string(),
    )
}
