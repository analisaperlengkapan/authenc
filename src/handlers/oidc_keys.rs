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
pub static RSA_KEYPAIR: Lazy<()> =
    Lazy::new(|| panic!("Legacy RSA keys disabled - use Ed25519 implementation"));

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
pub fn get_public_pem() -> String {
    panic!("Legacy RSA PEM disabled - use Ed25519 implementation")
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
pub fn get_private_pem() -> String {
    panic!("Legacy RSA private PEM disabled - use Ed25519 implementation")
}
