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
pub static RSA_KEYPAIR: Lazy<()> = Lazy::new(|| {
    panic!("Legacy RSA keys disabled - use Ed25519 implementation")
});

pub fn get_public_pem() -> String {
    panic!("Legacy RSA PEM disabled - use Ed25519 implementation")
}

pub fn get_private_pem() -> String {
    panic!("Legacy RSA private PEM disabled - use Ed25519 implementation")
}
