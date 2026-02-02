// Export all modules
pub mod aes_gcm;
pub mod debug_pem;
pub mod dpop;
pub mod ecdsa_keys;
pub mod ecdsa_p384_keys;
pub mod ecdsa_p521_keys;
pub mod ed25519_keys;
pub mod eddsa_ed448_keys;
pub mod mtls;
pub mod pqc;
pub mod sdjwt;
pub mod shamir;
pub mod xmldsig;

// Common re-exports
pub use authenc_api::error;
