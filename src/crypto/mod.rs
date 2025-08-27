// Modern cryptographic implementations
pub mod ed25519_keys;
pub mod ecdsa_keys;
pub mod simple_mtls;
pub mod aes_gcm;

// Re-exports for convenience
pub use ed25519_keys::*;
pub use ecdsa_keys::*;
pub use simple_mtls::*;
pub use aes_gcm::*;
