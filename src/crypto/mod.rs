// Modern cryptographic implementations
pub mod aes_gcm;
pub mod dpop;
pub mod ecdsa_keys;
pub mod ecdsa_p384_keys;
pub mod ecdsa_p521_keys;
pub mod ed25519_keys;
pub mod eddsa_ed448_keys;
pub mod sdjwt;
pub mod simple_mtls;

// Re-exports for convenience
pub use aes_gcm::*;
pub use ecdsa_keys::*;
pub use ecdsa_p384_keys::*;
pub use ecdsa_p521_keys::*;
pub use ed25519_keys::*;
pub use eddsa_ed448_keys::{
    get_eddsa_jwk_set, sign_jwt_eddsa, verify_jwt_eddsa, EddsaJwk, EddsaJwkSet,
};
pub use sdjwt::*;
pub use simple_mtls::*;
