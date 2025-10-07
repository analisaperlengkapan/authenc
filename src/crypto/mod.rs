// Modern cryptographic implementations
/// AES-GCM encryption and decryption utilities
pub mod aes_gcm;
/// DPoP (Demonstrated Proof of Possession) token handling
pub mod dpop;
/// ECDSA P-256 key operations and utilities
pub mod ecdsa_keys;
/// ECDSA P-384 key operations and utilities
pub mod ecdsa_p384_keys;
/// ECDSA P-521 key operations and utilities
pub mod ecdsa_p521_keys;
/// Ed25519 key operations and utilities
pub mod ed25519_keys;
/// EdDSA Ed448 key operations and utilities
pub mod eddsa_ed448_keys;
/// Mutual TLS authentication utilities
pub mod mtls;
/// Post-Quantum Cryptography (PQC) wrappers for quantum-resistant algorithms
pub mod pqc;
/// SD-JWT (Selective Disclosure JWT) implementation
pub mod sdjwt;
/// Shamir Secret Sharing for distributed key management
pub mod shamir;
/// XML Digital Signature (XMLDSig) implementation for SAML
pub mod xmldsig;

// Re-exports for convenience
pub use aes_gcm::*;
pub use ecdsa_keys::*;
pub use ecdsa_p384_keys::*;
pub use ecdsa_p521_keys::*;
pub use eddsa_ed448_keys::{
    get_eddsa_jwk_set, sign_jwt_eddsa, verify_jwt_eddsa, EddsaJwk, EddsaJwkSet,
};
pub use mtls::*;
pub use pqc::{falcon, hybrid, mldsa, mlkem};
pub use sdjwt::*;
pub use shamir::{
    generate_shares_with_commitments, reconstruct_secret, reconstruct_secret_verified,
    verify_share_with_commitment, Commitment, ShamirConfig, ShamirError, Share,
};
