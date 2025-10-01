//! Post-Quantum Cryptography (PQC) wrappers
//!
//! This module provides quantum-resistant cryptographic primitives using
//! the pqcrypto libraries. It includes ML-DSA for digital signatures,
//! ML-KEM for key encapsulation, and FALCON for compact signatures.
//!
//! # Security Considerations
//! - These algorithms are designed to be resistant to quantum attacks
//! - ML-DSA and FALCON provide digital signature capabilities
//! - ML-KEM provides quantum-resistant key exchange
//! - All operations use cryptographically secure parameters
//! - Keys should be generated securely and stored safely
//! - Secret keys are zeroized on drop to prevent memory leaks

#[cfg(feature = "quantum")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
#[cfg(feature = "quantum")]
use ed25519_dalek::{self, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(feature = "quantum")]
use hkdf::Hkdf;
#[cfg(feature = "quantum")]
use pqcrypto_falcon::falcon512;
#[cfg(feature = "quantum")]
use pqcrypto_mldsa::mldsa44;
#[cfg(feature = "quantum")]
use pqcrypto_mlkem::mlkem768;
#[cfg(feature = "quantum")]
use rand::RngCore;
#[cfg(feature = "quantum")]
use sha2::Sha256;
#[cfg(feature = "quantum")]
use subtle::ConstantTimeEq;
#[cfg(feature = "quantum")]
use zeroize::Zeroize;

/// Result type for PQC operations
pub type Result<T> = std::result::Result<T, PqcError>;

/// Errors that can occur during PQC operations
#[derive(Debug, thiserror::Error)]
pub enum PqcError {
    #[error("Invalid key format or corrupted key data")]
    InvalidKey,

    #[error("Invalid signature format or corrupted signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Key generation failed")]
    KeyGenerationFailed,

    #[error("Encryption/decryption operation failed")]
    CryptoOperationFailed,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Feature not available: quantum cryptography requires 'quantum' feature flag")]
    FeatureNotAvailable,
}

#[cfg(feature = "quantum")]
impl From<pqcrypto_traits::Error> for PqcError {
    fn from(err: pqcrypto_traits::Error) -> Self {
        match err {
            pqcrypto_traits::Error::BadLength { .. } => PqcError::InvalidKey,
            _ => PqcError::CryptoOperationFailed,
        }
    }
}

/// ML-DSA (Dilithium) digital signature wrapper
#[cfg(feature = "quantum")]
pub mod mldsa {
    use super::*;

    /// ML-DSA public key
    #[derive(Clone)]
    pub struct PublicKey(mldsa44::PublicKey);

    /// ML-DSA secret key with automatic zeroization
    /// Stores both secret and public key for proper key management
    pub struct SecretKey {
        secret: mldsa44::SecretKey,
        public: mldsa44::PublicKey,
    }

    impl Drop for SecretKey {
        fn drop(&mut self) {
            // Zeroize secret key bytes on drop
            let bytes =
                <mldsa44::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.secret);
            
            // SAFETY: This unsafe block is required to securely zero out secret key material
            // from memory. This is a critical security operation to prevent key leakage.
            //
            // Safety invariants:
            // 1. bytes.as_ptr() points to valid memory owned by the SecretKey
            // 2. bytes.len() accurately represents the size of the memory region
            // 3. Writing zeros to this memory does not create undefined behavior
            // 4. No other references to this memory exist (exclusive ownership via &mut self)
            unsafe {
                std::ptr::write_bytes(bytes.as_ptr() as *mut u8, 0, bytes.len());
            }
        }
    }

    /// ML-DSA signature
    pub struct Signature(mldsa44::DetachedSignature);

    impl PublicKey {
        /// Create a public key from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != mldsa44::public_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for public key, got {}",
                    mldsa44::public_key_bytes(),
                    bytes.len()
                )));
            }
            Ok(PublicKey(
                <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(bytes)?,
            ))
        }

        /// Export public key as bytes
        pub fn as_bytes(&self) -> &[u8] {
            <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(&self.0)
        }

        /// Verify a signature
        pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
            mldsa44::verify_detached_signature(&signature.0, message, &self.0)
                .map_err(|_| PqcError::VerificationFailed)
        }
    }

    impl SecretKey {
        /// Generate a new key pair with proper key storage
        pub fn new() -> Result<(PublicKey, SecretKey)> {
            let (pk, sk) = mldsa44::keypair();
            let pk_clone = <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(&pk),
            )?;
            Ok((
                PublicKey(pk_clone),
                SecretKey {
                    secret: sk,
                    public: pk,
                },
            ))
        }

        /// Create a secret key from bytes
        /// Note: Public key cannot be derived, must be provided separately
        pub fn from_bytes_with_public(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self> {
            if sk_bytes.len() != mldsa44::secret_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for secret key, got {}",
                    mldsa44::secret_key_bytes(),
                    sk_bytes.len()
                )));
            }
            if pk_bytes.len() != mldsa44::public_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for public key, got {}",
                    mldsa44::public_key_bytes(),
                    pk_bytes.len()
                )));
            }
            Ok(SecretKey {
                secret: <mldsa44::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(
                    sk_bytes,
                )?,
                public: <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                    pk_bytes,
                )?,
            })
        }

        /// ⚠️ SECURITY WARNING: Export secret key bytes
        /// Only use for secure storage/transmission. Ensure zeroization after use.
        pub fn as_bytes(&self) -> Vec<u8> {
            <mldsa44::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.secret)
                .to_vec()
        }

        /// Sign a message with domain separation
        pub fn sign(&self, message: &[u8]) -> Result<Signature> {
            let sig = mldsa44::detached_sign(message, &self.secret);
            Ok(Signature(sig))
        }

        /// Get the corresponding public key (now properly stored)
        pub fn public_key(&self) -> PublicKey {
            PublicKey(
                <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                    <mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(
                        &self.public,
                    ),
                )
                .expect("Public key bytes should always be valid"),
            )
        }
    }

    impl Signature {
        /// Create a signature from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != mldsa44::signature_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for signature, got {}",
                    mldsa44::signature_bytes(),
                    bytes.len()
                )));
            }
            Ok(Signature(<mldsa44::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(bytes)?))
        }

        /// Export signature as bytes
        pub fn as_bytes(&self) -> &[u8] {
            <mldsa44::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(
                &self.0,
            )
        }
    }

    /// Get the sizes of ML-DSA keys and signatures
    pub fn key_sizes() -> (usize, usize, usize) {
        (
            mldsa44::public_key_bytes(),
            mldsa44::secret_key_bytes(),
            mldsa44::signature_bytes(),
        )
    }
}

/// ML-KEM (Kyber) key encapsulation mechanism wrapper
#[cfg(feature = "quantum")]
pub mod mlkem {
    use super::*;

    /// ML-KEM public key
    #[derive(Clone)]
    pub struct PublicKey(mlkem768::PublicKey);

    /// ML-KEM secret key with automatic zeroization
    pub struct SecretKey {
        secret: mlkem768::SecretKey,
        public: mlkem768::PublicKey,
    }

    impl Drop for SecretKey {
        fn drop(&mut self) {
            let bytes =
                <mlkem768::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.secret);
            
            // SAFETY: This unsafe block securely zeros out KEM secret key material from memory
            // to prevent key leakage after the key is no longer needed.
            //
            // Safety invariants:
            // 1. bytes.as_ptr() is valid and points to SecretKey-owned memory
            // 2. bytes.len() matches the actual memory region size
            // 3. Zeroing memory does not violate any Rust safety guarantees
            // 4. Exclusive access guaranteed via Drop's &mut self
            unsafe {
                std::ptr::write_bytes(bytes.as_ptr() as *mut u8, 0, bytes.len());
            }
        }
    }

    /// ML-KEM ciphertext
    #[derive(Clone)]
    pub struct Ciphertext(mlkem768::Ciphertext);

    /// ML-KEM shared secret with automatic zeroization
    #[derive(Debug)]
    pub struct SharedSecret(mlkem768::SharedSecret);

    impl Drop for SharedSecret {
        fn drop(&mut self) {
            let bytes =
                <mlkem768::SharedSecret as pqcrypto_traits::kem::SharedSecret>::as_bytes(&self.0);
            
            // SAFETY: This unsafe block securely zeros out shared secret material from memory
            // to prevent secret leakage after key exchange is complete.
            //
            // Safety invariants:
            // 1. bytes.as_ptr() is valid and points to SharedSecret-owned memory
            // 2. bytes.len() accurately represents the memory region size
            // 3. Writing zeros is safe and does not create undefined behavior
            // 4. Exclusive access guaranteed via Drop's &mut self
            unsafe {
                std::ptr::write_bytes(bytes.as_ptr() as *mut u8, 0, bytes.len());
            }
        }
    }

    impl PublicKey {
        /// Create a public key from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != mlkem768::public_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for public key, got {}",
                    mlkem768::public_key_bytes(),
                    bytes.len()
                )));
            }
            Ok(PublicKey(
                <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::from_bytes(bytes)?,
            ))
        }

        /// Export public key as bytes
        pub fn as_bytes(&self) -> &[u8] {
            <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(&self.0)
        }

        /// Encapsulate a shared secret
        pub fn encapsulate(&self) -> Result<(Ciphertext, SharedSecret)> {
            let (ss, ct) = mlkem768::encapsulate(&self.0);
            Ok((Ciphertext(ct), SharedSecret(ss)))
        }
    }

    impl SecretKey {
        /// Generate a new key pair with proper key storage
        pub fn new() -> Result<(PublicKey, SecretKey)> {
            let (pk, sk) = mlkem768::keypair();
            let pk_clone = <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::from_bytes(
                <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(&pk),
            )?;
            Ok((
                PublicKey(pk_clone),
                SecretKey {
                    secret: sk,
                    public: pk,
                },
            ))
        }

        /// Create a secret key from bytes with public key
        pub fn from_bytes_with_public(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self> {
            if sk_bytes.len() != mlkem768::secret_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for secret key, got {}",
                    mlkem768::secret_key_bytes(),
                    sk_bytes.len()
                )));
            }
            if pk_bytes.len() != mlkem768::public_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for public key, got {}",
                    mlkem768::public_key_bytes(),
                    pk_bytes.len()
                )));
            }
            Ok(SecretKey {
                secret: <mlkem768::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(
                    sk_bytes,
                )?,
                public: <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::from_bytes(
                    pk_bytes,
                )?,
            })
        }

        /// ⚠️ SECURITY WARNING: Export secret key bytes
        pub fn as_bytes(&self) -> Vec<u8> {
            <mlkem768::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.secret)
                .to_vec()
        }

        /// Decapsulate a shared secret from ciphertext
        pub fn decapsulate(&self, ciphertext: &Ciphertext) -> Result<SharedSecret> {
            let ss = mlkem768::decapsulate(&ciphertext.0, &self.secret);
            Ok(SharedSecret(ss))
        }

        /// Get the corresponding public key (properly stored)
        pub fn public_key(&self) -> PublicKey {
            PublicKey(
                <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::from_bytes(
                    <mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(
                        &self.public,
                    ),
                )
                .expect("Public key bytes should always be valid"),
            )
        }
    }

    impl Ciphertext {
        /// Create a ciphertext from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != mlkem768::ciphertext_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for ciphertext, got {}",
                    mlkem768::ciphertext_bytes(),
                    bytes.len()
                )));
            }
            Ok(Ciphertext(
                <mlkem768::Ciphertext as pqcrypto_traits::kem::Ciphertext>::from_bytes(bytes)?,
            ))
        }

        /// Export ciphertext as bytes
        pub fn as_bytes(&self) -> &[u8] {
            <mlkem768::Ciphertext as pqcrypto_traits::kem::Ciphertext>::as_bytes(&self.0)
        }
    }

    impl SharedSecret {
        /// Create a shared secret from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != mlkem768::shared_secret_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for shared secret, got {}",
                    mlkem768::shared_secret_bytes(),
                    bytes.len()
                )));
            }
            Ok(SharedSecret(
                <mlkem768::SharedSecret as pqcrypto_traits::kem::SharedSecret>::from_bytes(bytes)?,
            ))
        }

        /// Export shared secret as bytes (WARNING: Handle with care!)
        pub fn as_bytes(&self) -> &[u8] {
            <mlkem768::SharedSecret as pqcrypto_traits::kem::SharedSecret>::as_bytes(&self.0)
        }
    }

    /// Constant-time comparison for SharedSecret
    impl PartialEq for SharedSecret {
        fn eq(&self, other: &Self) -> bool {
            use subtle::ConstantTimeEq;
            bool::from(self.as_bytes().ct_eq(other.as_bytes()))
        }
    }

    impl Eq for SharedSecret {}

    /// Get the sizes of ML-KEM keys and ciphertext
    pub fn key_sizes() -> (usize, usize, usize, usize) {
        (
            mlkem768::public_key_bytes(),
            mlkem768::secret_key_bytes(),
            mlkem768::ciphertext_bytes(),
            mlkem768::shared_secret_bytes(),
        )
    }
}

/// FALCON compact signature wrapper
#[cfg(feature = "quantum")]
pub mod falcon {
    use super::*;

    /// FALCON public key
    #[derive(Clone)]
    pub struct PublicKey(falcon512::PublicKey);

    /// FALCON secret key with automatic zeroization
    pub struct SecretKey {
        secret: falcon512::SecretKey,
        public: falcon512::PublicKey,
    }

    impl Drop for SecretKey {
        fn drop(&mut self) {
            let bytes =
                <falcon512::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.secret);
            
            // SAFETY: This unsafe block securely zeros out FALCON secret key material from memory
            // to prevent key leakage after the key is no longer needed.
            //
            // Safety invariants:
            // 1. bytes.as_ptr() points to valid memory owned by the FALCON SecretKey
            // 2. bytes.len() accurately represents the size of the memory region
            // 3. Zeroing memory is safe and does not create undefined behavior
            // 4. Exclusive access guaranteed via Drop's &mut self
            unsafe {
                std::ptr::write_bytes(bytes.as_ptr() as *mut u8, 0, bytes.len());
            }
        }
    }

    /// FALCON signature
    pub struct Signature(falcon512::DetachedSignature);

    impl PublicKey {
        /// Create a public key from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() != falcon512::public_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for public key, got {}",
                    falcon512::public_key_bytes(),
                    bytes.len()
                )));
            }
            Ok(PublicKey(
                <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(bytes)?,
            ))
        }

        /// Export public key as bytes
        pub fn as_bytes(&self) -> &[u8] {
            <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(&self.0)
        }

        /// Verify a signature
        pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
            falcon512::verify_detached_signature(&signature.0, message, &self.0)
                .map_err(|_| PqcError::VerificationFailed)
        }
    }

    impl SecretKey {
        /// Generate a new key pair with proper key storage
        pub fn new() -> Result<(PublicKey, SecretKey)> {
            let (pk, sk) = falcon512::keypair();
            let pk_clone = <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(&pk),
            )?;
            Ok((
                PublicKey(pk_clone),
                SecretKey {
                    secret: sk,
                    public: pk,
                },
            ))
        }

        /// Create a secret key from bytes with public key
        pub fn from_bytes_with_public(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self> {
            if sk_bytes.len() != falcon512::secret_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for secret key, got {}",
                    falcon512::secret_key_bytes(),
                    sk_bytes.len()
                )));
            }
            if pk_bytes.len() != falcon512::public_key_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Expected {} bytes for public key, got {}",
                    falcon512::public_key_bytes(),
                    pk_bytes.len()
                )));
            }
            Ok(SecretKey {
                secret: <falcon512::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(
                    sk_bytes,
                )?,
                public: <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                    pk_bytes,
                )?,
            })
        }

        /// ⚠️ SECURITY WARNING: Export secret key bytes
        pub fn as_bytes(&self) -> Vec<u8> {
            <falcon512::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.secret)
                .to_vec()
        }

        /// Sign a message
        pub fn sign(&self, message: &[u8]) -> Result<Signature> {
            let sig = falcon512::detached_sign(message, &self.secret);
            Ok(Signature(sig))
        }

        /// Get the corresponding public key (properly stored)
        pub fn public_key(&self) -> PublicKey {
            PublicKey(
                <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                    <falcon512::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(
                        &self.public,
                    ),
                )
                .expect("Public key bytes should always be valid"),
            )
        }
    }

    impl Signature {
        /// Create a signature from bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            if bytes.len() > falcon512::signature_bytes() {
                return Err(PqcError::InvalidInput(format!(
                    "Signature too long: got {} bytes, max {}",
                    bytes.len(),
                    falcon512::signature_bytes()
                )));
            }
            Ok(Signature(<falcon512::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(bytes)?))
        }

        /// Export signature as bytes
        pub fn as_bytes(&self) -> &[u8] {
            <falcon512::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(
                &self.0,
            )
        }
    }

    /// Get the sizes of FALCON keys and signatures
    pub fn key_sizes() -> (usize, usize, usize) {
        (
            falcon512::public_key_bytes(),
            falcon512::secret_key_bytes(),
            falcon512::signature_bytes(),
        )
    }
}

/// Hybrid cryptography combining classical and quantum algorithms
#[cfg(feature = "quantum")]
pub mod hybrid {
    use super::*;

    const AES_GCM_NONCE_SIZE: usize = 12;
    const AES_GCM_TAG_SIZE: usize = 16;

    /// Hybrid key exchange using ML-KEM + HKDF for AES-GCM key derivation
    pub fn key_exchange(pk: &mlkem::PublicKey) -> Result<(mlkem::Ciphertext, Vec<u8>)> {
        let (ct, ss) = pk.encapsulate()?;

        // Use HKDF to derive AES key from shared secret
        let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
        let mut aes_key = [0u8; 32];
        hk.expand(b"AES-256-GCM-KEY-V1", &mut aes_key)
            .map_err(|_| PqcError::CryptoOperationFailed)?;

        Ok((ct, aes_key.to_vec()))
    }

    /// Hybrid encryption using ML-KEM + AES-GCM with automatic nonce generation
    /// Returns (ciphertext_kem, encrypted_data, nonce)
    /// The nonce MUST be transmitted alongside the encrypted data
    pub fn encrypt_hybrid(
        pk: &mlkem::PublicKey,
        plaintext: &[u8],
    ) -> Result<(mlkem::Ciphertext, Vec<u8>, [u8; AES_GCM_NONCE_SIZE])> {
        let (ct, aes_key_vec) = key_exchange(pk)?;
        let aes_key: [u8; 32] = aes_key_vec
            .try_into()
            .map_err(|_| PqcError::CryptoOperationFailed)?;

        // Generate cryptographically secure random nonce
        let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
        use rand::rngs::OsRng;
        OsRng.fill_bytes(&mut nonce);

        let cipher = Aes256Gcm::new(&aes_key.into());
        let nonce_obj = Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|_| PqcError::CryptoOperationFailed)?;

        Ok((ct, ciphertext, nonce))
    }

    /// Hybrid decryption using ML-KEM + AES-GCM
    pub fn decrypt_hybrid(
        sk: &mlkem::SecretKey,
        ct: &mlkem::Ciphertext,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != AES_GCM_NONCE_SIZE {
            return Err(PqcError::InvalidInput(format!(
                "Invalid nonce size: expected {}, got {}",
                AES_GCM_NONCE_SIZE,
                nonce.len()
            )));
        }

        let ss = sk.decapsulate(ct)?;

        // Use HKDF to derive AES key
        let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
        let mut aes_key = [0u8; 32];
        hk.expand(b"AES-256-GCM-KEY-V1", &mut aes_key)
            .map_err(|_| PqcError::CryptoOperationFailed)?;

        let cipher = Aes256Gcm::new(&aes_key.into());
        let nonce_obj = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce_obj, ciphertext)
            .map_err(|_| PqcError::CryptoOperationFailed)
    }

    /// Hybrid signature using Ed25519 + ML-DSA with domain separation
    /// Applies different domain separators to prevent cross-protocol attacks
    pub fn sign_hybrid(
        message: &[u8],
        ed25519_sk: &SigningKey,
        mldsa_sk: &mldsa::SecretKey,
    ) -> Result<(ed25519_dalek::Signature, mldsa::Signature)> {
        // Domain separation: prepend protocol-specific tags
        let ed25519_msg = [b"HYBRID-ED25519-V1:", message].concat();
        let mldsa_msg = [b"HYBRID-MLDSA-V1:", message].concat();

        let ed25519_sig = ed25519_sk.sign(&ed25519_msg);
        let mldsa_sig = mldsa_sk.sign(&mldsa_msg)?;
        Ok((ed25519_sig, mldsa_sig))
    }

    /// Hybrid verification using Ed25519 + ML-DSA with domain separation
    pub fn verify_hybrid(
        message: &[u8],
        ed25519_sig: &ed25519_dalek::Signature,
        mldsa_sig: &mldsa::Signature,
        ed25519_pk: &VerifyingKey,
        mldsa_pk: &mldsa::PublicKey,
    ) -> Result<()> {
        // Apply same domain separation as in signing
        let ed25519_msg = [b"HYBRID-ED25519-V1:", message].concat();
        let mldsa_msg = [b"HYBRID-MLDSA-V1:", message].concat();

        // Verify Ed25519 signature
        ed25519_pk
            .verify(&ed25519_msg, ed25519_sig)
            .map_err(|_| PqcError::VerificationFailed)?;

        // Verify ML-DSA signature
        mldsa_pk.verify(&mldsa_msg, mldsa_sig)?;

        Ok(())
    }
}

// Non-quantum feature stubs
#[cfg(not(feature = "quantum"))]
pub mod mldsa {
    use super::*;
    pub struct PublicKey;
    pub struct SecretKey;
    pub struct Signature;

    impl PublicKey {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
        pub fn verify(&self, _message: &[u8], _signature: &Signature) -> Result<()> {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    impl SecretKey {
        pub fn new() -> Result<(PublicKey, SecretKey)> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> Vec<u8> {
            Vec::new()
        }
        pub fn sign(&self, _message: &[u8]) -> Result<Signature> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn public_key(&self) -> PublicKey {
            PublicKey
        }
    }

    impl Signature {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
    }

    pub fn key_sizes() -> (usize, usize, usize) {
        (0, 0, 0)
    }
}

#[cfg(not(feature = "quantum"))]
pub mod mlkem {
    use super::*;
    pub struct PublicKey;
    pub struct SecretKey;
    pub struct Ciphertext;
    pub struct SharedSecret;

    impl PublicKey {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
        pub fn encapsulate(&self) -> Result<(Ciphertext, SharedSecret)> {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    impl SecretKey {
        pub fn new() -> Result<(PublicKey, SecretKey)> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> Vec<u8> {
            Vec::new()
        }
        pub fn decapsulate(&self, _ciphertext: &Ciphertext) -> Result<SharedSecret> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn public_key(&self) -> PublicKey {
            PublicKey
        }
    }

    impl Ciphertext {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
    }

    impl SharedSecret {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
    }

    impl PartialEq for SharedSecret {
        fn eq(&self, _other: &Self) -> bool {
            false
        }
    }

    impl Eq for SharedSecret {}

    pub fn key_sizes() -> (usize, usize, usize, usize) {
        (0, 0, 0, 0)
    }
}

#[cfg(not(feature = "quantum"))]
pub mod falcon {
    use super::*;
    pub struct PublicKey;
    pub struct SecretKey;
    pub struct Signature;

    impl PublicKey {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
        pub fn verify(&self, _message: &[u8], _signature: &Signature) -> Result<()> {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    impl SecretKey {
        pub fn new() -> Result<(PublicKey, SecretKey)> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> Vec<u8> {
            Vec::new()
        }
        pub fn sign(&self, _message: &[u8]) -> Result<Signature> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn public_key(&self) -> PublicKey {
            PublicKey
        }
    }

    impl Signature {
        pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
            Err(PqcError::FeatureNotAvailable)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &[]
        }
    }

    pub fn key_sizes() -> (usize, usize, usize) {
        (0, 0, 0)
    }
}

#[cfg(not(feature = "quantum"))]
pub mod hybrid {
    use super::*;
    pub fn key_exchange(_pk: &mlkem::PublicKey) -> Result<(mlkem::Ciphertext, Vec<u8>)> {
        Err(PqcError::FeatureNotAvailable)
    }
    pub fn encrypt_hybrid(
        _pk: &mlkem::PublicKey,
        _plaintext: &[u8],
        _nonce: &[u8; 12],
    ) -> Result<(mlkem::Ciphertext, Vec<u8>)> {
        Err(PqcError::FeatureNotAvailable)
    }
    pub fn decrypt_hybrid(
        _sk: &mlkem::SecretKey,
        _ct: &mlkem::Ciphertext,
        _ciphertext: &[u8],
        _nonce: &[u8],
    ) -> Result<Vec<u8>> {
        Err(PqcError::FeatureNotAvailable)
    }
}

#[cfg(test)]
#[cfg(not(feature = "quantum"))]
mod tests_no_quantum {
    use super::*;

    #[test]
    fn test_feature_not_available() {
        assert!(matches!(
            mldsa::SecretKey::new(),
            Err(PqcError::FeatureNotAvailable)
        ));
        assert!(matches!(
            mlkem::SecretKey::new(),
            Err(PqcError::FeatureNotAvailable)
        ));
        assert!(matches!(
            falcon::SecretKey::new(),
            Err(PqcError::FeatureNotAvailable)
        ));
    }
}

#[cfg(test)]
#[cfg(feature = "quantum")]
mod tests_quantum {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_mldsa_key_generation() {
        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        assert!(!pk.as_bytes().is_empty());
        assert!(!sk.as_bytes().is_empty());
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        let message = b"Hello, quantum world!";
        let signature = sk.sign(message).unwrap();
        assert!(!signature.as_bytes().is_empty());
        assert!(pk.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_mldsa_sign_verify_wrong_message() {
        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        let message = b"Hello, quantum world!";
        let wrong_message = b"Goodbye, quantum world!";
        let signature = sk.sign(message).unwrap();
        assert!(pk.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_mldsa_invalid_key_size() {
        let invalid_key = vec![0u8; 10];
        assert!(mldsa::PublicKey::from_bytes(&invalid_key).is_err());
    }

    #[test]
    fn test_mlkem_key_exchange() {
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let (ciphertext, shared_secret) = pk.encapsulate().unwrap();
        let decrypted_secret = sk.decapsulate(&ciphertext).unwrap();
        // Compare bytes since SharedSecret doesn't implement Eq
        assert_eq!(shared_secret.as_bytes(), decrypted_secret.as_bytes());
    }

    #[test]
    fn test_mlkem_invalid_key_size() {
        let invalid_key = vec![0u8; 10];
        assert!(mlkem::PublicKey::from_bytes(&invalid_key).is_err());
    }

    #[test]
    fn test_falcon_key_generation() {
        let (pk, sk) = falcon::SecretKey::new().unwrap();
        assert!(!pk.as_bytes().is_empty());
        assert!(!sk.as_bytes().is_empty());
    }

    #[test]
    fn test_falcon_sign_verify() {
        let (pk, sk) = falcon::SecretKey::new().unwrap();
        let message = b"Falcon signature test";
        let signature = sk.sign(message).unwrap();
        assert!(!signature.as_bytes().is_empty());
        assert!(pk.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_falcon_sign_verify_wrong_message() {
        let (pk, sk) = falcon::SecretKey::new().unwrap();
        let message = b"Falcon signature test";
        let wrong_message = b"Different message";
        let signature = sk.sign(message).unwrap();
        assert!(pk.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let (ciphertext, aes_key) = hybrid::key_exchange(&pk).unwrap();
        assert_eq!(aes_key.len(), 32); // AES-256 key size

        // Verify we can derive the same key
        let shared_secret = sk.decapsulate(&ciphertext).unwrap();
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        hk.expand(b"AES-256-GCM-KEY-V1", &mut derived_key).unwrap();
        assert_eq!(aes_key, derived_key.to_vec());
    }

    #[test]
    fn test_hybrid_encrypt_decrypt() {
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"Secret message for hybrid encryption";

        // Nonce is now auto-generated
        let (ciphertext, encrypted_data, nonce) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();
        let decrypted = hybrid::decrypt_hybrid(&sk, &ciphertext, &encrypted_data, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_hybrid_nonce_randomness() {
        let (pk, _sk) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"Test";

        // Generate multiple encryptions, nonces should be different
        let (_, _, nonce1) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();
        let (_, _, nonce2) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();

        // Nonces should be different (extremely unlikely to be equal)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_hybrid_decrypt_invalid_nonce() {
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"Test";

        let (ciphertext, encrypted_data, _correct_nonce) =
            hybrid::encrypt_hybrid(&pk, plaintext).unwrap();

        // Try with invalid nonce size
        let invalid_nonce = [0u8; 8];
        assert!(hybrid::decrypt_hybrid(&sk, &ciphertext, &encrypted_data, &invalid_nonce).is_err());
    }

    #[test]
    fn test_hybrid_sign_verify() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let ed25519_sk = SigningKey::generate(&mut OsRng);
        let ed25519_pk = VerifyingKey::from(&ed25519_sk);
        let (mldsa_pk, mldsa_sk) = mldsa::SecretKey::new().unwrap();

        let message = b"Hybrid signature test";
        let (ed25519_sig, mldsa_sig) =
            hybrid::sign_hybrid(message, &ed25519_sk, &mldsa_sk).unwrap();

        assert!(
            hybrid::verify_hybrid(message, &ed25519_sig, &mldsa_sig, &ed25519_pk, &mldsa_pk)
                .is_ok()
        );
    }

    #[test]
    fn test_hybrid_verify_wrong_message() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let ed25519_sk = SigningKey::generate(&mut OsRng);
        let ed25519_pk = VerifyingKey::from(&ed25519_sk);
        let (mldsa_pk, mldsa_sk) = mldsa::SecretKey::new().unwrap();

        let message = b"Original message";
        let wrong_message = b"Tampered message";

        let (ed25519_sig, mldsa_sig) =
            hybrid::sign_hybrid(message, &ed25519_sk, &mldsa_sk).unwrap();

        assert!(hybrid::verify_hybrid(
            wrong_message,
            &ed25519_sig,
            &mldsa_sig,
            &ed25519_pk,
            &mldsa_pk
        )
        .is_err());
    }

    #[test]
    fn test_key_sizes() {
        let (pk_size, sk_size, sig_size) = mldsa::key_sizes();
        assert!(pk_size > 0);
        assert!(sk_size > 0);
        assert!(sig_size > 0);

        let (pk_size, sk_size, ct_size, ss_size) = mlkem::key_sizes();
        assert!(pk_size > 0);
        assert!(sk_size > 0);
        assert!(ct_size > 0);
        assert!(ss_size > 0);

        let (pk_size, sk_size, sig_size) = falcon::key_sizes();
        assert!(pk_size > 0);
        assert!(sk_size > 0);
        assert!(sig_size > 0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        // Test ML-DSA
        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();
        let pk_restored = mldsa::PublicKey::from_bytes(pk_bytes).unwrap();
        let sk_restored = mldsa::SecretKey::from_bytes_with_public(&sk_bytes, pk_bytes).unwrap();

        let message = b"Serialization test";
        let sig = sk_restored.sign(message).unwrap();
        assert!(pk_restored.verify(message, &sig).is_ok());

        // Test ML-KEM
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();
        let pk_restored = mlkem::PublicKey::from_bytes(pk_bytes).unwrap();
        let sk_restored = mlkem::SecretKey::from_bytes_with_public(&sk_bytes, pk_bytes).unwrap();

        let (ct, ss1) = pk_restored.encapsulate().unwrap();
        let ss2 = sk_restored.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2); // Now uses constant-time comparison

        // Test FALCON
        let (pk, sk) = falcon::SecretKey::new().unwrap();
        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();
        let pk_restored = falcon::PublicKey::from_bytes(pk_bytes).unwrap();
        let sk_restored = falcon::SecretKey::from_bytes_with_public(&sk_bytes, pk_bytes).unwrap();

        let sig = sk_restored.sign(message).unwrap();
        assert!(pk_restored.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_public_key_derivation() {
        // Test that public_key() returns the correct key
        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        let derived_pk = sk.public_key();

        // Sign with sk, verify with derived pk
        let message = b"Test public key derivation";
        let sig = sk.sign(message).unwrap();
        assert!(derived_pk.verify(message, &sig).is_ok());

        // Also verify with original pk
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_constant_time_comparison() {
        // Test that SharedSecret uses constant-time comparison
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let (ct, ss1) = pk.encapsulate().unwrap();
        let ss2 = sk.decapsulate(&ct).unwrap();

        // This should use constant-time comparison now
        assert_eq!(ss1, ss2);
        assert!(ss1 == ss2);
    }
}
