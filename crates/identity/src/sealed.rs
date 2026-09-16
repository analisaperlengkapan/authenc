//! Authenticated encryption for secrets that must live in the database.
//!
//! Two subsystems need the same thing: a value the server must be able to read
//! back in full, but which a database disclosure alone must not yield. OAuth
//! signing keys are one ([`crate::sealed`] is used by `authenc-oauth`); TOTP
//! shared secrets are the other. Both are sealed with AES-256-GCM under a
//! key-encryption key that comes from configuration and is never written down
//! anywhere the database can reach.
//!
//! # Why this is not the password treatment
//!
//! A password is verified, never recovered, so it is hashed with Argon2id and
//! the plaintext is gone forever. These values have to come *back* — you cannot
//! check a TOTP code against a hash of the shared secret, and you cannot sign
//! with a hash of a private key — so hashing is not an option and encryption is
//! the only honest answer.
//!
//! # Associated data is not optional
//!
//! Every call binds the row's own identity in as AAD. Without it, a ciphertext
//! copied from one row to another still decrypts, which turns a write anywhere
//! in the table into a way to make the server use the wrong secret. With it,
//! a moved ciphertext fails to open — loudly, at the point of use.

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use authenc_contract::{AppError, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Bytes in the key-encryption key.
pub const MASTER_KEY_BYTES: usize = 32;

/// Bytes in a GCM nonce.
pub const NONCE_BYTES: usize = 12;

/// The key-encryption key that protects stored secrets.
///
/// Kept as its own type so it cannot be confused with a signing key or a
/// session token, and so its `Debug` can be redacted.
#[derive(Clone)]
pub struct MasterKey([u8; MASTER_KEY_BYTES]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([redacted])")
    }
}

impl MasterKey {
    /// Parse a base64url-encoded 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns a validation error if the value is not 32 bytes once decoded.
    /// Rejecting a short key here rather than padding it is the point: a
    /// truncated key would silently weaken every secret stored under it.
    pub fn from_base64(value: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|_| AppError::validation("master key is not valid base64url"))?;

        let bytes: [u8; MASTER_KEY_BYTES] = bytes.try_into().map_err(|_| {
            AppError::validation(format!(
                "master key must decode to exactly {MASTER_KEY_BYTES} bytes"
            ))
        })?;

        Ok(Self(bytes))
    }

    /// Generate a fresh key, for `authenc generate-master-key`.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the OS entropy source fails.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; MASTER_KEY_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|e| AppError::internal_from("generating master key", e))?;
        Ok(Self(bytes))
    }

    /// Render for configuration.
    #[must_use]
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.0))
    }
}

/// A sealed value, as it is stored: ciphertext plus the nonce that produced it.
///
/// Both halves go in the same row. The nonce is not secret — it must simply
/// never repeat under one key, which [`seal`] guarantees by drawing 96 fresh
/// bits from the OS CSPRNG for every call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The encrypted value, with GCM's authentication tag appended.
    pub ciphertext: Vec<u8>,
    /// The nonce this ciphertext was produced under.
    pub nonce: [u8; NONCE_BYTES],
}

/// Seal a value under the master key, binding `aad` to the result.
///
/// `aad` must identify the row the ciphertext belongs to — a `kid`, a
/// credential id — so that moving the ciphertext elsewhere breaks it.
///
/// # Errors
///
/// Returns an internal error if entropy is unavailable or encryption fails.
pub fn seal(master: &MasterKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|e| AppError::internal_from("generating nonce", e))?;

    let ciphertext = master
        .cipher()
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // The error carries no detail worth surfacing, and what detail it has
        // is about the key.
        .map_err(|_| AppError::internal("sealing a stored secret"))?;

    Ok(Sealed { ciphertext, nonce })
}

/// Open a value sealed by [`seal`] with the same `aad`.
///
/// `what` names the secret for the error message an operator will read.
///
/// # Errors
///
/// Returns an internal error if the nonce is malformed, or if the ciphertext
/// does not authenticate — which means the master key is wrong, the AAD does
/// not match, or the row has been tampered with. All three are reported the
/// same way because the caller cannot tell them apart and must not guess.
pub fn open(
    master: &MasterKey,
    aad: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    what: &'static str,
) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_BYTES] = nonce
        .try_into()
        .map_err(|_| AppError::internal("stored nonce has the wrong length"))?;

    master
        .cipher()
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            // Almost always the wrong master key. Say so, because the
            // alternative reading — "the database is corrupt" — sends an
            // operator down the wrong path.
            AppError::internal(format!(
                "could not decrypt {what}; the configured master key does not \
                 match the one it was stored under"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_to_what_went_in() {
        let master = MasterKey::generate().unwrap();
        let sealed = seal(&master, b"row-1", b"the secret").unwrap();

        let opened = open(
            &master,
            b"row-1",
            &sealed.ciphertext,
            &sealed.nonce,
            "the test value",
        )
        .unwrap();

        assert_eq!(opened, b"the secret");
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let master = MasterKey::generate().unwrap();
        let sealed = seal(&master, b"row-1", b"the secret").unwrap();
        assert!(
            !sealed
                .ciphertext
                .windows(b"the secret".len())
                .any(|w| w == b"the secret"),
        );
    }

    #[test]
    fn a_different_master_key_cannot_open_it() {
        let sealed = seal(&MasterKey::generate().unwrap(), b"row-1", b"the secret").unwrap();
        let other = MasterKey::generate().unwrap();

        assert!(
            open(
                &other,
                b"row-1",
                &sealed.ciphertext,
                &sealed.nonce,
                "the test value",
            )
            .is_err(),
        );
    }

    #[test]
    fn a_ciphertext_moved_to_another_row_does_not_open() {
        // The whole reason AAD is mandatory here: without it, copying this
        // ciphertext onto a different row would make the server read the wrong
        // secret and never notice.
        let master = MasterKey::generate().unwrap();
        let sealed = seal(&master, b"row-1", b"the secret").unwrap();

        assert!(
            open(
                &master,
                b"row-2",
                &sealed.ciphertext,
                &sealed.nonce,
                "the test value",
            )
            .is_err(),
        );
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let master = MasterKey::generate().unwrap();
        let mut sealed = seal(&master, b"row-1", b"the secret").unwrap();
        sealed.ciphertext[0] ^= 0x01;

        assert!(
            open(
                &master,
                b"row-1",
                &sealed.ciphertext,
                &sealed.nonce,
                "the test value",
            )
            .is_err(),
        );
    }

    #[test]
    fn sealing_the_same_value_twice_gives_different_ciphertexts() {
        // A repeated nonce under one key is catastrophic for GCM. Fresh
        // entropy per call is what prevents it, and this is the test that
        // notices if someone "optimises" that away.
        let master = MasterKey::generate().unwrap();
        let first = seal(&master, b"row-1", b"the secret").unwrap();
        let second = seal(&master, b"row-1", b"the secret").unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_master_key_round_trips_through_base64() {
        let key = MasterKey::generate().unwrap();
        let parsed = MasterKey::from_base64(&key.to_base64()).unwrap();
        assert_eq!(key.to_base64(), parsed.to_base64());
    }

    #[test]
    fn a_short_or_malformed_master_key_is_refused() {
        assert!(MasterKey::from_base64("").is_err());
        assert!(MasterKey::from_base64("too-short").is_err());
        assert!(MasterKey::from_base64("!!! not base64 !!!").is_err());
        // 31 bytes: close enough to look right, weak enough to matter.
        assert!(MasterKey::from_base64(&URL_SAFE_NO_PAD.encode([7u8; 31])).is_err());
    }

    #[test]
    fn debug_never_prints_the_key() {
        let key = MasterKey::generate().unwrap();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "MasterKey([redacted])");
        assert!(!rendered.contains(&key.to_base64()));
    }
}
