//! Opaque secret tokens: session identifiers, reset links, verification links.
//!
//! The pattern is the same for all three. Generate 256 bits from the operating
//! system's CSPRNG, hand the caller the base64url encoding, and persist only
//! the SHA-256 hash. A database disclosure then yields hashes, not live
//! credentials.
//!
//! SHA-256 rather than Argon2 is deliberate and is *not* the reasoning that
//! applies to passwords: these tokens carry full entropy from a CSPRNG, so
//! there is no dictionary to attack and no work factor worth paying on every
//! request.

use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Bytes of entropy in a generated token.
const TOKEN_BYTES: usize = 32;

/// A freshly generated token, in the form given to the client.
///
/// `Debug` is redacted: this value is a live credential for as long as the
/// record it points at exists, and it must not turn up in a log line or a
/// panic message.
#[derive(Clone)]
pub struct SecretToken(String);

impl SecretToken {
    /// Generate a new token from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS entropy source fails. Callers must treat
    /// that as fatal for the request rather than falling back to a weaker
    /// source.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Reconstruct from a value supplied by a client.
    #[must_use]
    pub fn from_client(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value to send to the client — in a cookie, or in a link.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The hash to persist, and to look up by.
    #[must_use]
    pub fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.0.as_bytes()).to_vec()
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretToken([redacted])")
    }
}

/// Compare two byte strings without leaking their contents through timing.
///
/// Used wherever a client-supplied value is checked against a stored one — a
/// CSRF token, for instance — because `==` on slices returns as soon as it
/// finds a difference.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Generate `n` random bytes from the OS CSPRNG.
///
/// # Errors
///
/// Returns an error if the OS entropy source fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_unique() {
        let a = SecretToken::generate().unwrap();
        let b = SecretToken::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn tokens_carry_full_entropy() {
        let token = SecretToken::generate().unwrap();
        // 32 bytes base64url-encoded without padding is 43 characters.
        assert_eq!(token.expose().len(), 43);
        assert!(
            token
                .expose()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "must be URL-safe so it can travel in a cookie or a link",
        );
    }

    #[test]
    fn the_hash_is_stable_and_differs_from_the_token() {
        let token = SecretToken::generate().unwrap();
        assert_eq!(token.hash(), token.hash());
        assert_eq!(token.hash().len(), 32);
        assert_ne!(token.hash(), token.expose().as_bytes());
    }

    #[test]
    fn a_client_supplied_token_hashes_to_the_same_value() {
        // This is what makes lookup-by-hash work: the server stores the hash at
        // creation and recomputes it from the cookie on each request.
        let token = SecretToken::generate().unwrap();
        let echoed = SecretToken::from_client(token.expose());
        assert_eq!(token.hash(), echoed.hash());
    }

    #[test]
    fn debug_output_never_contains_the_token() {
        let token = SecretToken::generate().unwrap();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(token.expose()), "leaked: {rendered}");
    }

    #[test]
    fn constant_time_comparison_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn random_bytes_differ_between_calls() {
        let a = random_bytes::<32>().unwrap();
        let b = random_bytes::<32>().unwrap();
        assert_ne!(a, b);
    }
}
