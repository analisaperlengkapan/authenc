use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Ed25519 keypair for JWT signing - replaces vulnerable RSA
pub static ED25519_KEYPAIR: Lazy<SigningKey> = Lazy::new(|| {
    // In production, load from secure storage or environment
    // For demo purposes, generate a new key each time
    SigningKey::generate(&mut OsRng)
});

/// JSON Web Key Set containing Ed25519 public keys
#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519JwkSet {
    /// Array of JSON Web Keys
    pub keys: Vec<Ed25519Jwk>,
}

/// Individual Ed25519 JSON Web Key
#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519Jwk {
    /// Key type (always "OKP" for Ed25519)
    pub kty: String,
    /// Elliptic curve (always "Ed25519")
    pub crv: String,
    /// Base64URL-encoded public key
    pub x: String,
    /// Key ID for key identification
    pub kid: String,
    /// Intended use of the key ("sig" for signing)
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm identifier ("EdDSA" for Ed25519)
    pub alg: String,
}

impl Ed25519Jwk {
    /// Creates an Ed25519 JWK from a verifying key and key ID.
    ///
    /// # Arguments
    /// * `verifying_key` - The Ed25519 verifying key to convert
    /// * `kid` - The key ID to assign to this JWK
    ///
    /// # Returns
    /// A new `Ed25519Jwk` instance with the public key and metadata.
    pub fn from_verifying_key(verifying_key: &VerifyingKey, kid: &str) -> Self {
        let x = Base64UrlUnpadded::encode_string(verifying_key.as_bytes());

        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x,
            kid: kid.to_string(),
            key_use: "sig".to_string(),
            alg: "EdDSA".to_string(),
        }
    }
}

/// Get the Ed25519 public key in JWK format
///
/// # Returns
/// An `Ed25519Jwk` containing the public key from the global keypair
pub fn get_ed25519_jwk() -> Ed25519Jwk {
    let verifying_key = ED25519_KEYPAIR.verifying_key();
    Ed25519Jwk::from_verifying_key(&verifying_key, "authence-ed25519-key")
}

/// Get the Ed25519 public key in PEM format
pub fn get_ed25519_public_pem() -> String {
    let verifying_key = ED25519_KEYPAIR.verifying_key();
    // Ed25519 public key in raw format (32 bytes)
    let raw_bytes = verifying_key.as_bytes();

    // Create PEM format manually since ed25519-dalek doesn't have built-in PEM support
    let b64_data = base64ct::Base64::encode_string(raw_bytes);
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        b64_data
    )
}

/// Sign data with Ed25519 - secure replacement for RSA signing
pub fn sign_ed25519(data: &[u8]) -> Signature {
    ED25519_KEYPAIR.sign(data)
}

/// Verify Ed25519 signature
pub fn verify_ed25519(
    data: &[u8],
    signature: &Signature,
) -> Result<(), ed25519_dalek::SignatureError> {
    let verifying_key = ED25519_KEYPAIR.verifying_key();
    verifying_key.verify(data, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let data = b"test message";
        let signature = sign_ed25519(data);
        assert!(verify_ed25519(data, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_jwk_generation() {
        let jwk = get_ed25519_jwk();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert!(!jwk.x.is_empty());
    }

    #[test]
    fn test_ed25519_pem_generation() {
        let pem = get_ed25519_public_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----"));
    }
}
