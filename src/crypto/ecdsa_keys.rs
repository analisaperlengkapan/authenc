use base64ct::{Base64UrlUnpadded, Encoding};
use once_cell::sync::Lazy;
use p256::{
    PublicKey, SecretKey,
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// ECDSA P-256 keypair for JWT signing - secure alternative to RSA
pub static ECDSA_KEYPAIR: Lazy<SigningKey> = Lazy::new(|| {
    // In production, load from secure storage or environment
    // For demo purposes, generate a new key each time
    SigningKey::generate()
});

/// JSON Web Key Set containing ECDSA public keys
#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaJwkSet {
    /// Array of JSON Web Keys
    pub keys: Vec<EcdsaJwk>,
}

/// Individual ECDSA JSON Web Key
#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaJwk {
    /// Key type (always "EC" for ECDSA)
    pub kty: String,
    /// Elliptic curve (always "P-256" for ECDSA P-256)
    pub crv: String,
    /// Base64URL-encoded x coordinate of the public key
    pub x: String,
    /// Base64URL-encoded y coordinate of the public key
    pub y: String,
    /// Key ID for key identification
    pub kid: String,
    /// Intended use of the key ("sig" for signing)
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm identifier ("ES256" for ECDSA P-256)
    pub alg: String,
}

impl EcdsaJwk {
    /// Creates an ECDSA JWK from a verifying key and key ID.
    ///
    /// # Arguments
    /// * `verifying_key` - The ECDSA P-256 verifying key to convert
    /// * `kid` - The key ID to assign to this JWK
    ///
    /// # Returns
    /// A new `EcdsaJwk` instance with the public key coordinates and metadata.
    pub fn from_verifying_key(verifying_key: &VerifyingKey, kid: &str) -> Self {
        let public_key = PublicKey::from(verifying_key);
        let encoded_point = public_key.to_encoded_point(false);

        let x = Base64UrlUnpadded::encode_string(encoded_point.x().unwrap());
        let y = Base64UrlUnpadded::encode_string(encoded_point.y().unwrap());

        Self {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
            kid: kid.to_string(),
            key_use: "sig".to_string(),
            alg: "ES256".to_string(),
        }
    }
}

/// Get the ECDSA public key in JWK format
pub fn get_ecdsa_jwk() -> EcdsaJwk {
    let verifying_key = ECDSA_KEYPAIR.verifying_key();
    EcdsaJwk::from_verifying_key(verifying_key, "authence-ecdsa-key")
}

/// Get the ECDSA public key in PEM format
pub fn get_ecdsa_public_pem() -> Result<String, Box<dyn std::error::Error>> {
    let verifying_key = ECDSA_KEYPAIR.verifying_key();
    let public_key = PublicKey::from(verifying_key);
    Ok(public_key.to_public_key_pem(Default::default())?)
}

/// Get the ECDSA private key in PEM format (for testing)
pub fn get_ecdsa_private_pem() -> Result<String, Box<dyn std::error::Error>> {
    let secret_key = SecretKey::from(&*ECDSA_KEYPAIR);
    Ok(secret_key.to_pkcs8_pem(Default::default())?.to_string())
}

/// Sign data with ECDSA P-256 - secure replacement for RSA signing
pub fn sign_ecdsa(data: &[u8]) -> Result<Signature, ecdsa::Error> {
    ECDSA_KEYPAIR.try_sign(data)
}

/// Verify ECDSA signature
pub fn verify_ecdsa(data: &[u8], signature: &Signature) -> Result<(), ecdsa::Error> {
    let verifying_key = ECDSA_KEYPAIR.verifying_key();
    verifying_key.verify(data, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_sign_verify() {
        let data = b"test message";
        let signature = sign_ecdsa(data).unwrap();
        assert!(verify_ecdsa(data, &signature).is_ok());
    }

    #[test]
    fn test_ecdsa_jwk_generation() {
        let jwk = get_ecdsa_jwk();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.alg, "ES256");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
    }

    #[test]
    fn test_ecdsa_pem_generation() {
        let pem = get_ecdsa_public_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn test_ecdsa_private_pem_generation() {
        let pem = get_ecdsa_private_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }
}
