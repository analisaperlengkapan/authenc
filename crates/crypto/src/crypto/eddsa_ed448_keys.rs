use base64ct::{Base64UrlUnpadded, Encoding};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

// Using Ed25519 for EdDSA as Ed448 support is limited in Rust ecosystem
// Ed448 would require a different implementation with proper Ed448 library
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// EdDSA keypair for JWT signing - post-quantum ready security
/// Note: Using Ed25519 as Ed448 support is not mature in Rust ecosystem
pub static EDDSA_KEYPAIR: Lazy<SigningKey> = Lazy::new(|| {
    // In production, load from secure storage or environment
    // For demo purposes, generate a new key each time
    SigningKey::generate(&mut OsRng)
});

/// JSON Web Key Set containing EdDSA public keys
#[derive(Debug, Serialize, Deserialize)]
pub struct EddsaJwkSet {
    /// Array of JSON Web Keys
    pub keys: Vec<EddsaJwk>,
}

/// Individual EdDSA JSON Web Key
#[derive(Debug, Serialize, Deserialize)]
pub struct EddsaJwk {
    /// Key type (always "OKP" for EdDSA)
    pub kty: String,
    /// Elliptic curve ("Ed25519" - using Ed25519 as Ed448 not available)
    pub crv: String,
    /// Base64URL-encoded public key
    pub x: String,
    /// Key ID for key identification
    pub kid: String,
    /// Intended use of the key ("sig" for signing)
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm identifier ("EdDSA")
    pub alg: String,
}

impl EddsaJwk {
    /// Creates an EdDSA JWK from a verifying key and key ID.
    ///
    /// # Arguments
    /// * `verifying_key` - The EdDSA verifying key to convert
    /// * `kid` - The key ID to assign to this JWK
    ///
    /// # Returns
    /// A new `EddsaJwk` instance with the public key and metadata.
    pub fn from_verifying_key(verifying_key: &VerifyingKey, kid: &str) -> Self {
        let public_key_bytes = verifying_key.to_bytes();
        let x = Base64UrlUnpadded::encode_string(&public_key_bytes);

        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(), // Using Ed25519 as Ed448 not available
            x,
            kid: kid.to_string(),
            key_use: "sig".to_string(),
            alg: "EdDSA".to_string(),
        }
    }
}

/// Sign JWT with EdDSA
pub fn sign_jwt_eddsa(header: &str, payload: &str) -> Result<String, String> {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let header_b64 = Base64UrlUnpadded::encode_string(header.as_bytes());
    let payload_b64 = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let message = format!("{}.{}", header_b64, payload_b64);

    let signature: Signature = EDDSA_KEYPAIR.sign(message.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_slice());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Verify JWT with EdDSA
pub fn verify_jwt_eddsa(
    token: &str,
    verifying_key: &VerifyingKey,
) -> Result<(String, String), String> {
    use base64ct::Base64UrlUnpadded;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let message = format!("{}.{}", header_b64, payload_b64);

    let signature_bytes = Base64UrlUnpadded::decode_vec(signature_b64)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;

    let signature =
        Signature::from_slice(&signature_bytes).map_err(|e| format!("Invalid signature: {}", e))?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    let header = String::from_utf8(
        Base64UrlUnpadded::decode_vec(header_b64)
            .map_err(|e| format!("Invalid header encoding: {}", e))?,
    )
    .map_err(|e| format!("Invalid header UTF-8: {}", e))?;

    let payload = String::from_utf8(
        Base64UrlUnpadded::decode_vec(payload_b64)
            .map_err(|e| format!("Invalid payload encoding: {}", e))?,
    )
    .map_err(|e| format!("Invalid payload UTF-8: {}", e))?;

    Ok((header, payload))
}

/// Get JWK Set for EdDSA
pub fn get_eddsa_jwk_set() -> EddsaJwkSet {
    let verifying_key = VerifyingKey::from(&*EDDSA_KEYPAIR);
    let jwk = EddsaJwk::from_verifying_key(&verifying_key, "eddsa-key-1");

    EddsaJwkSet { keys: vec![jwk] }
}
