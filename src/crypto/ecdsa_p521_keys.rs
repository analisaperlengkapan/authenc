use base64ct::{Base64UrlUnpadded, Encoding};
use once_cell::sync::Lazy;
use p521::ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// ECDSA P-521 keypair for JWT signing - maximum security for enterprise
pub static ECDSA_P521_KEYPAIR: Lazy<SigningKey> = Lazy::new(|| {
    // In production, load from secure storage or environment
    // For demo purposes, generate a new key each time
    SigningKey::generate()
});

/// JSON Web Key Set containing ECDSA P-521 public keys
#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaP521JwkSet {
    /// Array of JSON Web Keys
    pub keys: Vec<EcdsaP521Jwk>,
}

/// Individual ECDSA P-521 JSON Web Key
#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaP521Jwk {
    /// Key type (always "EC" for ECDSA)
    pub kty: String,
    /// Elliptic curve (always "P-521" for ECDSA P-521)
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
    /// Algorithm identifier ("ES512" for ECDSA P-521)
    pub alg: String,
}

impl EcdsaP521Jwk {
    /// Creates an ECDSA P-521 JWK from a verifying key and key ID.
    ///
    /// # Arguments
    /// * `verifying_key` - The ECDSA P-521 verifying key to convert
    /// * `kid` - The key ID to assign to this JWK
    ///
    /// # Returns
    /// A new `EcdsaP521Jwk` instance with the public key coordinates and metadata.
    pub fn from_verifying_key(verifying_key: &VerifyingKey, kid: &str) -> Self {
        let encoded_point = verifying_key.to_encoded_point(false);

        let x = Base64UrlUnpadded::encode_string(encoded_point.x().unwrap());
        let y = Base64UrlUnpadded::encode_string(encoded_point.y().unwrap());

        Self {
            kty: "EC".to_string(),
            crv: "P-521".to_string(),
            x,
            y,
            kid: kid.to_string(),
            key_use: "sig".to_string(),
            alg: "ES512".to_string(),
        }
    }
}

/// Sign JWT with ECDSA P-521
pub fn sign_jwt_p521(header: &str, payload: &str) -> Result<String, String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use p521::ecdsa::Signature;

    let header_b64 = Base64UrlUnpadded::encode_string(header.as_bytes());
    let payload_b64 = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let message = format!("{}.{}", header_b64, payload_b64);

    let signature: Signature = ECDSA_P521_KEYPAIR.sign(message.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_slice());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Verify JWT with ECDSA P-521
pub fn verify_jwt_p521(
    token: &str,
    verifying_key: &VerifyingKey,
) -> Result<(String, String), String> {
    use base64ct::Base64UrlUnpadded;
    use p521::ecdsa::Signature;

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

/// Get JWK Set for ECDSA P-521
pub fn get_p521_jwk_set() -> EcdsaP521JwkSet {
    let verifying_key = VerifyingKey::from(&*ECDSA_P521_KEYPAIR);
    let jwk = EcdsaP521Jwk::from_verifying_key(&verifying_key, "p521-key-1");

    EcdsaP521JwkSet { keys: vec![jwk] }
}
