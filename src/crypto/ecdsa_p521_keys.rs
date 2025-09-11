use base64ct::{Base64UrlUnpadded, Encoding};
use once_cell::sync::Lazy;
use p521::{
    ecdsa::{signature::Signer, signature::Verifier, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// ECDSA P-521 keypair for JWT signing - maximum security for enterprise
pub static ECDSA_P521_KEYPAIR: Lazy<SigningKey> = Lazy::new(|| {
    // In production, load from secure storage or environment
    // For demo purposes, generate a new key each time
    SigningKey::random(&mut OsRng)
});

#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaP521JwkSet {
    pub keys: Vec<EcdsaP521Jwk>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EcdsaP521Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
}

impl EcdsaP521Jwk {
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
