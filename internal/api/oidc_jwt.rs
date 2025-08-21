use rsa::pkcs8::EncodePrivateKey;
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use crate::api::oidc_keys::RSA_KEYPAIR;
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub email: Option<String>,
    pub name: Option<String>,
}

pub fn generate_id_token(sub: &str, aud: &str, email: Option<&str>, name: Option<&str>) -> String {
    let now = Utc::now().timestamp() as usize;
    let claims = OidcIdTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: now + 3600,
        iat: now,
        email: email.map(|e| e.to_string()),
        name: name.map(|n| n.to_string()),
    };
    let der = RSA_KEYPAIR.to_pkcs8_der().unwrap();
    let key = EncodingKey::from_rsa_der(der.as_bytes());
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("authence-demo-key".to_string());
    encode(&header, &claims, &key).unwrap()
}
