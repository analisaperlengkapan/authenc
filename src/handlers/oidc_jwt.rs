// Legacy RSA implementation - DEPRECATED
// Replaced with Ed25519 in handlers/oidc_ed25519.rs for security
// use crate::handlers::oidc_keys::RSA_KEYPAIR;
use serde::{Deserialize, Serialize};
use chrono::Utc;
// use rsa::pkcs1::EncodeRsaPrivateKey; // REMOVED: Vulnerable to timing attacks

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<String>,
}

pub fn generate_id_token(
    sub: &str,
    aud: &str,
    email: Option<&str>,
    name: Option<&str>,
    role: Option<&str>,
) -> String {
    let now = Utc::now().timestamp() as usize;
    let claims = OidcIdTokenClaims {
        iss: "http://localhost:8080/v1".to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp: now + 3600,
        iat: now,
        email: email.map(|e| e.to_string()),
        name: name.map(|n| n.to_string()),
        role: role.map(|r| r.to_string()),
    };
    // DEPRECATED: Legacy RSA implementation removed for security
    // Use handlers/oidc_ed25519.rs for secure Ed25519 JWT signing instead
    panic!("Legacy RSA JWT signing disabled - use Ed25519 implementation")
}
