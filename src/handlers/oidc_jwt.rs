// Legacy RSA implementation - DEPRECATED
// Replaced with Ed25519 in handlers/oidc_ed25519.rs for security
// use crate::handlers::oidc_keys::RSA_KEYPAIR;
use chrono::Utc;
use serde::{Deserialize, Serialize};
// use rsa::pkcs1::EncodeRsaPrivateKey; // REMOVED: Vulnerable to timing attacks

/// Legacy OIDC ID token claims structure - DEPRECATED
///
/// This struct is deprecated and should not be used.
/// Use OidcIdTokenClaims from handlers/oidc_ed25519.rs instead.
///
/// # Security Considerations
/// - This legacy implementation uses RSA which is vulnerable to timing attacks
/// - Replaced with Ed25519 for enhanced security
/// - Do not use in production systems
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    /// Issuer identifier (token issuer)
    pub iss: String,
    /// Subject identifier (user ID)
    pub sub: String,
    /// Audience (client ID the token is for)
    pub aud: String,
    /// Expiration timestamp
    pub exp: usize,
    /// Issued at timestamp
    pub iat: usize,
    /// User's email address
    pub email: Option<String>,
    /// User's display name
    pub name: Option<String>,
    /// User's role or authorization level
    pub role: Option<String>,
}

/// Legacy JWT generation function - DEPRECATED
///
/// This function is deprecated and will return an error if called.
/// Use generate_ed25519_jwt from handlers/oidc_ed25519.rs instead.
///
/// # Arguments
/// * `sub` - Subject identifier (user ID)
/// * `aud` - Audience (client ID)
/// * `email` - User's email address
/// * `name` - User's display name
/// * `role` - User's role/authorization level
///
/// # Returns
/// Always returns an error indicating this function is deprecated
///
/// # Security Considerations
/// - Legacy RSA implementation removed due to security vulnerabilities
/// - RSA signatures are susceptible to timing attacks
/// - Use Ed25519 implementation for secure JWT signing
#[deprecated(
    since = "1.0.0",
    note = "Use generate_ed25519_jwt instead - RSA JWT signing is insecure"
)]
pub fn generate_id_token(
    sub: &str,
    aud: &str,
    email: Option<&str>,
    name: Option<&str>,
    role: Option<&str>,
) -> Result<String, String> {
    let now = Utc::now().timestamp() as usize;
    let _claims = OidcIdTokenClaims {
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
    Err("Legacy RSA JWT signing disabled - use Ed25519 implementation (see handlers/oidc_ed25519.rs)".to_string())
}
