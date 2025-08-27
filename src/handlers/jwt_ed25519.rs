use crate::crypto::ed25519_keys::{ED25519_KEYPAIR, get_ed25519_jwk};
use crate::utils::crypto_monitor::CryptoMonitor;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use base64ct::{Base64UrlUnpadded, Encoding};

#[derive(Debug, Serialize, Deserialize)]
pub struct Ed25519JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<String>,
}

/// Generate JWT token using Ed25519 - secure replacement for RSA
pub fn generate_ed25519_jwt(
    sub: &str,
    aud: &str,
    email: Option<&str>,
    name: Option<&str>,
    role: Option<&str>,
) -> String {
    let now = Utc::now().timestamp();
    
    let header = Ed25519JwtHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
        kid: "authence-ed25519-key".to_string(),
    };
    
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

    // Monitor Ed25519 operations for security
    CryptoMonitor::monitor_rsa_operation("ed25519_jwt_signing", || {
        // Encode header and payload
        let header_json = serde_json::to_string(&header).unwrap();
        let claims_json = serde_json::to_string(&claims).unwrap();
        
        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(claims_json.as_bytes());
        
        // Create signing input
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        
        // Sign with Ed25519
        let signature: Signature = ED25519_KEYPAIR.sign(signing_input.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());
        
        format!("{}.{}", signing_input, signature_b64)
    })
}

/// Verify Ed25519 JWT token
pub fn verify_ed25519_jwt(token: &str) -> Result<OidcIdTokenClaims, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".into());
    }

    let header_json = String::from_utf8(Base64UrlUnpadded::decode_vec(parts[0])?)?;
    let payload_json = String::from_utf8(Base64UrlUnpadded::decode_vec(parts[1])?)?;
    let signature_bytes = Base64UrlUnpadded::decode_vec(parts[2])?;

    // Verify header algorithm
    let header: Ed25519JwtHeader = serde_json::from_str(&header_json)?;
    if header.alg != "EdDSA" {
        return Err("Invalid algorithm".into());
    }

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = Signature::from_bytes(&signature_bytes.try_into().map_err(|_| "Invalid signature length")?);
    
    let verifying_key = ED25519_KEYPAIR.verifying_key();
    use ed25519_dalek::Verifier;
    verifying_key.verify(signing_input.as_bytes(), &signature)?;

    // Parse and return claims
    let claims: OidcIdTokenClaims = serde_json::from_str(&payload_json)?;
    Ok(claims)
}

/// Get Ed25519 JWKS endpoint response
pub fn get_ed25519_jwks() -> serde_json::Value {
    let jwk = get_ed25519_jwk();
    serde_json::json!({
        "keys": [jwk]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_jwt_generation_and_verification() {
        let token = generate_ed25519_jwt(
            "user123",
            "test-audience",
            Some("user@example.com"),
            Some("Test User"),
            Some("admin"),
        );

        // Token should have 3 parts
        assert_eq!(token.split('.').count(), 3);

        // Should be able to verify the token
        let claims = verify_ed25519_jwt(&token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.aud, "test-audience");
        assert_eq!(claims.email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_ed25519_jwks_generation() {
        let jwks = get_ed25519_jwks();
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert_eq!(key["alg"], "EdDSA");
    }

    #[test]
    fn test_invalid_jwt_verification() {
        let result = verify_ed25519_jwt("invalid.jwt.token");
        assert!(result.is_err());
    }
}
