use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Import Ed25519 functions
use crate::crypto::ed25519_keys::{ED25519_KEYPAIR, sign_ed25519};
use ed25519_dalek::{Signature, Verifier};

/// JWT claims structure for token payload
///
/// This struct represents the standard JWT claims used in authentication tokens.
/// It contains the essential claims for user identification and token expiration.
///
/// # Fields
/// * `sub` - Subject identifier (typically user ID)
/// * `exp` - Expiration timestamp (Unix timestamp)
/// * `email` - User's email address (optional)
/// * `roles` - User's assigned roles (optional)
///
/// # Security Considerations
/// - The `exp` claim should always be validated to prevent token reuse
/// - The `sub` claim should be validated against authenticated user identity
/// - Additional claims may be needed for more complex authorization scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier (typically the user ID or username)
    pub sub: String,
    /// Token expiration timestamp as Unix timestamp
    pub exp: usize,
    /// User's email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// User's assigned roles
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Session identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

// SECURITY NOTE: JWT signing now uses Ed25519 keypair (see crypto/ed25519_keys.rs)
// Ed25519 provides better security than symmetric signing and is resistant to timing attacks.

/// Generate a JWT token for user authentication using Ed25519
///
/// Creates a signed JWT token with standard claims for the specified user.
/// The token includes subject identifier and expiration time, and is signed
/// using Ed25519 digital signatures - secure replacement for RSA.
///
/// # Arguments
/// * `user_id` - The user identifier to include in the token's subject claim
///
/// # Returns
/// A `Result` containing the JWT token string on success, or an error string on failure
///
/// # Security Considerations
/// - Tokens expire after 1 hour by default
/// - Uses Ed25519 for cryptographic signing (secure replacement for vulnerable RSA)
/// - Ed25519 provides better security than RSA and is resistant to timing attacks
/// - Tokens should be validated on every request
///
/// # Example
/// ```rust
/// use authenc::utils::crypto::jwt::generate_jwt;
///
/// let token = generate_jwt("user123").expect("Failed to generate token");
/// ```
pub fn generate_jwt(user_id: &str) -> Result<String, String> {
    generate_jwt_with_claims(user_id, None, None, None)
}

/// Generate a JWT token with additional claims (email and roles)
///
/// Creates a signed JWT token with extended claims for the specified user.
/// This function allows including email and roles in the token payload.
///
/// # Arguments
/// * `user_id` - The user identifier to include in the token's subject claim
/// * `email` - Optional email address to include in the token
/// * `roles` - Optional list of roles to include in the token
///
/// # Returns
/// A `Result` containing the JWT token string on success, or an error string on failure
pub fn generate_jwt_with_claims(
    user_id: &str,
    email: Option<String>,
    roles: Option<Vec<String>>,
    sid: Option<String>,
) -> Result<String, String> {
    let expiration = SystemTime::now()
        .checked_add(Duration::from_secs(60 * 60))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
        email,
        roles,
        sid,
    };

    // Create JWT header
    let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;

    // Encode header and payload
    let header_b64 = Base64UrlUnpadded::encode_string(header.as_bytes());
    let payload_json =
        serde_json::to_string(&claims).map_err(|e| format!("Failed to serialize claims: {}", e))?;
    let payload_b64 = Base64UrlUnpadded::encode_string(payload_json.as_bytes());

    // Create message to sign
    let message = format!("{}.{}", header_b64, payload_b64);

    // Sign with Ed25519
    let signature = sign_ed25519(message.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());

    // Combine into JWT
    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Verify and decode a JWT token using Ed25519
///
/// Validates the signature and expiration of a JWT token, then extracts the claims.
/// This function performs all standard JWT validation including signature verification,
/// expiration checking, and claim extraction using Ed25519.
///
/// # Arguments
/// * `token` - The JWT token string to verify and decode
///
/// # Returns
/// A `Result` containing the decoded `Claims` on success, or an error string on failure
///
/// # Security Considerations
/// - Always verify tokens before trusting their claims
/// - Check token expiration to prevent replay attacks
/// - Validate Ed25519 signature to ensure token integrity
/// - Handle verification failures gracefully without exposing sensitive information
///
/// # Example
/// ```rust
/// use authenc::utils::crypto::jwt::{generate_jwt, verify_jwt};
///
/// let token = generate_jwt("user123").unwrap();
/// let claims = verify_jwt(&token).expect("Token verification failed");
/// assert_eq!(claims.sub, "user123");
/// ```
pub fn verify_jwt(token: &str) -> Result<Claims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Decode signature
    let signature_bytes = Base64UrlUnpadded::decode_vec(signature_b64)
        .map_err(|e| format!("Invalid signature encoding: {}", e))?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|e| format!("Invalid signature: {}", e))?;

    // Create message for verification
    let message = format!("{}.{}", header_b64, payload_b64);

    // Verify signature with Ed25519
    let verifying_key = ED25519_KEYPAIR.verifying_key();
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    // Decode payload
    let payload_json = String::from_utf8(
        Base64UrlUnpadded::decode_vec(payload_b64)
            .map_err(|e| format!("Invalid payload encoding: {}", e))?,
    )
    .map_err(|e| format!("Invalid payload UTF-8: {}", e))?;

    let claims: Claims =
        serde_json::from_str(&payload_json).map_err(|e| format!("Invalid claims JSON: {}", e))?;

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    if claims.exp < now {
        return Err("Token has expired".to_string());
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::{generate_jwt, verify_jwt};

    #[test]
    fn test_jwt_generation_and_verification() {
        let user_id = "test_user_123";

        // Generate a JWT
        let token = generate_jwt(user_id).expect("Failed to generate JWT");

        // Verify the JWT
        let claims = verify_jwt(&token).expect("Failed to verify JWT");

        // Check that the claims are correct
        assert_eq!(claims.sub, user_id);
        assert!(claims.exp > 0); // Expiration should be set
    }

    #[test]
    fn test_jwt_verification_fails_with_invalid_token() {
        let invalid_token = "invalid.jwt.token";

        // This should fail
        let result = verify_jwt(invalid_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_verification_fails_with_tampered_token() {
        let user_id = "test_user_123";

        // Generate a valid JWT
        let token = generate_jwt(user_id).expect("Failed to generate JWT");

        // Tamper with the token by modifying a character safely
        let mut token_chars: Vec<char> = token.chars().collect();
        if token_chars.len() > 20 {
            token_chars[20] = 'x'; // Change a character
        }
        let tampered_token: String = token_chars.into_iter().collect();

        // This should fail
        let result = verify_jwt(&tampered_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_with_extended_claims() {
        use super::generate_jwt_with_claims;

        let user_id = "test_user_456";
        let email = Some("user@example.com".to_string());
        let roles = Some(vec!["admin".to_string(), "user".to_string()]);
        let sid = Some("session_123".to_string());

        // Generate a JWT with extended claims
        let token = generate_jwt_with_claims(user_id, email.clone(), roles.clone(), sid.clone())
            .expect("Failed to generate JWT");

        // Verify the JWT
        let claims = verify_jwt(&token).expect("Failed to verify JWT");

        // Check that all claims are correct
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.email, email);
        assert_eq!(claims.roles, roles);
        assert_eq!(claims.sid, sid);
        assert!(claims.exp > 0);
    }
}
