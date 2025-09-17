use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// JWT claims structure for token payload
///
/// This struct represents the standard JWT claims used in authentication tokens.
/// It contains the essential claims for user identification and token expiration.
///
/// # Fields
/// * `sub` - Subject identifier (typically user ID)
/// * `exp` - Expiration timestamp (Unix timestamp)
///
/// # Security Considerations
/// - The `exp` claim should always be validated to prevent token reuse
/// - The `sub` claim should be validated against authenticated user identity
/// - Additional claims may be needed for more complex authorization scenarios
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier (typically the user ID or username)
    pub sub: String,
    /// Token expiration timestamp as Unix timestamp
    pub exp: usize,
}

const SECRET: &[u8] = b"supersecretkey";

/// Generate a JWT token for user authentication
///
/// Creates a signed JWT token with standard claims for the specified user.
/// The token includes subject identifier and expiration time, and is signed
/// using HMAC-SHA256 with a secret key.
///
/// # Arguments
/// * `user_id` - The user identifier to include in the token's subject claim
///
/// # Returns
/// A `Result` containing the JWT token string on success, or a JWT error on failure
///
/// # Security Considerations
/// - Tokens expire after 1 hour by default
/// - Uses HMAC-SHA256 for cryptographic signing
/// - Secret key should be cryptographically secure and regularly rotated
/// - Tokens should be validated on every request
///
/// # Example
/// ```rust
/// use authenc::utils::crypto::jwt::generate_jwt;
///
/// let token = generate_jwt("user123").expect("Failed to generate token");
/// ```
pub fn generate_jwt(user_id: &str) -> jsonwebtoken::errors::Result<String> {
    let expiration = SystemTime::now()
        .checked_add(Duration::from_secs(60 * 60))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
}

/// Verify and decode a JWT token
///
/// Validates the signature and expiration of a JWT token, then extracts the claims.
/// This function performs all standard JWT validation including signature verification,
/// expiration checking, and claim extraction.
///
/// # Arguments
/// * `token` - The JWT token string to verify and decode
///
/// # Returns
/// A `Result` containing the decoded `Claims` on success, or a JWT error on failure
///
/// # Security Considerations
/// - Always verify tokens before trusting their claims
/// - Check token expiration to prevent replay attacks
/// - Validate signature to ensure token integrity
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
pub fn verify_jwt(token: &str) -> jsonwebtoken::errors::Result<Claims> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET),
        &Validation::default(),
    )?;
    Ok(data.claims)
}
