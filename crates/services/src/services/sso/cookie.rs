//! SSO Cookie Management
//!
//! Handles secure SSO cookie generation, validation, and lifecycle.

use base64ct::{Base64, Encoding};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use authenc_core::error::{AuthencError, Result};

type HmacSha256 = Hmac<Sha256>;

/// SSO Cookie data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoCookieData {
    /// SSO session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: String,
    /// Realm identifier
    pub realm_id: String,
    /// Cookie creation timestamp
    pub created_at: DateTime<Utc>,
    /// Cookie expiration timestamp
    pub expires_at: DateTime<Utc>,
}

/// SSO Cookie Manager for secure cookie operations
pub struct SsoCookieManager {
    /// Secret key for HMAC signing
    secret_key: Vec<u8>,
    /// Cookie name
    cookie_name: String,
    /// Cookie domain
    cookie_domain: Option<String>,
    /// Cookie path
    cookie_path: String,
    /// Whether cookie is secure (HTTPS only)
    secure: bool,
    /// Whether cookie is HTTP only
    http_only: bool,
    /// SameSite policy
    same_site: SameSitePolicy,
}

/// SameSite cookie policy
#[derive(Debug, Clone)]
pub enum SameSitePolicy {
    /// Strict policy
    Strict,
    /// Lax policy
    Lax,
    /// None policy (requires Secure)
    None,
}

impl SsoCookieManager {
    /// Create a new SSO cookie manager
    ///
    /// # Arguments
    /// * `secret_key` - Secret key for HMAC signing (should be at least 32 bytes)
    /// * `cookie_name` - Name of the SSO cookie
    /// * `cookie_domain` - Optional domain for the cookie
    /// * `secure` - Whether cookie should be secure (HTTPS only)
    pub fn new(
        secret_key: &[u8],
        cookie_name: &str,
        cookie_domain: Option<String>,
        secure: bool,
    ) -> Self {
        Self {
            secret_key: secret_key.to_vec(),
            cookie_name: cookie_name.to_string(),
            cookie_domain,
            cookie_path: "/".to_string(),
            secure,
            http_only: true,
            same_site: SameSitePolicy::Lax,
        }
    }

    /// Generate SSO cookie value
    ///
    /// Format: base64(json_data) + "." + base64(hmac_signature)
    pub fn generate_cookie(
        &self,
        session_id: &str,
        user_id: &str,
        realm_id: &str,
        max_age_seconds: i64,
    ) -> Result<String> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(max_age_seconds);

        let cookie_data = SsoCookieData {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            realm_id: realm_id.to_string(),
            created_at: now,
            expires_at,
        };

        // Serialize to JSON
        let json_data = serde_json::to_string(&cookie_data)
            .map_err(|e| AuthencError::internal(format!("Failed to serialize cookie: {}", e)))?;

        // Base64 encode the JSON data
        let encoded_data = Base64::encode_string(json_data.as_bytes());

        // Create HMAC signature
        let signature = self.sign_data(&encoded_data)?;
        let encoded_signature = Base64::encode_string(&signature);

        // Combine: data.signature
        Ok(format!("{}.{}", encoded_data, encoded_signature))
    }

    /// Validate and parse SSO cookie value
    pub fn validate_cookie(&self, cookie_value: &str) -> Result<SsoCookieData> {
        // Split cookie into data and signature
        let parts: Vec<&str> = cookie_value.split('.').collect();
        if parts.len() != 2 {
            return Err(AuthencError::unauthorized("Invalid cookie format"));
        }

        let encoded_data = parts[0];
        let encoded_signature = parts[1];

        // Verify signature
        let expected_signature = self.sign_data(encoded_data)?;
        let provided_signature = Base64::decode_vec(encoded_signature)
            .map_err(|_| AuthencError::unauthorized("Invalid cookie signature encoding"))?;

        if expected_signature != provided_signature {
            return Err(AuthencError::unauthorized("Invalid cookie signature"));
        }

        // Decode and parse data
        let json_data = Base64::decode_vec(encoded_data)
            .map_err(|_| AuthencError::unauthorized("Invalid cookie data encoding"))?;

        let cookie_data: SsoCookieData = serde_json::from_slice(&json_data)
            .map_err(|_| AuthencError::unauthorized("Invalid cookie data format"))?;

        // Check expiration
        if Utc::now() > cookie_data.expires_at {
            return Err(AuthencError::unauthorized("Cookie expired"));
        }

        Ok(cookie_data)
    }

    /// Generate Set-Cookie header value
    pub fn generate_set_cookie_header(&self, cookie_value: &str, max_age_seconds: i64) -> String {
        let mut header = format!(
            "{}={}; Path={}",
            self.cookie_name, cookie_value, self.cookie_path
        );

        if let Some(ref domain) = self.cookie_domain {
            header.push_str(&format!("; Domain={}", domain));
        }

        header.push_str(&format!("; Max-Age={}", max_age_seconds));

        if self.secure {
            header.push_str("; Secure");
        }

        if self.http_only {
            header.push_str("; HttpOnly");
        }

        match self.same_site {
            SameSitePolicy::Strict => header.push_str("; SameSite=Strict"),
            SameSitePolicy::Lax => header.push_str("; SameSite=Lax"),
            SameSitePolicy::None => header.push_str("; SameSite=None"),
        }

        header
    }

    /// Generate cookie deletion header (for logout)
    pub fn generate_delete_cookie_header(&self) -> String {
        let mut header = format!("{}=; Path={}", self.cookie_name, self.cookie_path);

        if let Some(ref domain) = self.cookie_domain {
            header.push_str(&format!("; Domain={}", domain));
        }

        header.push_str("; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");

        if self.secure {
            header.push_str("; Secure");
        }

        if self.http_only {
            header.push_str("; HttpOnly");
        }

        header
    }

    /// Sign data using HMAC-SHA256
    fn sign_data(&self, data: &str) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .map_err(|e| AuthencError::internal(format!("Failed to create HMAC: {}", e)))?;

        mac.update(data.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Get cookie name
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation_and_validation() {
        let secret = b"test-secret-key-at-least-32-bytes-long!!";
        let manager = SsoCookieManager::new(secret, "AUTHENC_SSO", None, true);

        let cookie_value = manager
            .generate_cookie("session123", "user456", "realm789", 3600)
            .unwrap();

        let cookie_data = manager.validate_cookie(&cookie_value).unwrap();

        assert_eq!(cookie_data.session_id, "session123");
        assert_eq!(cookie_data.user_id, "user456");
        assert_eq!(cookie_data.realm_id, "realm789");
    }

    #[test]
    fn test_invalid_signature() {
        use base64ct::{Base64, Encoding};

        let secret = b"test-secret-key-at-least-32-bytes-long!!";
        let manager = SsoCookieManager::new(secret, "AUTHENC_SSO", None, true);

        let cookie_value = manager
            .generate_cookie("session123", "user456", "realm789", 3600)
            .unwrap();

        // Tamper with the cookie by modifying the data part but keeping signature
        let parts: Vec<&str> = cookie_value.split('.').collect();
        let mut data_bytes = Base64::decode_vec(parts[0]).unwrap();

        // Corrupt a byte in the JSON data
        if !data_bytes.is_empty() {
            data_bytes[0] ^= 0xFF; // Flip all bits in first byte
        }

        let tampered_data = Base64::encode_string(&data_bytes);
        let tampered = format!("{}.{}", tampered_data, parts[1]);

        let result = manager.validate_cookie(&tampered);
        assert!(result.is_err(), "Tampered cookie should be rejected");
    }

    #[test]
    fn test_set_cookie_header() {
        let secret = b"test-secret-key-at-least-32-bytes-long!!";
        let manager =
            SsoCookieManager::new(secret, "AUTHENC_SSO", Some("example.com".to_string()), true);

        let cookie_value = "test-value";
        let header = manager.generate_set_cookie_header(cookie_value, 3600);

        assert!(header.contains("AUTHENC_SSO=test-value"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("Domain=example.com"));
        assert!(header.contains("Max-Age=3600"));
        assert!(header.contains("Secure"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
    }

    #[test]
    fn test_delete_cookie_header() {
        let secret = b"test-secret-key-at-least-32-bytes-long!!";
        let manager = SsoCookieManager::new(secret, "AUTHENC_SSO", None, true);

        let header = manager.generate_delete_cookie_header();

        assert!(header.contains("AUTHENC_SSO="));
        assert!(header.contains("Max-Age=0"));
        assert!(header.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
    }
}
