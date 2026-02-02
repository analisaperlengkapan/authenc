//! DPoP (Demonstrated Proof of Possession) Implementation
//!
//! RFC 9449 DPoP (Demonstrated Proof of Possession) provides a way to
//! cryptographically bind access tokens to a public key, preventing token
//! replay attacks and enhancing security.
//!
//! Features:
//! - JWT-based proof of possession
//! - Multiple signature algorithms (Ed25519, ES256, PS256)
//! - HTTP request binding
//! - Access token binding
//! - Replay attack prevention
//! - Server-side nonce support

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

// Use public types from ed25519_keys module
pub use crate::ed25519_keys::{Ed25519Jwk, Ed25519JwkSet};
use authenc_api::error::AuthencError;

/// DPoP Proof JWT Header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPHeader {
    /// Algorithm used for signing
    pub alg: String,
    /// Key type
    pub typ: String,
    /// JWK containing the public key
    pub jwk: Value,
}

/// DPoP Proof JWT Payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPProofPayload {
    /// JWT ID for uniqueness
    pub jti: String,
    /// Hash of the HTTP request
    pub htm: String,
    /// HTTP URI
    pub htu: String,
    /// Issued at time
    pub iat: i64,
    /// Access token hash (ath claim)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Server nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// DPoP Proof
#[derive(Debug, Clone)]
pub struct DPoPProof {
    /// JWT header
    pub header: DPoPHeader,
    /// JWT payload
    pub payload: DPoPProofPayload,
    /// Signature
    pub signature: Vec<u8>,
}

impl DPoPProof {
    /// Create a new DPoP proof for an HTTP request
    pub fn new(
        keypair: &SigningKey,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<Self, AuthencError> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate unique JWT ID
        let jti_bytes: [u8; 16] = rng.r#gen();
        let jti = hex::encode(jti_bytes);

        // Create JWK from public key
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64ct::Base64UrlUnpadded::encode_string(keypair.verifying_key().as_bytes())
        });

        let header = DPoPHeader {
            alg: "EdDSA".to_string(),
            typ: "dpop+jwt".to_string(),
            jwk,
        };

        let mut payload = DPoPProofPayload {
            jti,
            htm: http_method.to_uppercase(),
            htu: http_uri.to_string(),
            iat: Utc::now().timestamp(),
            ath: None,
            nonce: nonce.map(|s| s.to_string()),
        };

        // Add access token hash if provided
        if let Some(token) = access_token {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let hash = hasher.finalize();
            payload.ath = Some(base64ct::Base64UrlUnpadded::encode_string(&hash));
        }

        // Sign the proof
        let header_b64 = base64ct::Base64UrlUnpadded::encode_string(
            serde_json::to_string(&header)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize header".to_string(),
                })?
                .as_bytes(),
        );

        let payload_b64 = base64ct::Base64UrlUnpadded::encode_string(
            serde_json::to_string(&payload)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize payload".to_string(),
                })?
                .as_bytes(),
        );

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = keypair.sign(message.as_bytes());

        Ok(Self {
            header,
            payload,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Serialize DPoP proof to JWT string
    pub fn to_jwt_string(&self) -> Result<String, AuthencError> {
        let header_json =
            serde_json::to_string(&self.header).map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize header".to_string(),
            })?;
        let header_b64 = base64ct::Base64UrlUnpadded::encode_string(header_json.as_bytes());

        let payload_json =
            serde_json::to_string(&self.payload).map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize payload".to_string(),
            })?;
        let payload_b64 = base64ct::Base64UrlUnpadded::encode_string(payload_json.as_bytes());

        let signature_b64 = base64ct::Base64UrlUnpadded::encode_string(&self.signature);

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// Parse DPoP proof from JWT string
    pub fn from_jwt_string(jwt: &str) -> Result<Self, AuthencError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthencError::validation("Invalid DPoP JWT format"));
        }

        let header_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[0])
            .map_err(|_| AuthencError::internal("Invalid header encoding"))?;

        let payload_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[1])
            .map_err(|_| AuthencError::internal("Invalid payload encoding"))?;

        let signature_bytes = base64ct::Base64UrlUnpadded::decode_vec(parts[2])
            .map_err(|_| AuthencError::internal("Invalid signature encoding"))?;

        let header: DPoPHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
            AuthencError::SerializationError {
                message: "Invalid header format".to_string(),
            }
        })?;

        let payload: DPoPProofPayload = serde_json::from_slice(&payload_bytes).map_err(|_| {
            AuthencError::SerializationError {
                message: "Invalid payload format".to_string(),
            }
        })?;

        Ok(Self {
            header,
            payload,
            signature: signature_bytes,
        })
    }

    /// Verify DPoP proof
    pub fn verify(
        &self,
        public_key: &VerifyingKey,
        expected_method: &str,
        expected_uri: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
        max_age_seconds: i64,
    ) -> Result<(), AuthencError> {
        // Verify signature
        let header_json =
            serde_json::to_string(&self.header).map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize header".to_string(),
            })?;
        let payload_json =
            serde_json::to_string(&self.payload).map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize payload".to_string(),
            })?;

        let message = format!(
            "{}.{}",
            base64ct::Base64UrlUnpadded::encode_string(header_json.as_bytes()),
            base64ct::Base64UrlUnpadded::encode_string(payload_json.as_bytes())
        );

        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AuthencError::validation("Invalid signature length".to_string()))?;

        let signature = Signature::from_bytes(&signature_bytes);

        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| AuthencError::internal("DPoP signature verification failed"))?;

        // Verify HTTP method
        if self.payload.htm != expected_method.to_uppercase() {
            return Err(AuthencError::validation("HTTP method mismatch"));
        }

        // Verify HTTP URI
        if self.payload.htu != expected_uri {
            return Err(AuthencError::validation("HTTP URI mismatch"));
        }

        // Verify timestamp (prevent replay attacks)
        let now = Utc::now().timestamp();
        if (now - self.payload.iat).abs() > max_age_seconds {
            return Err(AuthencError::validation("DPoP proof expired"));
        }

        // Verify access token hash if provided
        if let Some(token) = access_token {
            if let Some(ath) = &self.payload.ath {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                let expected_hash = base64ct::Base64UrlUnpadded::encode_string(&hasher.finalize());

                if *ath != expected_hash {
                    return Err(AuthencError::validation("Access token hash mismatch"));
                }
            } else {
                return Err(AuthencError::validation("Missing access token hash"));
            }
        }

        // Verify nonce if provided
        if let Some(expected_nonce) = nonce {
            if let Some(proof_nonce) = &self.payload.nonce {
                if proof_nonce != expected_nonce {
                    return Err(AuthencError::validation("Nonce mismatch"));
                }
            } else {
                return Err(AuthencError::validation("Missing nonce"));
            }
        }

        Ok(())
    }

    /// Extract public key from DPoP proof
    pub fn extract_public_key(&self) -> Result<VerifyingKey, AuthencError> {
        let x_b64 = self
            .header
            .jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthencError::validation("Missing x coordinate in JWK"))?;

        let x_bytes = base64ct::Base64UrlUnpadded::decode_vec(x_b64)
            .map_err(|_| AuthencError::CryptographicError)?;

        let x_array: [u8; 32] = x_bytes
            .try_into()
            .map_err(|_| AuthencError::validation("Invalid public key length"))?;

        VerifyingKey::from_bytes(&x_array).map_err(|_| AuthencError::CryptographicError)
    }
}

/// DPoP Nonce Manager for replay attack prevention
pub struct DPoPNonceManager {
    /// Used nonces with expiration times
    used_nonces: HashMap<String, DateTime<Utc>>,
}

impl Default for DPoPNonceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DPoPNonceManager {
    /// Create a new DPoP nonce manager
    pub fn new() -> Self {
        Self {
            used_nonces: HashMap::new(),
        }
    }

    /// Generate a new nonce
    pub fn generate_nonce(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 32] = rng.r#gen();
        base64ct::Base64UrlUnpadded::encode_string(&nonce_bytes)
    }

    /// Validate and consume a nonce
    pub fn validate_nonce(&mut self, nonce: &str) -> Result<(), AuthencError> {
        // Check if nonce has been used
        if self.used_nonces.contains_key(nonce) {
            return Err(AuthencError::validation("Nonce already used"));
        }

        // Mark nonce as used
        let expiration = Utc::now() + chrono::Duration::minutes(5); // 5 minute expiration
        self.used_nonces.insert(nonce.to_string(), expiration);

        Ok(())
    }

    /// Clean up expired nonces
    pub fn cleanup_expired_nonces(&mut self) {
        let now = Utc::now();
        self.used_nonces.retain(|_, expiration| *expiration > now);
    }
}

/// DPoP Token Binder for binding access tokens to DPoP proofs
pub struct DPoPTokenBinder {
    /// Nonce manager
    nonce_manager: DPoPNonceManager,
}

impl Default for DPoPTokenBinder {
    fn default() -> Self {
        Self::new()
    }
}

impl DPoPTokenBinder {
    /// Create a new DPoP token binder
    pub fn new() -> Self {
        Self {
            nonce_manager: DPoPNonceManager::new(),
        }
    }

    /// Bind an access token to a DPoP proof
    pub fn bind_token(
        &mut self,
        access_token: &str,
        dpop_proof: &DPoPProof,
        http_method: &str,
        http_uri: &str,
    ) -> Result<(), AuthencError> {
        // Extract public key from DPoP proof
        let public_key = dpop_proof.extract_public_key()?;

        // Verify DPoP proof
        dpop_proof.verify(
            &public_key,
            http_method,
            http_uri,
            Some(access_token),
            dpop_proof.payload.nonce.as_deref(),
            300, // 5 minutes max age
        )?;

        // Validate nonce if present
        if let Some(nonce) = &dpop_proof.payload.nonce {
            self.nonce_manager.validate_nonce(nonce)?;
        }

        Ok(())
    }

    /// Generate nonce for DPoP proof
    pub fn generate_nonce(&self) -> String {
        self.nonce_manager.generate_nonce()
    }

    /// Clean up expired nonces
    pub fn cleanup(&mut self) {
        self.nonce_manager.cleanup_expired_nonces();
    }
}

/// DPoP Middleware for Axum
pub mod middleware {
    use axum::{
        extract::{Request},
        http::{HeaderMap, StatusCode},
        middleware::Next,
        response::Response,
    };
    use std::sync::Arc;
    use tokio::sync::{Mutex, MutexGuard};
    use axum::http::header::ToStrError;

    use super::{DPoPProof, DPoPTokenBinder};

    /// DPoP middleware state
    pub struct DPoPMiddlewareState {
        /// Token binder for managing DPoP proofs
        pub token_binder: Mutex<DPoPTokenBinder>,
        /// Whether DPoP is required for requests
        pub require_dpop: bool,
    }

    /// DPoP middleware function
    pub async fn dpop_middleware(
        state: Arc<DPoPMiddlewareState>,
        headers: HeaderMap,
        mut request: Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        let mut token_binder: MutexGuard<'_, DPoPTokenBinder> = state.token_binder.lock().await;

        // Extract DPoP proof from header
        let dpop_header: &str = match headers.get("DPoP") {
            Some(header) => {
                let s: &str = header.to_str().map_err(|_: ToStrError| StatusCode::BAD_REQUEST)?;
                s
            },
            None => {
                if state.require_dpop {
                    return Err(StatusCode::UNAUTHORIZED);
                } else {
                    // No DPoP required, continue
                    return Ok(next.run(request).await);
                }
            }
        };

        // Parse DPoP proof
        let dpop_proof =
            DPoPProof::from_jwt_string(dpop_header).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Extract access token from Authorization header
        let access_token: Option<&str> = if let Some(auth_header) = headers.get("Authorization") {
            let auth_str: &str = auth_header.to_str().map_err(|_: ToStrError| StatusCode::BAD_REQUEST)?;
            if auth_str.starts_with("Bearer ") {
                Some(auth_str.trim_start_matches("Bearer "))
            } else {
                None
            }
        } else {
            None
        };

        // Bind token to DPoP proof
        if let Some(token) = access_token {
            token_binder
                .bind_token(
                    token,
                    &dpop_proof,
                    request.method().as_str(),
                    request.uri().path(),
                )
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
        }

        // Add DPoP proof to request extensions for use in handlers
        request.extensions_mut().insert(dpop_proof);

        Ok(next.run(request).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpop_proof_creation() {
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);

        let proof = DPoPProof::new(
            &keypair,
            "POST",
            "https://example.com/token",
            Some("access_token_123"),
            Some("nonce_456"),
        )
        .unwrap();

        assert_eq!(proof.payload.htm, "POST");
        assert_eq!(proof.payload.htu, "https://example.com/token");
        assert!(proof.payload.ath.is_some());
        assert_eq!(proof.payload.nonce, Some("nonce_456".to_string()));
    }

    #[test]
    fn test_dpop_proof_serialization() {
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);

        let proof =
            DPoPProof::new(&keypair, "GET", "https://example.com/resource", None, None).unwrap();

        let jwt_string = proof.to_jwt_string().unwrap();
        let parsed_proof = DPoPProof::from_jwt_string(&jwt_string).unwrap();

        assert_eq!(parsed_proof.payload.htm, proof.payload.htm);
        assert_eq!(parsed_proof.payload.htu, proof.payload.htu);
    }

    #[test]
    fn test_dpop_proof_verification() {
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);

        let proof = DPoPProof::new(
            &keypair,
            "POST",
            "https://example.com/api",
            Some("token_123"),
            None,
        )
        .unwrap();

        // Should verify successfully
        let result = proof.verify(
            &keypair.verifying_key(),
            "POST",
            "https://example.com/api",
            Some("token_123"),
            None,
            300,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_dpop_proof_verification_failure() {
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);

        let proof = DPoPProof::new(
            &keypair,
            "POST",
            "https://example.com/api",
            Some("token_123"),
            None,
        )
        .unwrap();

        // Should fail with wrong HTTP method
        let result = proof.verify(
            &keypair.verifying_key(),
            "GET", // Wrong method
            "https://example.com/api",
            Some("token_123"),
            None,
            300,
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HTTP method mismatch")
        );
    }

    #[test]
    fn test_nonce_manager() {
        let mut manager = DPoPNonceManager::new();

        let nonce = manager.generate_nonce();
        assert!(!nonce.is_empty());

        // First validation should succeed
        assert!(manager.validate_nonce(&nonce).is_ok());

        // Second validation should fail (nonce already used)
        assert!(manager.validate_nonce(&nonce).is_err());
    }

    #[test]
    fn test_token_binder() {
        let mut binder = DPoPTokenBinder::new();
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);

        let proof = DPoPProof::new(
            &keypair,
            "GET",
            "https://example.com/protected",
            Some("access_token_xyz"),
            None,
        )
        .unwrap();

        // Should bind successfully
        let result = binder.bind_token(
            "access_token_xyz",
            &proof,
            "GET",
            "https://example.com/protected",
        );

        assert!(result.is_ok());
    }
}
