//! mTLS (Mutual TLS) Authentication
//!
//! This module provides client certificate validation suitable for:
//! - Development environments with self-signed certificates
//! - Production with TLS termination at reverse proxy (nginx, traefik, etc.)
//! - Scenarios where full X.509 chain validation is handled upstream
//!
//! ## Architecture
//!
//! The implementation expects the reverse proxy/load balancer to:
//! 1. Handle TLS termination and certificate validation
//! 2. Forward certificate information via HTTP headers:
//!    - `X-SSL-Client-Fingerprint`: SHA-256 fingerprint of client cert
//!    - `X-SSL-Client-Cert`: Base64 encoded DER certificate
//!    - `X-SSL-Client-Subject`: Certificate subject DN
//!    - `X-SSL-Client-Issuer`: Certificate issuer DN
//!
//! ## Security Considerations
//!
//! - This is NOT a replacement for proper TLS/mTLS at the transport layer
//! - Always use this behind a trusted reverse proxy
//! - Validate that headers cannot be spoofed by clients
//! - Use `allowed_client_fingerprints` in production for whitelist-based auth
//!
//! ## Example
//!
//! ```rust,no_run
//! use authenc::crypto::mtls::{MtlsConfig, mtls_middleware};
//! use axum::{Router, middleware, routing::get};
//! use std::sync::Arc;
//!
//! async fn handler() -> &'static str {
//!     "Hello, authenticated client!"
//! }
//!
//! let config = MtlsConfig::prod_config(vec![
//!     "abc123...".to_string(), // Allowed client cert fingerprints
//! ]);
//!
//! let app: Router = Router::new()
//!     .route("/", get(handler))
//!     .layer(middleware::from_fn_with_state(
//!         Arc::new(config),
//!         mtls_middleware
//!     ));
//! ```

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use base64ct::{Base64, Encoding};
use std::sync::Arc;
use tracing::{error, info, warn};

/// mTLS configuration for client certificate validation
#[derive(Clone, Debug, Default)]
pub struct MtlsConfig {
    /// Whether client certificates are required for authentication
    pub require_client_cert: bool,
    /// List of allowed client certificate fingerprints (SHA-256)
    pub allowed_client_fingerprints: Vec<String>,
    /// List of trusted CA certificate fingerprints for validation
    pub trusted_ca_fingerprints: Vec<String>,
}

impl MtlsConfig {
    /// Create development configuration that allows all certificates
    pub fn dev_config() -> Self {
        Self {
            require_client_cert: false,
            allowed_client_fingerprints: Vec::new(),
            trusted_ca_fingerprints: Vec::new(),
        }
    }

    /// Create production configuration with specific allowed fingerprints
    pub fn prod_config(allowed_fingerprints: Vec<String>) -> Self {
        Self {
            require_client_cert: true,
            allowed_client_fingerprints: allowed_fingerprints,
            trusted_ca_fingerprints: Vec::new(),
        }
    }
}

/// Client certificate information
#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    /// SHA-256 fingerprint of the client certificate
    pub fingerprint: String,
    /// Subject field from the client certificate
    pub subject: Option<String>,
    /// Issuer field from the client certificate
    pub issuer: Option<String>,
}

/// mTLS middleware for Axum
pub async fn mtls_middleware(
    State(mtls_config): State<Arc<MtlsConfig>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client certificate from headers (set by reverse proxy)
    let client_cert_info = extract_client_cert_info(&headers)?;

    // Check if client certificate is required
    if mtls_config.require_client_cert && client_cert_info.is_none() {
        warn!("Client certificate required but not provided");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate client certificate if present
    if let Some(cert_info) = client_cert_info {
        if !validate_client_cert(&cert_info, &mtls_config) {
            error!("Client certificate validation failed");
            return Err(StatusCode::FORBIDDEN);
        }

        // Add certificate information to request extensions
        request.extensions_mut().insert(cert_info);
        info!("Client certificate validation successful");
    }

    Ok(next.run(request).await)
}

/// Extract client certificate information from headers
fn extract_client_cert_info(headers: &HeaderMap) -> Result<Option<ClientCertInfo>, StatusCode> {
    // Check for client certificate fingerprint (common in reverse proxy setups)
    if let Some(fingerprint_header) = headers.get("X-SSL-Client-Fingerprint") {
        let fingerprint = fingerprint_header
            .to_str()
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .to_string();

        let subject = headers
            .get("X-SSL-Client-Subject")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let issuer = headers
            .get("X-SSL-Client-Issuer")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        return Ok(Some(ClientCertInfo {
            fingerprint,
            subject,
            issuer,
        }));
    }

    // Check for base64 encoded certificate
    if let Some(cert_header) = headers.get("X-SSL-Client-Cert") {
        let cert_b64 = cert_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;

        // Decode certificate and calculate fingerprint
        let cert_der = Base64::decode_vec(cert_b64).map_err(|_| StatusCode::BAD_REQUEST)?;

        let fingerprint = calculate_cert_fingerprint(&cert_der);

        return Ok(Some(ClientCertInfo {
            fingerprint,
            subject: None,
            issuer: None,
        }));
    }

    Ok(None)
}

/// Validate client certificate against configuration
fn validate_client_cert(cert_info: &ClientCertInfo, config: &MtlsConfig) -> bool {
    // If no specific fingerprints are configured, allow all certificates
    if config.allowed_client_fingerprints.is_empty() {
        return true;
    }

    // Check if certificate fingerprint is in allowed list
    config
        .allowed_client_fingerprints
        .contains(&cert_info.fingerprint)
}

/// Calculate SHA-256 fingerprint of certificate
fn calculate_cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_simple_mtls_config_creation() {
        let dev_config = MtlsConfig::dev_config();
        assert!(!dev_config.require_client_cert);

        let prod_config = MtlsConfig::prod_config(vec!["abc123".to_string()]);
        assert!(prod_config.require_client_cert);
        assert_eq!(prod_config.allowed_client_fingerprints.len(), 1);
    }

    #[test]
    fn test_extract_client_cert_info() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-SSL-Client-Fingerprint",
            HeaderValue::from_static("abc123"),
        );
        headers.insert("X-SSL-Client-Subject", HeaderValue::from_static("CN=test"));

        let result = extract_client_cert_info(&headers).unwrap();
        assert!(result.is_some());

        let cert_info = result.unwrap();
        assert_eq!(cert_info.fingerprint, "abc123");
        assert_eq!(cert_info.subject, Some("CN=test".to_string()));
    }

    #[test]
    fn test_validate_client_cert() {
        let config = MtlsConfig::prod_config(vec!["allowed123".to_string()]);

        let allowed_cert = ClientCertInfo {
            fingerprint: "allowed123".to_string(),
            subject: None,
            issuer: None,
        };
        assert!(validate_client_cert(&allowed_cert, &config));

        let denied_cert = ClientCertInfo {
            fingerprint: "denied456".to_string(),
            subject: None,
            issuer: None,
        };
        assert!(!validate_client_cert(&denied_cert, &config));
    }

    #[test]
    fn test_calculate_cert_fingerprint() {
        let test_data = b"test certificate data";
        let fingerprint = calculate_cert_fingerprint(test_data);
        assert!(!fingerprint.is_empty());
        assert_eq!(fingerprint.len(), 64); // SHA-256 hex string length
    }

    #[test]
    fn test_extract_client_cert_info_no_headers() {
        let headers = HeaderMap::new();
        let result = extract_client_cert_info(&headers).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_client_cert_info_fingerprint_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-SSL-Client-Fingerprint",
            HeaderValue::from_static("fingerprint123"),
        );

        let result = extract_client_cert_info(&headers).unwrap();
        assert!(result.is_some());

        let cert_info = result.unwrap();
        assert_eq!(cert_info.fingerprint, "fingerprint123");
        assert!(cert_info.subject.is_none());
        assert!(cert_info.issuer.is_none());
    }

    #[test]
    fn test_extract_client_cert_info_all_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-SSL-Client-Fingerprint",
            HeaderValue::from_static("fingerprint123"),
        );
        headers.insert(
            "X-SSL-Client-Subject",
            HeaderValue::from_static("CN=Test User,O=Test Org"),
        );
        headers.insert(
            "X-SSL-Client-Issuer",
            HeaderValue::from_static("CN=Test CA,O=Test Org"),
        );

        let result = extract_client_cert_info(&headers).unwrap();
        assert!(result.is_some());

        let cert_info = result.unwrap();
        assert_eq!(cert_info.fingerprint, "fingerprint123");
        assert_eq!(
            cert_info.subject,
            Some("CN=Test User,O=Test Org".to_string())
        );
        assert_eq!(cert_info.issuer, Some("CN=Test CA,O=Test Org".to_string()));
    }

    #[test]
    fn test_extract_client_cert_info_base64_cert() {
        let mut headers = HeaderMap::new();
        // Add a base64 encoded certificate header
        headers.insert(
            "X-SSL-Client-Cert",
            HeaderValue::from_static("dGVzdCBjZXJ0IGRhdGE="), // base64 of "test cert data"
        );

        let result = extract_client_cert_info(&headers).unwrap();
        assert!(result.is_some());

        let cert_info = result.unwrap();
        // The fingerprint should be calculated from the decoded cert data
        let expected_fingerprint = calculate_cert_fingerprint(b"test cert data");
        assert_eq!(cert_info.fingerprint, expected_fingerprint);
        assert!(cert_info.subject.is_none());
        assert!(cert_info.issuer.is_none());
    }

    #[test]
    fn test_extract_client_cert_info_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-SSL-Client-Cert",
            HeaderValue::from_static("invalid-base64!@#"),
        );

        let result = extract_client_cert_info(&headers);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_extract_client_cert_info_invalid_utf8() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-SSL-Client-Fingerprint",
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(), // Invalid UTF-8
        );

        let result = extract_client_cert_info(&headers);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_client_cert_no_restrictions() {
        let config = MtlsConfig::dev_config();

        let cert = ClientCertInfo {
            fingerprint: "any-fingerprint".to_string(),
            subject: None,
            issuer: None,
        };

        assert!(validate_client_cert(&cert, &config));
    }

    #[test]
    fn test_validate_client_cert_multiple_allowed() {
        let config = MtlsConfig::prod_config(vec![
            "allowed1".to_string(),
            "allowed2".to_string(),
            "allowed3".to_string(),
        ]);

        let allowed_cert1 = ClientCertInfo {
            fingerprint: "allowed1".to_string(),
            subject: None,
            issuer: None,
        };
        assert!(validate_client_cert(&allowed_cert1, &config));

        let allowed_cert2 = ClientCertInfo {
            fingerprint: "allowed2".to_string(),
            subject: None,
            issuer: None,
        };
        assert!(validate_client_cert(&allowed_cert2, &config));

        let denied_cert = ClientCertInfo {
            fingerprint: "not-allowed".to_string(),
            subject: None,
            issuer: None,
        };
        assert!(!validate_client_cert(&denied_cert, &config));
    }

    #[test]
    fn test_client_cert_info_debug() {
        let cert_info = ClientCertInfo {
            fingerprint: "test-fingerprint".to_string(),
            subject: Some("CN=Test".to_string()),
            issuer: Some("CN=CA".to_string()),
        };

        let debug_str = format!("{:?}", cert_info);
        assert!(debug_str.contains("test-fingerprint"));
        assert!(debug_str.contains("CN=Test"));
        assert!(debug_str.contains("CN=CA"));
    }

    #[test]
    fn test_simple_mtls_config_debug() {
        let config = MtlsConfig {
            require_client_cert: true,
            allowed_client_fingerprints: vec!["fp1".to_string(), "fp2".to_string()],
            trusted_ca_fingerprints: vec!["ca1".to_string()],
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("true"));
        assert!(debug_str.contains("fp1"));
        assert!(debug_str.contains("fp2"));
        assert!(debug_str.contains("ca1"));
    }

    #[test]
    fn test_calculate_cert_fingerprint_different_inputs() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        let data3 = b"test data 1"; // Same as data1

        let fp1 = calculate_cert_fingerprint(data1);
        let fp2 = calculate_cert_fingerprint(data2);
        let fp3 = calculate_cert_fingerprint(data3);

        assert_ne!(fp1, fp2);
        assert_eq!(fp1, fp3); // Same input should produce same fingerprint
        assert_eq!(fp1.len(), 64);
        assert_eq!(fp2.len(), 64);
        assert_eq!(fp3.len(), 64);
    }

    #[test]
    fn test_calculate_cert_fingerprint_empty() {
        let data = b"";
        let fp = calculate_cert_fingerprint(data);
        assert_eq!(fp.len(), 64);
        // SHA-256 of empty string
        assert_eq!(
            fp,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
