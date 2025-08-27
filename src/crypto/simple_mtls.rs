use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info, warn, error};
use base64ct::{Base64, Encoding};

/// Simplified mTLS configuration for basic client certificate validation
#[derive(Clone, Debug)]
pub struct SimpleMtlsConfig {
    pub require_client_cert: bool,
    pub allowed_client_fingerprints: Vec<String>,
    pub trusted_ca_fingerprints: Vec<String>,
}

impl Default for SimpleMtlsConfig {
    fn default() -> Self {
        Self {
            require_client_cert: false,
            allowed_client_fingerprints: Vec::new(),
            trusted_ca_fingerprints: Vec::new(),
        }
    }
}

impl SimpleMtlsConfig {
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
    pub fingerprint: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

/// Simplified mTLS middleware for Axum
pub async fn simple_mtls_middleware(
    State(mtls_config): State<Arc<SimpleMtlsConfig>>,
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
        let cert_b64 = cert_header
            .to_str()
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Decode certificate and calculate fingerprint
        let cert_der = Base64::decode_vec(cert_b64)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

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
fn validate_client_cert(cert_info: &ClientCertInfo, config: &SimpleMtlsConfig) -> bool {
    // If no specific fingerprints are configured, allow all certificates
    if config.allowed_client_fingerprints.is_empty() {
        return true;
    }

    // Check if certificate fingerprint is in allowed list
    config.allowed_client_fingerprints.contains(&cert_info.fingerprint)
}

/// Calculate SHA-256 fingerprint of certificate
fn calculate_cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Sha256, Digest};
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
        let dev_config = SimpleMtlsConfig::dev_config();
        assert!(!dev_config.require_client_cert);

        let prod_config = SimpleMtlsConfig::prod_config(vec!["abc123".to_string()]);
        assert!(prod_config.require_client_cert);
        assert_eq!(prod_config.allowed_client_fingerprints.len(), 1);
    }

    #[test]
    fn test_extract_client_cert_info() {
        let mut headers = HeaderMap::new();
        headers.insert("X-SSL-Client-Fingerprint", HeaderValue::from_static("abc123"));
        headers.insert("X-SSL-Client-Subject", HeaderValue::from_static("CN=test"));

        let result = extract_client_cert_info(&headers).unwrap();
        assert!(result.is_some());
        
        let cert_info = result.unwrap();
        assert_eq!(cert_info.fingerprint, "abc123");
        assert_eq!(cert_info.subject, Some("CN=test".to_string()));
    }

    #[test]
    fn test_validate_client_cert() {
        let config = SimpleMtlsConfig::prod_config(vec!["allowed123".to_string()]);
        
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
}
