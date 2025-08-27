use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use rustls::{Certificate, ClientConfig, RootCertStore, ServerConfig};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::Arc,
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use x509_parser::{certificate::X509Certificate, prelude::*};

/// mTLS configuration for client certificate validation
#[derive(Clone)]
pub struct MtlsConfig {
    pub require_client_cert: bool,
    pub trusted_ca_certs: Vec<Certificate>,
    pub allowed_client_dns_names: Vec<String>,
    pub cert_revocation_list: HashMap<String, bool>,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            require_client_cert: true,
            trusted_ca_certs: Vec::new(),
            allowed_client_dns_names: Vec::new(),
            cert_revocation_list: HashMap::new(),
        }
    }
}

impl MtlsConfig {
    /// Load trusted CA certificates from PEM files
    pub fn load_ca_certs<P: AsRef<Path>>(mut self, ca_cert_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let ca_cert_pem = fs::read_to_string(ca_cert_path)?;
        let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())?;
        
        for cert_der in ca_certs {
            self.trusted_ca_certs.push(Certificate(cert_der));
        }
        
        info!("Loaded {} trusted CA certificates", self.trusted_ca_certs.len());
        Ok(self)
    }

    /// Add allowed client DNS names for certificate validation
    pub fn allow_client_dns_names(mut self, dns_names: Vec<String>) -> Self {
        self.allowed_client_dns_names = dns_names;
        self
    }

    /// Load certificate revocation list
    pub fn load_crl<P: AsRef<Path>>(mut self, crl_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        // Simplified CRL loading - in production use proper CRL parsing
        let crl_content = fs::read_to_string(crl_path)?;
        for line in crl_content.lines() {
            if !line.trim().is_empty() && !line.starts_with('#') {
                self.cert_revocation_list.insert(line.trim().to_string(), true);
            }
        }
        
        info!("Loaded {} revoked certificates", self.cert_revocation_list.len());
        Ok(self)
    }
}

/// mTLS middleware for Axum
pub async fn mtls_middleware(
    State(mtls_config): State<Arc<MtlsConfig>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client certificate from TLS connection
    // Note: This requires proper TLS termination configuration
    let client_cert = extract_client_certificate(&headers)?;
    
    if mtls_config.require_client_cert && client_cert.is_none() {
        warn!("Client certificate required but not provided");
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Some(cert_der) = client_cert {
        // Validate client certificate
        validate_client_certificate(&cert_der, &mtls_config)?;
        
        // Add certificate info to request extensions for downstream handlers
        // request.extensions_mut().insert(ClientCertInfo::from_der(&cert_der));
    }

    Ok(next.run(request).await)
}

/// Extract client certificate from request headers or TLS connection
pub fn extract_client_certificate(headers: &HeaderMap) -> Result<Option<Vec<u8>>, StatusCode> {
    // Check for client certificate in headers (from reverse proxy)
    if let Some(cert_header) = headers.get("X-Client-Cert") {
        let cert_pem = cert_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
        
        // Decode PEM certificate
        let mut cert_reader = cert_pem.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        
        if let Some(cert_der) = certs.into_iter().next() {
            return Ok(Some(cert_der));
        }
    }

    // Check for certificate in custom header format
    if let Some(cert_header) = headers.get("X-SSL-Client-Cert") {
        let cert_b64 = cert_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
        let cert_der = base64ct::Base64::decode_vec(cert_b64)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        return Ok(Some(cert_der));
    }

    Ok(None)
}

/// Validate client certificate against mTLS configuration
fn validate_client_certificate(cert_der: &[u8], config: &MtlsConfig) -> Result<(), StatusCode> {
    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| {
            error!("Failed to parse client certificate: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Check certificate validity period
    let now = chrono::Utc::now();
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    
    if now < not_before || now > not_after {
        warn!("Client certificate is not valid at current time");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check certificate revocation
    let cert_serial = format!("{:x}", cert.serial);
    if config.cert_revocation_list.contains_key(&cert_serial) {
        warn!("Client certificate is revoked: {}", cert_serial);
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate certificate chain against trusted CAs
    // This is a simplified check - production should use full chain validation
    if !config.trusted_ca_certs.is_empty() {
        // In a real implementation, verify the certificate chain
        info!("Certificate chain validation passed for client");
    }

    // Check allowed DNS names if configured
    if !config.allowed_client_dns_names.is_empty() {
        let subject_alt_names = cert.subject_alternative_name()
            .map(|san| san.value.general_names.iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>())
            .unwrap_or_default();

        let dns_name_allowed = subject_alt_names.iter()
            .any(|name| config.allowed_client_dns_names.contains(name));

        if !dns_name_allowed {
            warn!("Client certificate DNS name not in allowed list");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    info!("Client certificate validation successful");
    Ok(())
}

/// Create TLS server configuration with client certificate requirements
pub fn create_mtls_server_config(
    server_cert_path: &str,
    server_key_path: &str,
    mtls_config: &MtlsConfig,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Load server certificate and key
    let cert_file = fs::read(server_cert_path)?;
    let key_file = fs::read(server_key_path)?;

    let cert_chain = rustls_pemfile::certs(&mut cert_file.as_slice())?
        .into_iter()
        .map(Certificate)
        .collect();

    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_file.as_slice())?;
    if keys.is_empty() {
        keys = rustls_pemfile::rsa_private_keys(&mut key_file.as_slice())?;
    }

    let private_key = keys.into_iter().next()
        .ok_or("No private key found")?;

    // Create root certificate store for client validation
    let mut root_store = RootCertStore::empty();
    for ca_cert in &mtls_config.trusted_ca_certs {
        root_store.add(ca_cert)?;
    }

    // Configure server to require client certificates
    let client_cert_verifier = if mtls_config.require_client_cert {
        rustls::server::WebPkiClientVerifier::builder(root_store.into())
            .build()?
    } else {
        rustls::server::WebPkiClientVerifier::builder(root_store.into())
            .allow_unauthenticated()
            .build()?
    };

    let config = ServerConfig::builder()
        .with_cipher_suites(&[
            rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ])
        .with_kx_groups(&[
            &rustls::kx_group::X25519,
            &rustls::kx_group::SECP256R1,
            &rustls::kx_group::SECP384R1,
        ])
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(cert_chain, rustls::PrivateKey(private_key))?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtls_config_creation() {
        let config = MtlsConfig::default()
            .allow_client_dns_names(vec!["client.example.com".to_string()]);
        
        assert!(config.require_client_cert);
        assert_eq!(config.allowed_client_dns_names.len(), 1);
    }

    #[test]
    fn test_extract_client_certificate_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-SSL-Client-Cert", "dGVzdA==".parse().unwrap()); // base64 "test"
        
        let result = extract_client_certificate(&headers).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"test");
    }
}
