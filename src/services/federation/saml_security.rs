// SAML Security Validator - Integrates XMLDSig validation with SAML authentication
// Provides comprehensive security validation: XML structure, signatures, certificates, revocation

use anyhow::{Result, anyhow};
use openssl::x509::X509;

use crate::crypto::xmldsig::{
    CertificateValidationResult, CertificateValidator, XmlSecurityLimits, XmlSecurityValidator, XmlSignature,
    CrlManager, OcspClient, RevocationStatus, OcspStatus,
};

/// SAML Security Configuration
#[derive(Debug, Clone)]
pub struct SamlSecurityConfig {
    /// Enable XML security validation (billion laughs, depth limits, etc.)
    pub enable_xml_security: bool,

    /// Enable certificate chain validation against trust store
    pub enable_certificate_validation: bool,

    /// Enable CRL (Certificate Revocation List) checking
    pub enable_crl_check: bool,

    /// Enable OCSP (Online Certificate Status Protocol) checking
    pub enable_ocsp_check: bool,

    /// Fail authentication if CRL is unavailable (hard-fail vs soft-fail)
    pub crl_fail_on_unavailable: bool,

    /// Fail authentication if OCSP is unavailable (hard-fail vs soft-fail)
    pub ocsp_fail_on_unavailable: bool,

    /// XML security limits
    pub xml_limits: XmlSecurityLimits,

    /// CRL cache duration in seconds
    pub crl_cache_duration_secs: u64,

    /// CRL maximum size in bytes
    pub crl_max_size_bytes: usize,

    /// OCSP cache duration in seconds
    pub ocsp_cache_duration_secs: u64,

    /// OCSP HTTP timeout in seconds
    pub ocsp_timeout_secs: u64,
}

impl Default for SamlSecurityConfig {
    fn default() -> Self {
        Self {
            // Enable XML security by default (good defense, low risk)
            enable_xml_security: true,

            // Enable cert validation if trust store available
            enable_certificate_validation: true,

            // CRL/OCSP disabled by default (require explicit opt-in)
            enable_crl_check: false,
            enable_ocsp_check: false,

            // Soft-fail by default (backward compatible)
            crl_fail_on_unavailable: false,
            ocsp_fail_on_unavailable: false,

            // Default XML limits (secure but permissive)
            xml_limits: XmlSecurityLimits::default(),

            // CRL settings
            crl_cache_duration_secs: 3600,        // 1 hour
            crl_max_size_bytes: 10 * 1024 * 1024, // 10MB

            // OCSP settings
            ocsp_cache_duration_secs: 300, // 5 minutes
            ocsp_timeout_secs: 10,         // 10 seconds
        }
    }
}

/// SAML Security Validator - Comprehensive SAML assertion validation
pub struct SamlSecurityValidator {
    /// XML security validator (XML bombs, depth limits, etc.)
    xml_validator: XmlSecurityValidator,

    /// Certificate validator with trust store
    cert_validator: Option<CertificateValidator>,

    /// CRL manager for revocation checking
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    crl_manager: Option<CrlManager>,

    /// OCSP client for real-time revocation checking
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    ocsp_client: Option<OcspClient>,

    /// Security configuration
    config: SamlSecurityConfig,
}

impl SamlSecurityValidator {
    /// Create a new SAML security validator
    ///
    /// # Arguments
    /// * `config` - Security configuration
    /// * `trust_certs` - Optional list of trusted CA certificates for chain validation
    pub fn new(config: SamlSecurityConfig, trust_certs: Option<Vec<X509>>) -> Result<Self> {
        // Create XML security validator
        let xml_validator = XmlSecurityValidator::with_limits(config.xml_limits.clone());

        // Create certificate validator if trust store provided
        let cert_validator = if let Some(certs) = trust_certs {
            if !certs.is_empty() {
                // Build X509Store from certificates
                use openssl::x509::store::X509StoreBuilder;
                let mut builder = X509StoreBuilder::new()
                    .map_err(|e| anyhow!("Failed to create X509StoreBuilder: {}", e))?;

                for cert in certs {
                    builder
                        .add_cert(cert)
                        .map_err(|e| anyhow!("Failed to add certificate to trust store: {}", e))?;
                }

                Some(CertificateValidator::new(builder.build()))
            } else {
                None
            }
        } else {
            None
        };

        // Create CRL manager if enabled
        #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
        let crl_manager = if config.enable_crl_check {
            let manager = CrlManager::with_config(
                std::time::Duration::from_secs(config.crl_cache_duration_secs),
                config.crl_max_size_bytes,
            )?;
            Some(manager)
        } else {
            None
        };

        // Create OCSP client if enabled
        #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
        let ocsp_client = if config.enable_ocsp_check {
            let client = OcspClient::with_config(
                std::time::Duration::from_secs(config.ocsp_cache_duration_secs),
                std::time::Duration::from_secs(config.ocsp_timeout_secs),
            )?;
            Some(client)
        } else {
            None
        };

        Ok(Self {
            xml_validator,
            cert_validator,
            #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
            crl_manager,
            #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
            ocsp_client,
            config,
        })
    }

    /// Validate XML structure and security
    ///
    /// Checks for:
    /// - Document size limits
    /// - Element depth limits
    /// - Entity expansion attacks (billion laughs)
    /// - ID uniqueness (prevents spoofing)
    /// - Signature wrapping attacks
    pub fn validate_xml_security(&self, xml: &str) -> Result<()> {
        if !self.config.enable_xml_security {
            return Ok(());
        }

        self.xml_validator
            .validate_xml(xml)
            .map_err(|e| anyhow!("XML security validation failed: {}", e))?;

        tracing::debug!("XML security validation passed");
        Ok(())
    }

    /// Validate SAML assertion signature with full certificate and revocation checking
    ///
    /// Validation steps:
    /// 1. Extract signature from XML
    /// 2. Extract certificate from signature
    /// 3. Validate certificate chain (if trust store configured)
    /// 4. Check certificate expiration
    /// 5. Check certificate revocation via CRL (if enabled)
    /// 6. Check certificate revocation via OCSP (if enabled)
    /// 7. Verify signature with validated certificate
    ///
    /// # Arguments
    /// * `xml` - SAML assertion XML (decoded)
    ///
    /// # Returns
    /// * `Ok(())` if signature and certificate are valid
    /// * `Err` if any validation step fails
    pub async fn validate_signature_comprehensive(&self, xml: &str) -> Result<()> {
        // Extract signature from XML
        let signature = XmlSignature::extract_from_xml(xml)
            .map_err(|e| anyhow!("Failed to extract XML signature: {}", e))?;

        // Extract certificate from signature
        let cert = signature
            .get_certificate()
            .ok_or_else(|| anyhow!("No certificate in signature"))?;

        tracing::debug!("Extracted certificate from signature");

        // Validate certificate chain if trust store configured
        if self.config.enable_certificate_validation {
            if let Some(cert_validator) = &self.cert_validator {
                match cert_validator.validate_certificate(&cert)? {
                    CertificateValidationResult::Valid => {
                        tracing::debug!("Certificate chain validation passed");
                    }
                    CertificateValidationResult::Expired => {
                        return Err(anyhow!("Certificate has expired"));
                    }
                    CertificateValidationResult::NotYetValid => {
                        return Err(anyhow!("Certificate is not yet valid"));
                    }
                    CertificateValidationResult::UntrustedRoot => {
                        return Err(anyhow!("Certificate has untrusted root"));
                    }
                    CertificateValidationResult::ChainInvalid => {
                        return Err(anyhow!("Certificate chain is invalid"));
                    }
                    CertificateValidationResult::Revoked => {
                        return Err(anyhow!("Certificate has been revoked"));
                    }
                }
            } else {
                tracing::warn!("Certificate validation enabled but no trust store configured");
            }
        }

        // Check certificate revocation via CRL if enabled
        #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
        if self.config.enable_crl_check {
            if let Some(crl_manager) = &self.crl_manager {
                match crl_manager.check_revocation(&cert).await {
                    Ok(RevocationStatus::NotRevoked) => {
                        tracing::debug!("CRL check passed: certificate not revoked");
                    }
                    Ok(RevocationStatus::Revoked { reason, .. }) => {
                        return Err(anyhow!(
                            "Certificate revoked (CRL): {}",
                            reason.unwrap_or_else(|| "No reason provided".to_string())
                        ));
                    }
                    Ok(RevocationStatus::Unknown) => {
                        if self.config.crl_fail_on_unavailable {
                            return Err(anyhow!("CRL revocation status unknown (hard-fail mode)"));
                        } else {
                            tracing::warn!("CRL revocation status unknown (soft-fail mode)");
                        }
                    }
                    Err(e) => {
                        if self.config.crl_fail_on_unavailable {
                            return Err(anyhow!("CRL check failed (hard-fail mode): {}", e));
                        } else {
                            tracing::warn!("CRL check failed (soft-fail mode): {}", e);
                        }
                    }
                }
            }
        }

        // Check certificate revocation via OCSP if enabled
        #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
        if self.config.enable_ocsp_check
            && let Some(ocsp_client) = &self.ocsp_client {
                // Get issuer from certificate chain if validator is available
                let issuer = if let Some(cert_validator) = &self.cert_validator {
                    match cert_validator.get_issuer_from_chain(&cert) {
                        Ok(Some(issuer)) => Some(issuer),
                        Ok(None) => {
                            tracing::warn!(
                                "Could not determine issuer from certificate chain for OCSP check"
                            );
                            None
                        }
                        Err(e) => {
                            tracing::warn!("Failed to extract issuer for OCSP check: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                if let Some(issuer) = issuer {
                    match ocsp_client.check_status(&cert, &issuer).await {
                        Ok(OcspStatus::Good) => {
                            tracing::debug!("OCSP check passed: certificate is good");
                        }
                        Ok(OcspStatus::Revoked {
                            reason,
                            revocation_time,
                        }) => {
                            return Err(anyhow!(
                                "Certificate revoked (OCSP): {} (time: {:?})",
                                reason.unwrap_or_else(|| "No reason provided".to_string()),
                                revocation_time
                            ));
                        }
                        Ok(OcspStatus::Unknown) => {
                            if self.config.ocsp_fail_on_unavailable {
                                return Err(anyhow!(
                                    "OCSP revocation status unknown (hard-fail mode)"
                                ));
                            } else {
                                tracing::warn!("OCSP revocation status unknown (soft-fail mode)");
                            }
                        }
                        Err(e) => {
                            if self.config.ocsp_fail_on_unavailable {
                                return Err(anyhow!("OCSP check failed (hard-fail mode): {}", e));
                            } else {
                                tracing::warn!("OCSP check failed (soft-fail mode): {}", e);
                            }
                        }
                    }
                } else {
                    tracing::debug!("OCSP check skipped: issuer certificate not available");
                }
            }
        // Verify signature with validated certificate
        let is_valid = signature
            .verify(&cert, xml)
            .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

        if !is_valid {
            return Err(anyhow!("Signature is invalid"));
        }

        tracing::info!("SAML signature validation passed (comprehensive)");
        Ok(())
    }

    /// Get cache statistics for monitoring
    ///
    /// Returns (crl_stats, ocsp_stats) where each is (total, valid)
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    pub fn get_cache_stats(&self) -> ((usize, usize), (usize, usize)) {
        let crl_stats = if let Some(crl_manager) = &self.crl_manager {
            crl_manager.cache_stats()
        } else {
            (0, 0)
        };

        let ocsp_stats = if let Some(ocsp_client) = &self.ocsp_client {
            ocsp_client.cache_stats()
        } else {
            (0, 0)
        };

        (crl_stats, ocsp_stats)
    }

    /// Clear all caches (CRL and OCSP)
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    pub fn clear_caches(&mut self) {
        if let Some(crl_manager) = &mut self.crl_manager {
            crl_manager.clear_cache();
            tracing::debug!("Cleared CRL cache");
        }

        if let Some(ocsp_client) = &mut self.ocsp_client {
            ocsp_client.clear_cache();
            tracing::debug!("Cleared OCSP cache");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_security_config_default() {
        let config = SamlSecurityConfig::default();

        assert!(config.enable_xml_security);
        assert!(config.enable_certificate_validation);
        assert!(!config.enable_crl_check);
        assert!(!config.enable_ocsp_check);
        assert!(!config.crl_fail_on_unavailable);
        assert!(!config.ocsp_fail_on_unavailable);
    }

    #[test]
    fn test_saml_security_validator_creation_no_trust() {
        let config = SamlSecurityConfig::default();
        let validator = SamlSecurityValidator::new(config, None);

        assert!(validator.is_ok());
        let validator = validator.unwrap();
        assert!(validator.cert_validator.is_none());
    }

    #[test]
    fn test_saml_security_validator_xml_validation() {
        let config = SamlSecurityConfig::default();
        let validator = SamlSecurityValidator::new(config, None).unwrap();

        let valid_xml = r#"<?xml version="1.0"?><root><element>test</element></root>"#;
        assert!(validator.validate_xml_security(valid_xml).is_ok());
    }

    #[test]
    fn test_saml_security_config_disabled() {
        let mut config = SamlSecurityConfig::default();
        config.enable_xml_security = false;

        let validator = SamlSecurityValidator::new(config, None).unwrap();

        // Even invalid XML should pass if validation disabled
        let xml = "<invalid";
        assert!(validator.validate_xml_security(xml).is_ok());
    }
}
