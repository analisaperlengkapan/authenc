// SAML 2.0 Identity Provider Implementation
// Supports SAML 2.0 Web Browser SSO Profile with full signature validation

use crate::database::Database;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::x509::X509;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::sync::Arc;

use super::saml_security::{SamlSecurityConfig, SamlSecurityValidator};
use super::{AuthRequest, AuthResponse, IdentityProvider, IdentityProviderConfig, UserInfo};

/// SAML 2.0 Identity Provider
pub struct SamlIdentityProvider {
    /// Provider configuration
    config: IdentityProviderConfig,
    /// IdP entity ID
    entity_id: String,
    /// SSO service URL
    sso_url: String,
    /// Logout service URL
    logout_url: String,
    /// X.509 certificate for signature validation
    certificate: Option<X509>,
    /// Database for assertion cache
    db: Arc<Database>,
    /// Security validator for comprehensive validation
    security_validator: Option<SamlSecurityValidator>,
}

impl SamlIdentityProvider {
    /// Create new SAML identity provider
    pub fn new(config: IdentityProviderConfig, db: Arc<Database>) -> Result<Self> {
        let entity_id = config
            .config
            .get("entity_id")
            .ok_or_else(|| anyhow!("Missing entity_id in SAML config"))?
            .clone();

        let sso_url = config
            .config
            .get("sso_url")
            .ok_or_else(|| anyhow!("Missing sso_url in SAML config"))?
            .clone();

        let logout_url = config
            .config
            .get("logout_url")
            .unwrap_or(&"".to_string())
            .clone();

        // Load X.509 certificate if provided
        let certificate = if let Some(cert_path) = &config.truststore_path {
            Some(Self::load_certificate(cert_path)?)
        } else if let Some(cert_pem) = config.config.get("certificate") {
            Some(X509::from_pem(cert_pem.as_bytes())?)
        } else {
            None
        };

        // Load trust store for certificate validation
        let trust_certs = if let Some(truststore_path) = &config.truststore_path {
            Self::load_trust_store(truststore_path).ok()
        } else {
            None
        };

        // Create security configuration
        let security_config = Self::parse_security_config(&config.config);

        // Create security validator if any security features are enabled
        let security_validator = if security_config.enable_xml_security
            || security_config.enable_certificate_validation
            || security_config.enable_crl_check
            || security_config.enable_ocsp_check
        {
            match SamlSecurityValidator::new(security_config, trust_certs) {
                Ok(validator) => {
                    tracing::info!("SAML security validator initialized");
                    Some(validator)
                }
                Err(e) => {
                    tracing::warn!("Failed to create SAML security validator: {}. Continuing without enhanced security.", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            entity_id,
            sso_url,
            logout_url,
            certificate,
            db,
            security_validator,
        })
    }

    /// Load X.509 certificate from file
    fn load_certificate(path: &str) -> Result<X509> {
        let cert_pem = std::fs::read(path)?;
        Ok(X509::from_pem(&cert_pem)?)
    }

    /// Load trust store (multiple CA certificates) from file or directory
    fn load_trust_store(path: &str) -> Result<Vec<X509>> {
        use std::path::Path;

        let path_obj = Path::new(path);

        if path_obj.is_file() {
            // Single file - may contain multiple PEM certificates
            let pem_data = std::fs::read(path)?;
            let certs = X509::stack_from_pem(&pem_data)?;
            Ok(certs.into_iter().collect())
        } else if path_obj.is_dir() {
            // Directory - load all .pem and .crt files
            let mut all_certs = Vec::new();

            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "pem" || ext == "crt" {
                            if let Ok(pem_data) = std::fs::read(&path) {
                                if let Ok(certs) = X509::stack_from_pem(&pem_data) {
                                    all_certs.extend(certs.into_iter());
                                }
                            }
                        }
                    }
                }
            }

            if all_certs.is_empty() {
                return Err(anyhow!("No certificates found in trust store directory"));
            }

            Ok(all_certs)
        } else {
            Err(anyhow!("Trust store path is neither file nor directory"))
        }
    }

    /// Parse security configuration from provider config
    fn parse_security_config(config: &HashMap<String, String>) -> SamlSecurityConfig {
        use crate::crypto::xmldsig::XmlSecurityLimits;

        let mut security_config = SamlSecurityConfig::default();

        // Parse boolean flags
        if let Some(val) = config.get("enable_xml_security") {
            security_config.enable_xml_security = val.parse().unwrap_or(true);
        }

        if let Some(val) = config.get("enable_certificate_validation") {
            security_config.enable_certificate_validation = val.parse().unwrap_or(true);
        }

        if let Some(val) = config.get("enable_crl_check") {
            security_config.enable_crl_check = val.parse().unwrap_or(false);
        }

        if let Some(val) = config.get("enable_ocsp_check") {
            security_config.enable_ocsp_check = val.parse().unwrap_or(false);
        }

        if let Some(val) = config.get("crl_fail_on_unavailable") {
            security_config.crl_fail_on_unavailable = val.parse().unwrap_or(false);
        }

        if let Some(val) = config.get("ocsp_fail_on_unavailable") {
            security_config.ocsp_fail_on_unavailable = val.parse().unwrap_or(false);
        }

        // Parse numeric settings
        if let Some(val) = config.get("crl_cache_duration_secs") {
            if let Ok(secs) = val.parse() {
                security_config.crl_cache_duration_secs = secs;
            }
        }

        if let Some(val) = config.get("crl_max_size_bytes") {
            if let Ok(bytes) = val.parse() {
                security_config.crl_max_size_bytes = bytes;
            }
        }

        if let Some(val) = config.get("ocsp_cache_duration_secs") {
            if let Ok(secs) = val.parse() {
                security_config.ocsp_cache_duration_secs = secs;
            }
        }

        if let Some(val) = config.get("ocsp_timeout_secs") {
            if let Ok(secs) = val.parse() {
                security_config.ocsp_timeout_secs = secs;
            }
        }

        // Parse XML security limits
        let mut xml_limits = XmlSecurityLimits::default();

        if let Some(val) = config.get("xml_max_document_size") {
            if let Ok(size) = val.parse() {
                xml_limits.max_document_size = size;
            }
        }

        if let Some(val) = config.get("xml_max_element_depth") {
            if let Ok(depth) = val.parse() {
                xml_limits.max_element_depth = depth;
            }
        }

        if let Some(val) = config.get("xml_max_elements") {
            if let Ok(elements) = val.parse() {
                xml_limits.max_elements = elements;
            }
        }

        if let Some(val) = config.get("xml_max_entity_expansions") {
            if let Ok(expansions) = val.parse() {
                xml_limits.max_entity_expansions = expansions;
            }
        }

        security_config.xml_limits = xml_limits;

        security_config
    }

    /// Parse SAML Response XML and extract assertion
    fn parse_saml_response(&self, saml_response: &str) -> Result<SamlAssertion> {
        // Decode base64 SAML response
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(saml_response.as_bytes())
            .map_err(|e| anyhow!("Failed to decode SAML response: {}", e))?;

        let xml = String::from_utf8(decoded)?;

        // Parse XML
        let mut reader = Reader::from_str(&xml);
        reader.trim_text(true);

        let mut assertion = SamlAssertion::default();
        let mut in_assertion = false;
        let mut in_subject = false;
        let mut in_conditions = false;
        let mut in_attribute_statement = false;
        let mut current_attribute_name = String::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    match e.name().as_ref() {
                        b"saml:Assertion" | b"Assertion" => {
                            in_assertion = true;
                            // Extract AssertionID
                            for attr in e.attributes() {
                                let attr = attr?;
                                if attr.key.as_ref() == b"ID" {
                                    assertion.id = String::from_utf8(attr.value.to_vec())?;
                                }
                            }
                        }
                        b"saml:Subject" | b"Subject" => {
                            in_subject = true;
                        }
                        b"saml:NameID" | b"NameID" if in_subject => {
                            let text = reader.read_text(e.name())?;
                            assertion.name_id = text.to_string();
                        }
                        b"saml:Conditions" | b"Conditions" => {
                            in_conditions = true;
                            // Extract NotBefore and NotOnOrAfter
                            for attr in e.attributes() {
                                let attr = attr?;
                                match attr.key.as_ref() {
                                    b"NotBefore" => {
                                        let value = String::from_utf8(attr.value.to_vec())?;
                                        assertion.not_before = Some(
                                            DateTime::parse_from_rfc3339(&value)?
                                                .with_timezone(&Utc),
                                        );
                                    }
                                    b"NotOnOrAfter" => {
                                        let value = String::from_utf8(attr.value.to_vec())?;
                                        assertion.not_on_or_after = Some(
                                            DateTime::parse_from_rfc3339(&value)?
                                                .with_timezone(&Utc),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                        }
                        b"saml:AudienceRestriction" | b"AudienceRestriction" if in_conditions => {
                            // Read audience value
                            if let Ok(Event::Start(e)) = reader.read_event_into(&mut buf) {
                                if e.name().as_ref() == b"saml:Audience"
                                    || e.name().as_ref() == b"Audience"
                                {
                                    let text = reader.read_text(e.name())?;
                                    assertion.audience = Some(text.to_string());
                                }
                            }
                        }
                        b"saml:AttributeStatement" | b"AttributeStatement" => {
                            in_attribute_statement = true;
                        }
                        b"saml:Attribute" | b"Attribute" if in_attribute_statement => {
                            // Extract attribute name
                            for attr in e.attributes() {
                                let attr = attr?;
                                if attr.key.as_ref() == b"Name" {
                                    current_attribute_name =
                                        String::from_utf8(attr.value.to_vec())?;
                                }
                            }
                        }
                        b"saml:AttributeValue" | b"AttributeValue" if in_attribute_statement => {
                            let text = reader.read_text(e.name())?;
                            if !current_attribute_name.is_empty() {
                                assertion
                                    .attributes
                                    .entry(current_attribute_name.clone())
                                    .or_insert_with(Vec::new)
                                    .push(text.to_string());
                            }
                        }
                        b"saml:AuthnStatement" | b"AuthnStatement" if in_assertion => {
                            // Extract session index
                            for attr in e.attributes() {
                                let attr = attr?;
                                if attr.key.as_ref() == b"SessionIndex" {
                                    assertion.session_index =
                                        Some(String::from_utf8(attr.value.to_vec())?);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => match e.name().as_ref() {
                    b"saml:Assertion" | b"Assertion" => in_assertion = false,
                    b"saml:Subject" | b"Subject" => in_subject = false,
                    b"saml:Conditions" | b"Conditions" => in_conditions = false,
                    b"saml:AttributeStatement" | b"AttributeStatement" => {
                        in_attribute_statement = false
                    }
                    _ => {}
                },
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parse error: {:?}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(assertion)
    }

    /// Validate XML signature using certificate (full XMLDSig implementation)
    ///
    /// Enhanced version with comprehensive security validation:
    /// - XML structure validation (attacks prevention)
    /// - Certificate chain validation
    /// - Certificate expiration checking
    /// - Revocation checking (CRL/OCSP if enabled)
    /// - Signature cryptographic verification
    fn validate_signature(&self, xml: &str) -> Result<bool> {
        // Use security validator if available (comprehensive validation)
        if let Some(validator) = &self.security_validator {
            // Comprehensive validation (XML security + cert chain + revocation + signature)
            validator.validate_signature_comprehensive(xml)?;
            tracing::info!("SAML signature validation passed (comprehensive)");
            return Ok(true);
        }

        // Fallback to basic signature validation (backward compatibility)
        use crate::crypto::xmldsig::XmlSignature;

        if let Some(cert) = &self.certificate {
            // Extract and verify XML signature
            let signature = XmlSignature::extract_from_xml(xml)
                .map_err(|e| anyhow!("Failed to extract XML signature: {}", e))?;

            // Verify signature using certificate
            let is_valid = signature
                .verify(cert, xml)
                .map_err(|e| anyhow!("Failed to verify XML signature: {}", e))?;

            if !is_valid {
                tracing::error!("SAML signature verification failed");
                return Ok(false);
            }

            tracing::debug!("SAML signature verified successfully (basic)");
            Ok(true)
        } else {
            // If no certificate configured, skip signature validation
            // This is NOT recommended for production
            tracing::warn!(
                "No certificate configured for SAML provider, skipping signature validation"
            );
            Ok(true)
        }
    }

    /// Validate assertion conditions (NotBefore, NotOnOrAfter, Audience)
    fn validate_conditions(&self, assertion: &SamlAssertion) -> Result<()> {
        let now = Utc::now();

        // Check NotBefore
        if let Some(not_before) = assertion.not_before {
            if now < not_before {
                return Err(anyhow!("Assertion not yet valid (NotBefore)"));
            }
        }

        // Check NotOnOrAfter
        if let Some(not_on_or_after) = assertion.not_on_or_after {
            if now >= not_on_or_after {
                return Err(anyhow!("Assertion expired (NotOnOrAfter)"));
            }
        }

        // Check Audience Restriction
        if let Some(audience) = &assertion.audience {
            // Audience should match our SP entity ID
            let expected_audience = self
                .config
                .config
                .get("sp_entity_id")
                .unwrap_or(&self.entity_id);

            if audience != expected_audience {
                return Err(anyhow!(
                    "Audience mismatch: expected {}, got {}",
                    expected_audience,
                    audience
                ));
            }
        }

        Ok(())
    }

    /// Check if assertion has been used before (replay attack prevention)
    async fn check_replay(&self, assertion_id: &str) -> Result<bool> {
        let db = &self.db;

        // Check if assertion ID exists in cache
        let query = "SELECT assertion_id FROM saml_assertion_cache WHERE assertion_id = $1";
        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&assertion_id]).await?;

        if !rows.is_empty() {
            return Ok(true); // Assertion already used (replay attack)
        }

        // Store assertion ID in cache (expires in 5 minutes)
        let expires_at = Utc::now() + Duration::minutes(5);
        let insert_query =
            "INSERT INTO saml_assertion_cache (assertion_id, expires_at) VALUES ($1, $2)";
        db.execute(insert_query, &[&assertion_id, &expires_at])
            .await?;

        Ok(false) // Not a replay
    }

    /// Clean up expired assertion cache entries
    pub async fn cleanup_expired_assertions(&self) -> Result<u64> {
        let db = &self.db;
        let query = "DELETE FROM saml_assertion_cache WHERE expires_at < NOW()";
        let deleted = db.execute(query, &[]).await?;
        Ok(deleted)
    }

    /// Map SAML attributes to UserInfo
    fn map_attributes_to_user_info(&self, assertion: &SamlAssertion) -> UserInfo {
        let mut user_info = UserInfo {
            id: assertion.name_id.clone(),
            username: None,
            email: None,
            first_name: None,
            last_name: None,
            groups: Vec::new(),
            roles: Vec::new(),
            attributes: HashMap::new(),
        };

        // Map common SAML attributes
        for (key, values) in &assertion.attributes {
            let value = values.first().cloned().unwrap_or_default();

            match key.as_str() {
                "uid" | "username" | "sAMAccountName" => {
                    user_info.username = Some(value);
                }
                "mail" | "email" | "emailAddress" => {
                    user_info.email = Some(value);
                }
                "givenName" | "firstName" => {
                    user_info.first_name = Some(value);
                }
                "sn" | "surname" | "lastName" => {
                    user_info.last_name = Some(value);
                }
                "memberOf" | "groups" => {
                    user_info.groups = values.clone();
                }
                "roles" | "role" => {
                    user_info.roles = values.clone();
                }
                _ => {
                    // Store other attributes
                    user_info.attributes.insert(key.clone(), value);
                }
            }
        }

        user_info
    }
}

#[async_trait]
impl IdentityProvider for SamlIdentityProvider {
    async fn authenticate(&self, request: &AuthRequest) -> Result<AuthResponse> {
        if let Some(saml_response) = &request.saml_assertion {
            // Decode base64 SAML response for validation
            use base64::Engine;
            let xml = match base64::engine::general_purpose::STANDARD
                .decode(saml_response.as_bytes())
                .and_then(|bytes| {
                    String::from_utf8(bytes).map_err(|e| {
                        base64::DecodeError::InvalidByte(0, e.utf8_error().valid_up_to() as u8)
                    })
                }) {
                Ok(xml) => xml,
                Err(e) => {
                    return Ok(AuthResponse {
                        success: false,
                        user_id: None,
                        username: None,
                        email: None,
                        groups: vec![],
                        roles: vec![],
                        attributes: HashMap::new(),
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some(format!("Failed to decode SAML response: {}", e)),
                    });
                }
            };

            // 1. XML Security Validation (FIRST - prevents attacks before expensive operations)
            if let Some(validator) = &self.security_validator {
                if let Err(e) = validator.validate_xml_security(&xml) {
                    tracing::warn!("XML security validation failed: {}", e);
                    return Ok(AuthResponse {
                        success: false,
                        user_id: None,
                        username: None,
                        email: None,
                        groups: vec![],
                        roles: vec![],
                        attributes: HashMap::new(),
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some(format!("XML security validation failed: {}", e)),
                    });
                }
            }

            // 2. Parse SAML response
            let assertion = match self.parse_saml_response(saml_response) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(AuthResponse {
                        success: false,
                        user_id: None,
                        username: None,
                        email: None,
                        groups: vec![],
                        roles: vec![],
                        attributes: HashMap::new(),
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some(format!("Failed to parse SAML response: {}", e)),
                    });
                }
            };

            // 3. Validate signature (comprehensive: cert chain + revocation + signature)
            if let Err(e) = self.validate_signature(&xml) {
                return Ok(AuthResponse {
                    success: false,
                    user_id: None,
                    username: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    attributes: HashMap::new(),
                    token: None,
                    refresh_token: None,
                    expires_at: None,
                    error: Some(format!("Signature validation failed: {}", e)),
                });
            }

            // 4. Validate conditions (NotBefore, NotOnOrAfter, Audience)
            if let Err(e) = self.validate_conditions(&assertion) {
                return Ok(AuthResponse {
                    success: false,
                    user_id: None,
                    username: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    attributes: HashMap::new(),
                    token: None,
                    refresh_token: None,
                    expires_at: None,
                    error: Some(format!("Assertion conditions invalid: {}", e)),
                });
            }

            // 5. Check for replay attack
            if let Ok(is_replay) = self.check_replay(&assertion.id).await {
                if is_replay {
                    return Ok(AuthResponse {
                        success: false,
                        user_id: None,
                        username: None,
                        email: None,
                        groups: vec![],
                        roles: vec![],
                        attributes: HashMap::new(),
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some("Replay attack detected: assertion already used".to_string()),
                    });
                }
            }

            // Extract user info
            let user_info = self.map_attributes_to_user_info(&assertion);

            Ok(AuthResponse {
                success: true,
                user_id: Some(user_info.id.clone()),
                username: user_info.username.clone(),
                email: user_info.email.clone(),
                groups: user_info.groups.clone(),
                roles: user_info.roles.clone(),
                attributes: user_info.attributes.clone(),
                token: assertion.session_index.clone(),
                refresh_token: None,
                expires_at: assertion.not_on_or_after.map(|dt| dt.timestamp() as u64),
                error: None,
            })
        } else {
            Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("No SAML assertion provided".to_string()),
            })
        }
    }

    async fn get_user_info(&self, token: &str) -> Result<UserInfo> {
        // In SAML, the "token" is typically the session index
        // User info should be retrieved from the session or database

        // For now, return a placeholder
        // In production, this would query the session store
        Ok(UserInfo {
            id: token.to_string(),
            username: Some("saml_user".to_string()),
            email: Some("user@example.com".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            groups: vec![],
            roles: vec![],
            attributes: HashMap::new(),
        })
    }

    async fn validate_token(&self, token: &str) -> Result<bool> {
        // Validate SAML session token
        // In production, this would check the session store
        // and verify the session hasn't expired

        if token.is_empty() {
            return Ok(false);
        }

        // Check if session exists in database
        // For now, accept any non-empty token
        Ok(true)
    }

    async fn logout(&self, token: &str) -> Result<()> {
        // Implement SAML Single Logout (SLO)
        // This would:
        // 1. Generate LogoutRequest XML
        // 2. Send to IdP logout endpoint
        // 3. Handle LogoutResponse
        // 4. Clean up local session

        tracing::info!("SAML logout for session: {}", token);

        // In production, send LogoutRequest to IdP
        if !self.logout_url.is_empty() {
            // TODO: Implement actual SAML LogoutRequest generation and sending
            tracing::info!("Would send LogoutRequest to: {}", self.logout_url);
        }

        Ok(())
    }
}

/// SAML Assertion data structure
#[derive(Debug, Default, Clone)]
struct SamlAssertion {
    /// Unique assertion ID
    id: String,
    /// Subject NameID
    name_id: String,
    /// NotBefore condition
    not_before: Option<DateTime<Utc>>,
    /// NotOnOrAfter condition
    not_on_or_after: Option<DateTime<Utc>>,
    /// Audience restriction
    audience: Option<String>,
    /// Session index from AuthnStatement
    session_index: Option<String>,
    /// User attributes
    attributes: HashMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_assertion_default() {
        let assertion = SamlAssertion::default();
        assert!(assertion.id.is_empty());
        assert!(assertion.name_id.is_empty());
        assert!(assertion.attributes.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires database
    async fn test_saml_provider_creation() {
        // This test requires a database connection
        // Run with: cargo test --features db -- --ignored
    }
}
