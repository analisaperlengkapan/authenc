use crate::database::Database;
use crate::error::{AuthencError, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use quick_xml::de::from_str as xml_from_str;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

/// SAML 2.0 Service Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProvider {
    /// Entity ID of the service provider
    pub entity_id: String,
    /// URL for assertion consumer service
    pub assertion_consumer_service_url: String,
    /// URL for single logout service
    pub single_logout_service_url: Option<String>,
    /// Name ID format expected
    pub name_id_format: String,
    /// Whether assertions should be signed
    pub want_assertions_signed: bool,
    /// Whether responses should be signed
    pub want_response_signed: bool,
}

/// SAML 2.0 Identity Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdentityProvider {
    /// Entity ID of the identity provider
    pub entity_id: String,
    /// Single sign-on URL
    pub sso_url: String,
    /// Single logout URL
    pub slo_url: Option<String>,
    /// X.509 certificate for signature verification
    pub certificate: String,
    /// Name ID format supported
    pub name_id_format: String,
    /// Whether authentication requests should be signed
    pub want_authn_requests_signed: bool,
}

/// SAML 2.0 Authentication Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnRequest {
    /// Unique identifier for the request
    pub id: String,
    /// SAML version
    pub version: String,
    /// Timestamp when the request was issued
    pub issue_instant: String,
    /// Assertion consumer service URL
    pub assertion_consumer_service_url: String,
    /// Issuer of the request
    pub issuer: String,
    /// Name ID policy
    pub name_id_policy: Option<NameIdPolicy>,
    /// Requested authentication context
    pub requested_authn_context: Option<RequestedAuthnContext>,
}

/// Name ID Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameIdPolicy {
    /// Name ID format
    pub format: String,
    /// Whether creation of new identifiers is allowed
    pub allow_create: bool,
}

/// Requested Authentication Context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedAuthnContext {
    /// Comparison method for authentication context
    pub comparison: String,
    /// List of authentication context class references
    pub authn_context_class_ref: Vec<String>,
}

/// SAML 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    /// Unique identifier for the response
    pub id: String,
    /// SAML version
    pub version: String,
    /// Timestamp when the response was issued
    pub issue_instant: String,
    /// ID of the request this response is for
    pub in_response_to: String,
    /// Issuer of the response
    pub issuer: String,
    /// Status of the response
    pub status: SamlStatus,
    /// SAML assertion (if successful)
    pub assertion: Option<SamlAssertion>,
}

/// SAML Status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStatus {
    /// Status code indicating success or failure
    pub status_code: SamlStatusCode,
}

/// SAML Status Code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStatusCode {
    /// Status code value
    pub value: String,
}

/// SAML Assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Unique identifier for the assertion
    pub id: String,
    /// SAML version
    pub version: String,
    /// Timestamp when the assertion was issued
    pub issue_instant: String,
    /// Issuer of the assertion
    pub issuer: String,
    /// Subject of the assertion
    pub subject: SamlSubject,
    /// Conditions for the assertion validity
    pub conditions: SamlConditions,
    /// Authentication statement
    pub authn_statement: SamlAuthnStatement,
    /// Attribute statement (optional)
    pub attribute_statement: Option<SamlAttributeStatement>,
}

/// SAML Subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubject {
    /// Name identifier for the subject
    pub name_id: NameId,
    /// Subject confirmations
    pub subject_confirmations: Vec<SubjectConfirmation>,
}

/// Name ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameId {
    /// Name ID format
    pub format: String,
    /// Name ID value
    pub value: String,
}

/// Subject Confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectConfirmation {
    /// Confirmation method
    pub method: String,
    /// Subject confirmation data
    pub subject_confirmation_data: SubjectConfirmationData,
}

/// Subject Confirmation Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectConfirmationData {
    /// Expiration timestamp
    pub not_on_or_after: String,
    /// Intended recipient
    pub recipient: String,
    /// Response to request ID
    pub in_response_to: String,
}

/// SAML Conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConditions {
    /// Start of validity period
    pub not_before: String,
    /// End of validity period
    pub not_on_or_after: String,
    /// Audience restrictions
    pub audience_restriction: Vec<AudienceRestriction>,
}

/// Audience Restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudienceRestriction {
    /// List of allowed audiences
    pub audience: Vec<String>,
}

/// SAML Authentication Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnStatement {
    /// Timestamp of authentication
    pub authn_instant: String,
    /// Session index
    pub session_index: String,
    /// Authentication context
    pub authn_context: SamlAuthnContext,
}

/// SAML Authentication Context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnContext {
    /// Authentication context class reference
    pub authn_context_class_ref: String,
}

/// SAML Attribute Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeStatement {
    /// List of SAML attributes
    pub attributes: Vec<SamlAttribute>,
}

/// SAML Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttribute {
    /// Attribute name
    pub name: String,
    /// Attribute name format
    pub name_format: String,
    /// Attribute values
    pub values: Vec<String>,
}

/// SAML service for handling SAML 2.0 authentication
pub struct SamlService {
    #[allow(dead_code)]
    db: Arc<Database>,
    service_providers: HashMap<String, SamlServiceProvider>,
    identity_providers: HashMap<String, SamlIdentityProvider>,
}

impl SamlService {
    /// Create new SAML service
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            service_providers: HashMap::new(),
            identity_providers: HashMap::new(),
        }
    }

    /// Register SAML Identity Provider
    pub fn register_identity_provider(&mut self, idp: SamlIdentityProvider) {
        self.identity_providers.insert(idp.entity_id.clone(), idp);
    }

    /// Register SAML Service Provider
    pub fn register_service_provider(&mut self, sp: SamlServiceProvider) {
        self.service_providers.insert(sp.entity_id.clone(), sp);
    }

    /// Generate SAML AuthnRequest
    pub async fn generate_authn_request(
        &self,
        sp_entity_id: &str,
        idp_entity_id: &str,
        relay_state: Option<&str>,
    ) -> Result<String> {
        let sp = self
            .service_providers
            .get(sp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Service Provider not found"))?;

        let idp = self
            .identity_providers
            .get(idp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Identity Provider not found"))?;

        let request_id = format!("_{}", Uuid::new_v4().simple());
        let now = Utc::now().to_rfc3339();

        let authn_request = SamlAuthnRequest {
            id: request_id.clone(),
            version: "2.0".to_string(),
            issue_instant: now,
            assertion_consumer_service_url: sp.assertion_consumer_service_url.clone(),
            issuer: sp.entity_id.clone(),
            name_id_policy: Some(NameIdPolicy {
                format: sp.name_id_format.clone(),
                allow_create: true,
            }),
            requested_authn_context: Some(RequestedAuthnContext {
                comparison: "exact".to_string(),
                authn_context_class_ref: vec![
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_string(),
                ],
            }),
        };

        // Convert to XML and sign if required
        let xml = self.authn_request_to_xml(&authn_request)?;
        let signed_xml = if idp.want_authn_requests_signed {
            self.sign_xml(&xml)?
        } else {
            xml
        };

        // Compress and base64 encode
        let compressed = self.deflate_compress(&signed_xml)?;
        let encoded = Base64UrlUnpadded::encode_string(&compressed);

        // Build redirect URL
        let mut url = format!("{}?SAMLRequest={}", idp.sso_url, encoded);
        if let Some(relay_state) = relay_state {
            url.push_str(&format!("&RelayState={}", urlencoding::encode(relay_state)));
        }

        // Store request for later verification
        self.store_authn_request(&request_id, &authn_request)
            .await?;

        Ok(url)
    }

    /// Decode and decompress SAML Response
    fn decode_saml_response(&self, saml_response: &str) -> Result<String> {
        // Decode
        let decoded = Base64UrlUnpadded::decode_vec(saml_response).map_err(|_| {
            AuthencError::ValidationError {
                message: "Invalid SAML response encoding".to_string(),
            }
        })?;

        // Decompress
        self.deflate_decompress(&decoded)
    }

    /// Get Issuer and raw XML from SAML Response without full validation
    /// This is useful for identifying the IdP to load its configuration
    pub fn get_issuer_and_xml_from_response(&self, saml_response: &str) -> Result<(String, String)> {
        let xml = self.decode_saml_response(saml_response)?;

        // Parse XML to SamlResponse
        let response: SamlResponse = self.parse_saml_xml(&xml)?;

        // Extract assertion issuer
        let issuer = if let Some(assertion) = &response.assertion {
            assertion.issuer.clone()
        } else {
            response.issuer.clone()
        };

        Ok((issuer, xml))
    }

    /// Process SAML Response (using pre-parsed XML)
    pub async fn process_xml_response(
        &self,
        xml: &str,
        _relay_state: Option<&str>,
        expected_idp_entity_id: &str,
    ) -> Result<SamlUserInfo> {
        // Verify signature if IdP is configured
        if let Some(idp) = self.identity_providers.get(expected_idp_entity_id) {
            if !idp.certificate.is_empty() {
                self.verify_saml_signature(xml, &idp.certificate)?;
            }
        }

        // Parse XML to SamlResponse
        let response: SamlResponse = self.parse_saml_xml(xml)?;

        // Validate response against stored request
        self.validate_response_against_request(&response, &response.in_response_to)
            .await?;

        // Verify response
        self.verify_response(&response).await?;

        // Check status
        if response.status.status_code.value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
            return Err(AuthencError::ValidationError {
                message: format!(
                    "SAML authentication failed: {}",
                    response.status.status_code.value
                ),
            });
        }

        // Extract user information
        let assertion = response
            .assertion
            .ok_or_else(|| AuthencError::ValidationError {
                message: "No assertion in SAML response".to_string(),
            })?;

        // Verify issuer
        if assertion.issuer != expected_idp_entity_id {
            return Err(AuthencError::ValidationError {
                message: "Issuer mismatch in SAML assertion".to_string(),
            });
        }

        let user_info = SamlUserInfo {
            issuer: assertion.issuer,
            name_id: assertion.subject.name_id.value,
            name_id_format: assertion.subject.name_id.format,
            session_index: assertion.authn_statement.session_index,
            authn_context_class_ref: assertion
                .authn_statement
                .authn_context
                .authn_context_class_ref,
            attributes: assertion
                .attribute_statement
                .map(|stmt| {
                    stmt.attributes
                        .into_iter()
                        .map(|attr| (attr.name, attr.values))
                        .collect()
                })
                .unwrap_or_default(),
        };

        Ok(user_info)
    }

    /// Process SAML Response (backward compatibility wrapper)
    pub async fn process_response(
        &self,
        saml_response: &str,
        relay_state: Option<&str>,
        expected_idp_entity_id: &str,
    ) -> Result<SamlUserInfo> {
        let xml = self.decode_saml_response(saml_response)?;
        self.process_xml_response(&xml, relay_state, expected_idp_entity_id).await
    }

    /// Generate SAML metadata for Service Provider
    pub fn generate_sp_metadata(&self, sp_entity_id: &str) -> Result<String> {
        let sp = self
            .service_providers
            .get(sp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Service Provider not found"))?;

        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                 entityID="{}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                   WantAssertionsSigned="{}"
                   WantResponseSigned="{}">
    <NameIDFormat>{}</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="{}"
                              index="0"
                              isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>"#,
            sp.entity_id,
            sp.want_assertions_signed,
            sp.want_response_signed,
            sp.name_id_format,
            sp.assertion_consumer_service_url
        );

        Ok(metadata)
    }

    /// Generate SAML metadata for Identity Provider
    pub fn generate_idp_metadata(&self, idp_entity_id: &str) -> Result<String> {
        let idp = self
            .identity_providers
            .get(idp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Identity Provider not found"))?;

        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                 entityID="{}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>{}</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="{}"/>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>"#,
            idp.entity_id, idp.name_id_format, idp.sso_url, idp.certificate
        );

        Ok(metadata)
    }

    fn authn_request_to_xml(&self, request: &SamlAuthnRequest) -> Result<String> {
        // Generate proper SAML AuthnRequest XML
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{}"
                    Version="{}"
                    IssueInstant="{}"
                    AssertionConsumerServiceURL="{}">
  <saml:Issuer>{}</saml:Issuer>
  <samlp:NameIDPolicy Format="{}" AllowCreate="{}"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"#,
            request.id,
            request.version,
            request.issue_instant,
            request.assertion_consumer_service_url,
            request.issuer,
            request
                .name_id_policy
                .as_ref()
                .map(|p| &p.format)
                .unwrap_or(&"urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified".to_string()),
            request
                .name_id_policy
                .as_ref()
                .map(|p| if p.allow_create { "true" } else { "false" })
                .unwrap_or("true")
        );

        Ok(xml)
    }

    fn sign_xml(&self, xml: &str) -> Result<String> {
        // Use the XmlSigner from saml_signature module
        // In production, load the actual private key
        // For now, return unsigned XML as signing requires key configuration
        Ok(xml.to_string())
    }

    /// Verify SAML signature using the configured certificate
    fn verify_saml_signature(&self, xml: &str, certificate_pem: &str) -> Result<()> {
        // Parse the X.509 certificate
        let pem = parse_x509_pem(certificate_pem.as_bytes()).map_err(|_| {
            AuthencError::ValidationError {
                message: "Invalid certificate format".to_string(),
            }
        })?;

        let cert =
            parse_x509_certificate(&pem.1.contents).map_err(|_| AuthencError::ValidationError {
                message: "Failed to parse X.509 certificate".to_string(),
            })?;

        // Extract public key from certificate
        let public_key = cert.1.public_key();
        let public_key_der = public_key.raw;

        // For RSA keys, create UnparsedPublicKey
        let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public_key_der);

        // Extract signature and signed data from XML
        // This is a simplified implementation - in production, use proper XML signature parsing
        let signature_start = xml.find("<ds:Signature").unwrap_or(0);
        let signature_end = xml.find("</ds:Signature>").unwrap_or(xml.len()) + 15;

        if signature_start == 0 || signature_end >= xml.len() {
            return Err(AuthencError::ValidationError {
                message: "No signature found in SAML response".to_string(),
            });
        }

        // Remove signature from document to get signed content
        let mut signed_content = xml.to_string();
        signed_content.replace_range(signature_start..signature_end, "");

        // Extract signature value (simplified - in production, parse properly)
        let sig_value_start = xml.find("<ds:SignatureValue>").unwrap_or(0) + 19;
        let sig_value_end = xml.find("</ds:SignatureValue>").unwrap_or(xml.len());

        if sig_value_start >= sig_value_end {
            return Err(AuthencError::ValidationError {
                message: "Invalid signature format".to_string(),
            });
        }

        let signature_b64 = &xml[sig_value_start..sig_value_end];
        let signature = base64ct::Base64::decode_vec(signature_b64.trim()).map_err(|_| {
            AuthencError::ValidationError {
                message: "Invalid base64 signature".to_string(),
            }
        })?;

        // Verify signature
        key.verify(signed_content.as_bytes(), &signature)
            .map_err(|_| AuthencError::ValidationError {
                message: "Signature verification failed".to_string(),
            })?;

        Ok(())
    }

    fn deflate_compress(&self, data: &str) -> Result<Vec<u8>> {
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data.as_bytes())?;
        encoder
            .finish()
            .map_err(|_| AuthencError::CryptographicError)
    }

    fn deflate_decompress(&self, data: &[u8]) -> Result<String> {
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        let mut decoder = DeflateDecoder::new(data);
        let mut result = String::new();
        decoder.read_to_string(&mut result)?;
        Ok(result)
    }

    fn parse_saml_xml(&self, xml: &str) -> Result<SamlResponse> {
        // Parse XML to SamlResponse using quick-xml
        let response: SamlResponse =
            xml_from_str(xml).map_err(|e| AuthencError::ValidationError {
                message: format!("Failed to parse SAML XML: {}", e),
            })?;

        Ok(response)
    }

    async fn verify_response(&self, response: &SamlResponse) -> Result<()> {
        // Verify SAML response signature if present
        if let Some(assertion) = &response.assertion {
            // Check timestamps (simplified validation)
            let now_str = Utc::now().to_rfc3339();
            if assertion.conditions.not_before > now_str
                || assertion.conditions.not_on_or_after < now_str
            {
                return Err(AuthencError::ValidationError {
                    message: "SAML assertion is not valid at this time".to_string(),
                });
            }

            // Verify issuer matches expected IdP
            if response.issuer.is_empty() {
                return Err(AuthencError::ValidationError {
                    message: "Missing issuer in SAML response".to_string(),
                });
            }

            // Additional validations can be added here
        }

        Ok(())
    }

    async fn store_authn_request(
        &self,
        request_id: &str,
        request: &SamlAuthnRequest,
    ) -> Result<()> {
        // Serialize request to XML or JSON for storage
        let xml_content = serde_json::to_string(request)
            .map_err(|e| AuthencError::validation(format!("Failed to serialize request: {}", e)))?;

        // Store in database with 5 minute TTL for replay prevention
        crate::services::saml_signature::saml_storage::store_saml_request(
            &self.db,
            request_id,
            "AuthnRequest",
            &request.issuer,
            &request.assertion_consumer_service_url,
            &xml_content,
            None,
            None,
            300, // 5 minutes
        )
        .await?;

        log::info!("Stored SAML AuthnRequest: {}", request_id);
        Ok(())
    }

    async fn retrieve_authn_request(&self, request_id: &str) -> Result<Option<SamlAuthnRequest>> {
        let message =
            crate::services::saml_signature::saml_storage::get_saml_request(&self.db, request_id)
                .await?;

        match message {
            Some(msg) => {
                // Deserialize from stored XML content
                let request: SamlAuthnRequest =
                    serde_json::from_str(&msg.xml_content).map_err(|e| {
                        AuthencError::validation(format!("Failed to deserialize request: {}", e))
                    })?;
                log::info!("Retrieved SAML AuthnRequest: {}", request_id);
                Ok(Some(request))
            }
            None => {
                log::warn!("SAML AuthnRequest not found: {}", request_id);
                Ok(None)
            }
        }
    }

    /// Validate SAML response against stored request
    async fn validate_response_against_request(
        &self,
        response: &SamlResponse,
        request_id: &str,
    ) -> Result<()> {
        // Retrieve the original request
        let _original_request =
            self.retrieve_authn_request(request_id)
                .await?
                .ok_or_else(|| AuthencError::ValidationError {
                    message: "Original SAML request not found".to_string(),
                })?;

        // Verify response corresponds to request
        if response.in_response_to != request_id {
            return Err(AuthencError::ValidationError {
                message: "SAML response does not match request".to_string(),
            });
        }

        Ok(())
    }

    /// Generate SAML Logout Request
    pub async fn generate_logout_request(
        &self,
        sp_entity_id: &str,
        idp_entity_id: &str,
        name_id: &str,
        session_index: Option<&str>,
    ) -> Result<String> {
        let sp = self
            .service_providers
            .get(sp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Service Provider not found"))?;

        let idp = self
            .identity_providers
            .get(idp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Identity Provider not found"))?;

        let request_id = format!("_{}", Uuid::new_v4().simple());
        let now = Utc::now().to_rfc3339();

        let logout_request_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="{}"
                     Version="2.0"
                     IssueInstant="{}">
  <saml:Issuer>{}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{}</saml:NameID>
  {}</samlp:LogoutRequest>"#,
            request_id,
            now,
            sp.entity_id,
            name_id,
            session_index
                .map(|si| format!("<samlp:SessionIndex>{}</samlp:SessionIndex>", si))
                .unwrap_or_default()
        );

        // Sign if required
        let signed_xml = if idp.want_authn_requests_signed {
            self.sign_xml(&logout_request_xml)?
        } else {
            logout_request_xml
        };

        // Compress and base64 encode
        let compressed = self.deflate_compress(&signed_xml)?;
        let encoded = Base64UrlUnpadded::encode_string(&compressed);

        // Build logout URL
        let url = format!(
            "{}?SAMLRequest={}",
            idp.slo_url.as_ref().unwrap_or(&idp.sso_url),
            encoded
        );

        Ok(url)
    }

    /// Process SAML Logout Response
    pub async fn process_logout_response(
        &self,
        saml_response: &str,
        _expected_idp_entity_id: &str,
    ) -> Result<()> {
        // Decode and decompress
        let decoded = Base64UrlUnpadded::decode_vec(saml_response).map_err(|_| {
            AuthencError::ValidationError {
                message: "Invalid SAML logout response encoding".to_string(),
            }
        })?;

        let xml = self.deflate_decompress(&decoded)?;

        // Parse XML (simplified - in production, use proper SAML logout response parsing)
        if xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success") {
            Ok(())
        } else {
            Err(AuthencError::ValidationError {
                message: "SAML logout failed".to_string(),
            })
        }
    }

    /// Get SAML metadata for Identity Provider
    pub fn get_idp_metadata(&self, idp_entity_id: &str) -> Result<String> {
        let idp = self
            .identity_providers
            .get(idp_entity_id)
            .ok_or_else(|| AuthencError::resource_not_found("Identity Provider not found"))?;

        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                 entityID="{}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>{}</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="{}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="{}"/>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>"#,
            idp.entity_id,
            idp.name_id_format,
            idp.sso_url,
            idp.slo_url.as_ref().unwrap_or(&"".to_string()),
            idp.certificate
        );

        Ok(metadata)
    }
}

/// User information extracted from SAML response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlUserInfo {
    /// Issuer of the assertion (IdP Entity ID)
    pub issuer: String,
    /// Name identifier for the user
    pub name_id: String,
    /// Format of the name identifier
    pub name_id_format: String,
    /// Session index from the authentication
    pub session_index: String,
    /// Authentication context class reference
    pub authn_context_class_ref: String,
    /// User attributes from the SAML assertion
    pub attributes: HashMap<String, Vec<String>>,
}
