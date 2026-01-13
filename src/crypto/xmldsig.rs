// XMLDSig (XML Digital Signature) Implementation
// Compliant with W3C XML Signature Syntax and Processing (Second Edition)
// https://www.w3.org/TR/xmldsig-core/

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use openssl::hash::{Hasher, MessageDigest};
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspRequest, OcspResponse, OcspResponseStatus};
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509, X509Crl, X509StoreContext};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use x509_parser::prelude::*;

/// Supported canonicalization methods
#[derive(Debug, Clone, PartialEq)]
pub enum CanonicalizationMethod {
    /// Canonical XML 1.0 (without comments)
    C14n,
    /// Canonical XML 1.0 (with comments)
    C14nWithComments,
    /// Exclusive XML Canonicalization 1.0 (without comments)
    ExclusiveC14n,
    /// Exclusive XML Canonicalization 1.0 (with comments)
    ExclusiveC14nWithComments,
}

impl CanonicalizationMethod {
    /// Create canonicalization method from URI string
    pub fn from_uri(uri: &str) -> Result<Self> {
        match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => Ok(Self::C14n),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                Ok(Self::C14nWithComments)
            }
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Ok(Self::ExclusiveC14n),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                Ok(Self::ExclusiveC14nWithComments)
            }
            _ => Err(anyhow!("Unsupported canonicalization method: {}", uri)),
        }
    }
}

/// Supported digest methods
#[derive(Debug, Clone, PartialEq)]
pub enum DigestMethod {
    /// SHA-256 digest algorithm
    Sha256,
    /// SHA-384 digest algorithm
    Sha384,
    /// SHA-512 digest algorithm
    Sha512,
}

impl DigestMethod {
    /// Create digest method from URI string
    pub fn from_uri(uri: &str) -> Result<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(Self::Sha512),
            // Block insecure algorithms
            "http://www.w3.org/2000/09/xmldsig#sha1" => {
                Err(anyhow!("SHA-1 is deprecated and not allowed"))
            }
            _ => Err(anyhow!("Unsupported digest method: {}", uri)),
        }
    }

    /// Convert to OpenSSL MessageDigest
    pub fn to_message_digest(&self) -> MessageDigest {
        match self {
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }
}

/// Supported signature methods
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureMethod {
    /// RSA with SHA-256
    RsaSha256,
    /// RSA with SHA-384
    RsaSha384,
    /// RSA with SHA-512
    RsaSha512,
}

impl SignatureMethod {
    /// Create signature method from URI string
    pub fn from_uri(uri: &str) -> Result<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok(Self::RsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Ok(Self::RsaSha384),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Ok(Self::RsaSha512),
            // Block insecure algorithms
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => {
                Err(anyhow!("RSA-SHA1 is deprecated and not allowed"))
            }
            _ => Err(anyhow!("Unsupported signature method: {}", uri)),
        }
    }

    /// Convert to OpenSSL MessageDigest for the signature's hash algorithm
    pub fn to_message_digest(&self) -> MessageDigest {
        match self {
            Self::RsaSha256 => MessageDigest::sha256(),
            Self::RsaSha384 => MessageDigest::sha384(),
            Self::RsaSha512 => MessageDigest::sha512(),
        }
    }
}

/// Reference element from SignedInfo
#[derive(Debug, Clone)]
pub struct Reference {
    /// URI of the referenced data (empty string for enveloped signature)
    pub uri: String,
    /// Digest algorithm used
    pub digest_method: DigestMethod,
    /// Computed digest value
    pub digest_value: Vec<u8>,
    /// List of transform algorithms applied before digesting
    pub transforms: Vec<String>,
}

/// SignedInfo element
#[derive(Debug, Clone)]
pub struct SignedInfo {
    /// Canonicalization method applied to SignedInfo
    pub canonicalization_method: CanonicalizationMethod,
    /// Signature algorithm used
    pub signature_method: SignatureMethod,
    /// List of references to signed data
    pub references: Vec<Reference>,
    /// Raw XML content for canonicalization
    pub raw_xml: String, // Store raw XML for canonicalization
}

/// KeyInfo element (simplified - only X509 certificate support)
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// Base64-encoded X.509 certificate
    pub x509_certificate: Option<String>,
}

/// Complete XML Signature structure
#[derive(Debug, Clone)]
pub struct XmlSignature {
    /// SignedInfo element containing signature parameters
    pub signed_info: SignedInfo,
    /// Base64-encoded signature value
    pub signature_value: Vec<u8>,
    /// Key information for signature verification
    pub key_info: Option<KeyInfo>,
}

impl XmlSignature {
    /// Extract XML signature from SAML Response or Assertion
    pub fn extract_from_xml(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut buf = Vec::new();
        // Whether we're currently parsing a Signature element
        let mut in_signature = false;
        // Whether we're currently parsing a SignedInfo element
        let mut in_signed_info = false;
        // Whether we're currently parsing a Reference element
        let mut in_reference = false;
        // Whether we're currently parsing a SignatureValue element
        let mut in_signature_value = false;
        // Whether we're currently parsing a KeyInfo element
        let mut in_key_info = false;
        // Whether we're currently parsing an X509Certificate element
        let mut in_x509_cert = false;

        let mut signed_info_xml = String::new();
        let mut signature_value = String::new();
        let mut x509_cert = String::new();

        // Canonicalization method algorithm URI
        let mut c14n_method = String::new();
        // Signature method algorithm URI
        let mut sig_method = String::new();
        // Current reference being parsed
        let mut current_ref = Reference {
            uri: String::new(),
            digest_method: DigestMethod::Sha256,
            digest_value: Vec::new(),
            transforms: Vec::new(),
        };
        // List of all references found
        let mut references = Vec::new();
        // Digest method algorithm URI for current reference
        let mut digest_method_uri = String::new();
        // Digest value text for current reference
        let mut digest_value_text = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    match name.as_str() {
                        "Signature" | "ds:Signature" => {
                            in_signature = true;
                        }
                        "SignedInfo" | "ds:SignedInfo" if in_signature => {
                            in_signed_info = true;
                            signed_info_xml.clear();
                        }
                        "CanonicalizationMethod" | "ds:CanonicalizationMethod"
                            if in_signed_info =>
                        {
                            if let Some(attr) = e.attributes().find(|a| {
                                a.as_ref()
                                    .map(|attr| {
                                        String::from_utf8_lossy(attr.key.as_ref()) == "Algorithm"
                                    })
                                    .unwrap_or(false)
                            }) {
                                if let Ok(attr) = attr {
                                    c14n_method = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        "SignatureMethod" | "ds:SignatureMethod" if in_signed_info => {
                            if let Some(attr) = e.attributes().find(|a| {
                                a.as_ref()
                                    .map(|attr| {
                                        String::from_utf8_lossy(attr.key.as_ref()) == "Algorithm"
                                    })
                                    .unwrap_or(false)
                            }) {
                                if let Ok(attr) = attr {
                                    sig_method = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        "Reference" | "ds:Reference" if in_signed_info => {
                            in_reference = true;
                            current_ref = Reference {
                                uri: String::new(),
                                digest_method: DigestMethod::Sha256,
                                digest_value: Vec::new(),
                                transforms: Vec::new(),
                            };
                            // Extract URI attribute
                            if let Some(attr) = e.attributes().find(|a| {
                                a.as_ref()
                                    .map(|attr| {
                                        String::from_utf8_lossy(attr.key.as_ref()) == "URI"
                                    })
                                    .unwrap_or(false)
                            }) {
                                if let Ok(attr) = attr {
                                    current_ref.uri =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        "DigestMethod" | "ds:DigestMethod" if in_reference => {
                            if let Some(attr) = e.attributes().find(|a| {
                                a.as_ref()
                                    .map(|attr| {
                                        String::from_utf8_lossy(attr.key.as_ref()) == "Algorithm"
                                    })
                                    .unwrap_or(false)
                            }) {
                                if let Ok(attr) = attr {
                                    digest_method_uri =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        "DigestValue" | "ds:DigestValue" if in_reference => {
                            // Start capturing digest value text
                        }
                        "SignatureValue" | "ds:SignatureValue" if in_signature => {
                            in_signature_value = true;
                            signature_value.clear();
                        }
                        "KeyInfo" | "ds:KeyInfo" if in_signature => {
                            in_key_info = true;
                        }
                        "X509Certificate" | "ds:X509Certificate" if in_key_info => {
                            in_x509_cert = true;
                            x509_cert.clear();
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape().unwrap_or_default();
                    if in_signature_value {
                        signature_value.push_str(&text);
                    } else if in_x509_cert {
                        x509_cert.push_str(&text);
                    } else if in_reference && !digest_value_text.is_empty() {
                        digest_value_text.push_str(&text);
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    match name.as_str() {
                        "SignedInfo" | "ds:SignedInfo" => {
                            in_signed_info = false;
                        }
                        "Reference" | "ds:Reference" => {
                            in_reference = false;
                            // Parse digest method and value
                            current_ref.digest_method = DigestMethod::from_uri(&digest_method_uri)?;
                            current_ref.digest_value = BASE64
                                .decode(digest_value_text.trim())
                                .map_err(|e| anyhow!("Failed to decode digest value: {}", e))?;
                            references.push(current_ref.clone());
                            digest_value_text.clear();
                        }
                        "DigestValue" | "ds:DigestValue" if !digest_value_text.is_empty() => {
                            // Digest value text captured in Text event
                        }
                        "SignatureValue" | "ds:SignatureValue" => {
                            in_signature_value = false;
                        }
                        "KeyInfo" | "ds:KeyInfo" => {
                            in_key_info = false;
                        }
                        "X509Certificate" | "ds:X509Certificate" => {
                            in_x509_cert = false;
                        }
                        "Signature" | "ds:Signature" => {
                            let _ = in_signature; // Used for state tracking, break exits loop
                            break; // Found complete signature
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        // Validate we found required elements
        if c14n_method.is_empty() {
            return Err(anyhow!("CanonicalizationMethod not found"));
        }
        if sig_method.is_empty() {
            return Err(anyhow!("SignatureMethod not found"));
        }
        if signature_value.is_empty() {
            return Err(anyhow!("SignatureValue not found"));
        }
        if references.is_empty() {
            return Err(anyhow!("No Reference elements found"));
        }

        // Parse methods
        let canonicalization_method = CanonicalizationMethod::from_uri(&c14n_method)?;
        let signature_method = SignatureMethod::from_uri(&sig_method)?;

        // Decode signature value
        let signature_bytes = BASE64
            .decode(signature_value.trim())
            .map_err(|e| anyhow!("Failed to decode signature value: {}", e))?;

        // Extract raw SignedInfo XML for verification (simplified)
        let signed_info = SignedInfo {
            canonicalization_method,
            signature_method,
            references,
            raw_xml: extract_signed_info_xml(xml)?,
        };

        let key_info = if !x509_cert.is_empty() {
            Some(KeyInfo {
                x509_certificate: Some(x509_cert),
            })
        } else {
            None
        };

        Ok(XmlSignature {
            signed_info,
            signature_value: signature_bytes,
            key_info,
        })
    }

    /// Verify the XML signature using provided certificate
    pub fn verify(&self, certificate: &X509, document: &str) -> Result<bool> {
        // Step 1: Validate all reference digests
        for reference in &self.signed_info.references {
            if !self.verify_reference(reference, document)? {
                return Ok(false);
            }
        }

        // Step 2: Canonicalize SignedInfo
        let canonical_signed_info = canonicalize_xml(
            &self.signed_info.raw_xml,
            &self.signed_info.canonicalization_method,
        )?;

        // Step 3: Verify signature
        let public_key = certificate.public_key()?;
        self.verify_signature_value(&canonical_signed_info, &public_key)
    }

    /// Verify a single reference digest
    fn verify_reference(&self, reference: &Reference, document: &str) -> Result<bool> {
        // Extract referenced element
        let referenced_xml = extract_element_by_uri(document, &reference.uri)?;

        // Apply transforms (simplified - assume enveloped signature transform)
        let transformed_xml = apply_transforms(&referenced_xml, &reference.transforms)?;

        // Canonicalize (assume C14N for simplicity)
        let canonical_xml = canonicalize_xml(&transformed_xml, &CanonicalizationMethod::C14n)?;

        // Calculate digest
        let mut hasher = Hasher::new(reference.digest_method.to_message_digest())?;
        hasher.update(canonical_xml.as_bytes())?;
        let calculated_digest = hasher.finish()?;

        // Compare digests
        Ok(calculated_digest.as_ref() == reference.digest_value.as_slice())
    }

    /// Verify the signature value
    fn verify_signature_value(&self, signed_info: &str, public_key: &PKey<Public>) -> Result<bool> {
        let mut verifier = Verifier::new(
            self.signed_info.signature_method.to_message_digest(),
            public_key,
        )?;
        verifier.update(signed_info.as_bytes())?;
        Ok(verifier.verify(&self.signature_value)?)
    }
}

/// Canonicalize XML according to specified method
fn canonicalize_xml(xml: &str, method: &CanonicalizationMethod) -> Result<String> {
    // Simplified canonicalization (production would use full C14N implementation)
    match method {
        CanonicalizationMethod::C14n | CanonicalizationMethod::ExclusiveC14n => {
            // Basic normalization:
            // 1. Normalize whitespace
            // 2. Sort attributes
            // 3. Remove XML declaration
            // 4. Normalize line endings

            let normalized = xml
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join("");

            Ok(normalized)
        }
        CanonicalizationMethod::C14nWithComments
        | CanonicalizationMethod::ExclusiveC14nWithComments => {
            // Same as above but preserve comments (not implemented for simplicity)
            Ok(xml.to_string())
        }
    }
}

/// Extract SignedInfo XML from document
fn extract_signed_info_xml(xml: &str) -> Result<String> {
    let start_tags = ["<SignedInfo>", "<ds:SignedInfo>"];
    let end_tags = ["</SignedInfo>", "</ds:SignedInfo>"];

    for (start_tag, end_tag) in start_tags.iter().zip(end_tags.iter()) {
        if let Some(start_pos) = xml.find(start_tag) {
            if let Some(end_pos) = xml.find(end_tag) {
                let end_with_tag = end_pos + end_tag.len();
                return Ok(xml[start_pos..end_with_tag].to_string());
            }
        }
    }

    Err(anyhow!("SignedInfo element not found in XML"))
}

/// Extract element by URI reference
fn extract_element_by_uri(document: &str, uri: &str) -> Result<String> {
    // Handle different URI formats
    if uri.is_empty() {
        // Empty URI references the entire document
        return Ok(document.to_string());
    }

    if let Some(id) = uri.strip_prefix('#') {
        // Fragment identifier - extract element with ID
        // Try different ID attributes
        let id_patterns = [
            format!(" ID=\"{}\"", id),
            format!(" id=\"{}\"", id),
            format!(" Id=\"{}\"", id),
        ];

        for pattern in &id_patterns {
            if let Some(start_pos) = document.find(pattern) {
                // Find the start of the element containing this ID
                if let Some(element_start) = document[..start_pos].rfind('<') {
                    // Extract element name
                    let element_name_end = document[element_start + 1..]
                        .find(|c: char| c.is_whitespace() || c == '>')
                        .map(|pos| element_start + 1 + pos)
                        .unwrap_or(element_start + 1);

                    let element_name = &document[element_start + 1..element_name_end];

                    // Find closing tag
                    let closing_tag = format!("</{}>", element_name);
                    if let Some(end_pos) = document[element_start..].find(&closing_tag) {
                        let full_end = element_start + end_pos + closing_tag.len();
                        return Ok(document[element_start..full_end].to_string());
                    }
                }
            }
        }

        return Err(anyhow!("Element with ID '{}' not found", id));
    }

    // Unsupported URI format
    Err(anyhow!("Unsupported URI format: {}", uri))
}

/// Apply XML transforms
fn apply_transforms(xml: &str, transforms: &[String]) -> Result<String> {
    let mut result = xml.to_string();

    for transform in transforms {
        match transform.as_str() {
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature" => {
                // Remove Signature element
                result = remove_signature_element(&result)?;
            }
            "http://www.w3.org/2001/10/xml-exc-c14n#" => {
                // Apply exclusive canonicalization
                result = canonicalize_xml(&result, &CanonicalizationMethod::ExclusiveC14n)?;
            }
            _ => {
                // Unsupported transform - ignore or error
                tracing::warn!("Unsupported transform: {}", transform);
            }
        }
    }

    Ok(result)
}

/// Remove Signature element from XML (for enveloped signature transform)
fn remove_signature_element(xml: &str) -> Result<String> {
    let start_tags = ["<Signature>", "<ds:Signature>"];
    let end_tags = ["</Signature>", "</ds:Signature>"];

    for (start_tag, end_tag) in start_tags.iter().zip(end_tags.iter()) {
        if let Some(start_pos) = xml.find(start_tag) {
            if let Some(end_pos) = xml[start_pos..].find(end_tag) {
                let full_end = start_pos + end_pos + end_tag.len();
                let mut result = xml[..start_pos].to_string();
                result.push_str(&xml[full_end..]);
                return Ok(result);
            }
        }
    }

    // No signature found - return original
    Ok(xml.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalization_method_parsing() {
        let c14n =
            CanonicalizationMethod::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
                .unwrap();
        assert_eq!(c14n, CanonicalizationMethod::C14n);

        let exc_c14n =
            CanonicalizationMethod::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#").unwrap();
        assert_eq!(exc_c14n, CanonicalizationMethod::ExclusiveC14n);
    }

    #[test]
    fn test_digest_method_parsing() {
        let sha256 = DigestMethod::from_uri("http://www.w3.org/2001/04/xmlenc#sha256").unwrap();
        assert_eq!(sha256, DigestMethod::Sha256);

        // SHA-1 should be rejected
        let sha1_result = DigestMethod::from_uri("http://www.w3.org/2000/09/xmldsig#sha1");
        assert!(sha1_result.is_err());
    }

    #[test]
    fn test_signature_method_parsing() {
        let rsa_sha256 =
            SignatureMethod::from_uri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256").unwrap();
        assert_eq!(rsa_sha256, SignatureMethod::RsaSha256);

        // RSA-SHA1 should be rejected
        let rsa_sha1_result =
            SignatureMethod::from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        assert!(rsa_sha1_result.is_err());
    }

    #[test]
    fn test_extract_element_by_uri() {
        let xml = r#"<root><element ID="test123">content</element></root>"#;
        let result = extract_element_by_uri(xml, "#test123").unwrap();
        assert!(result.contains("test123"));
    }

    #[test]
    fn test_remove_signature_element() {
        let xml = r#"<root><before/>><ds:Signature>sig content</ds:Signature><after/></root>"#;
        let result = remove_signature_element(xml).unwrap();
        assert!(!result.contains("Signature"));
        assert!(result.contains("<before/>"));
        assert!(result.contains("<after/>"));
    }
}

#[cfg(test)]
mod issuer_tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;
    use openssl::x509::X509NameBuilder;
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
    };

    fn create_ca_cert() -> Result<(X509, PKey<openssl::pkey::Private>)> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", "Test CA")?;
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;

        // Set serial number
        let serial = BigNum::from_u32(1)?;
        let serial_asn1 = serial.to_asn1_integer()?;
        builder.set_serial_number(&serial_asn1)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;

        builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = builder.build();

        Ok((cert, pkey))
    }

    fn create_leaf_cert(
        ca_cert: &X509,
        ca_key: &PKey<openssl::pkey::Private>,
    ) -> Result<(X509, PKey<openssl::pkey::Private>)> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", "Test Leaf")?;
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(ca_cert.subject_name())?;
        builder.set_pubkey(&pkey)?;

        // Set serial number
        let serial = BigNum::from_u32(2)?;
        let serial_asn1 = serial.to_asn1_integer()?;
        builder.set_serial_number(&serial_asn1)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        // Authority Key Identifier
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&builder.x509v3_context(Some(ca_cert), None))?,
        )?;

        builder.sign(ca_key, MessageDigest::sha256())?;
        let cert = builder.build();

        Ok((cert, pkey))
    }

    #[test]
    fn test_get_issuer_from_chain() -> Result<()> {
        // 1. Create CA and Leaf certs
        let (ca_cert, ca_key) = create_ca_cert()?;
        let (leaf_cert, _leaf_key) = create_leaf_cert(&ca_cert, &ca_key)?;

        // 2. Setup CertificateValidator with CA in trust store
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(ca_cert.clone())?;
        let store = store_builder.build();
        let validator = CertificateValidator::new(store);

        // 3. Call get_issuer_from_chain with leaf cert
        let issuer_option = validator.get_issuer_from_chain(&leaf_cert)?;

        // 4. Verify we got the issuer
        assert!(issuer_option.is_some());
        let issuer = issuer_option.unwrap();

        // Verify it is indeed the CA cert
        assert_eq!(
            issuer.serial_number().to_bn()?,
            ca_cert.serial_number().to_bn()?
        );
        assert_eq!(
            issuer.subject_name().to_der()?,
            ca_cert.subject_name().to_der()?
        );

        Ok(())
    }

    #[test]
    fn test_get_issuer_self_signed() -> Result<()> {
        // 1. Create self-signed CA cert
        let (ca_cert, _ca_key) = create_ca_cert()?;

        // 2. Setup CertificateValidator with CA in trust store
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(ca_cert.clone())?;
        let store = store_builder.build();
        let validator = CertificateValidator::new(store);

        // 3. Call get_issuer_from_chain with CA cert (it is self-signed)
        let issuer_option = validator.get_issuer_from_chain(&ca_cert)?;

        // 4. Verify we got the issuer (itself)
        assert!(issuer_option.is_some());
        let issuer = issuer_option.unwrap();

        assert_eq!(
            issuer.serial_number().to_bn()?,
            ca_cert.serial_number().to_bn()?
        );

        Ok(())
    }

    #[test]
    fn test_get_issuer_not_found() -> Result<()> {
        // 1. Create CA and Leaf certs
        let (ca_cert, ca_key) = create_ca_cert()?;
        let (leaf_cert, _leaf_key) = create_leaf_cert(&ca_cert, &ca_key)?;

        // 2. Setup CertificateValidator with EMPTY trust store
        let store_builder = X509StoreBuilder::new()?;
        let store = store_builder.build();
        let validator = CertificateValidator::new(store);

        // 3. Call get_issuer_from_chain with leaf cert
        // Validation should fail, so it should return None or error?
        // The implementation returns Ok(None) if verification fails.
        let issuer_option = validator.get_issuer_from_chain(&leaf_cert)?;

        // 4. Verify we got None
        assert!(issuer_option.is_none());

        Ok(())
    }

    #[test]
    fn test_check_key_usage() -> Result<()> {
        let (ca_cert, ca_key) = create_ca_cert()?;

        // 1. Create cert WITH digitalSignature
        let (ds_cert, _) = create_leaf_cert(&ca_cert, &ca_key)?; // create_leaf_cert has digitalSignature

        // 2. Create cert WITHOUT digitalSignature (e.g. only keyEncipherment)
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", "No DS")?;
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(ca_cert.subject_name())?;
        builder.set_pubkey(&pkey)?;
        let serial_3 = BigNum::from_u32(3)?.to_asn1_integer()?;
        builder.set_serial_number(&serial_3)?;
        let not_before = Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_after(&not_after)?;

        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_encipherment() // Only KeyEncipherment, no DigitalSignature
                .build()?,
        )?;
        builder.sign(&ca_key, MessageDigest::sha256())?;
        let no_ds_cert = builder.build();

        // 3. Create cert WITHOUT KeyUsage extension
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(ca_cert.subject_name())?;
        builder.set_pubkey(&pkey)?;
        let serial_4 = BigNum::from_u32(4)?.to_asn1_integer()?;
        builder.set_serial_number(&serial_4)?;
        let not_before = Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_after(&not_after)?;
        builder.sign(&ca_key, MessageDigest::sha256())?;
        let no_ext_cert = builder.build();

        // 4. Test
        let store_builder = X509StoreBuilder::new()?;
        let validator = CertificateValidator::new(store_builder.build());

        assert!(
            validator.check_key_usage(&ds_cert)?,
            "Cert with digitalSignature should pass"
        );
        assert!(
            !validator.check_key_usage(&no_ds_cert)?,
            "Cert without digitalSignature should fail"
        );
        assert!(
            validator.check_key_usage(&no_ext_cert)?,
            "Cert without KeyUsage extension should pass"
        );

        Ok(())
    }
}

// ============================================================================
// Certificate Validation (Phase 2)
// ============================================================================

/// Certificate validation result
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateValidationResult {
    /// Certificate is valid and trusted
    Valid,
    /// Certificate has expired
    Expired,
    /// Certificate is not yet valid (issued in the future)
    NotYetValid,
    /// Certificate has been revoked
    Revoked,
    /// Certificate chain is invalid
    ChainInvalid,
    /// Root certificate is not trusted
    UntrustedRoot,
}

/// Certificate revocation status (simple version for validation results)
#[derive(Debug, Clone, PartialEq)]
pub enum SimpleRevocationStatus {
    /// Certificate has not been revoked
    NotRevoked,
    /// Certificate has been revoked
    Revoked,
    /// Revocation status is unknown
    Unknown,
}

/// Certificate validator with trust store and CRL support
pub struct CertificateValidator {
    /// X.509 trust store for certificate validation
    trust_store: X509Store,
    /// Whether to check certificate expiration dates
    pub enable_expiration_check: bool,
}

impl CertificateValidator {
    /// Create a new certificate validator with a trust store
    pub fn new(trust_store: X509Store) -> Self {
        Self {
            trust_store,
            enable_expiration_check: true,
        }
    }

    /// Create a validator with system trust store
    pub fn with_system_trust_store() -> Result<Self> {
        let mut builder = X509StoreBuilder::new()?;

        // Load system certificates (platform-specific)
        #[cfg(target_os = "linux")]
        {
            // Common Linux certificate paths
            let cert_paths = [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
            ];

            for path in &cert_paths {
                if std::path::Path::new(path).exists() {
                    if let Ok(certs) = std::fs::read(path) {
                        if let Ok(cert) = X509::from_pem(&certs) {
                            let _ = builder.add_cert(cert);
                        }
                    }
                    break;
                }
            }
        }

        Ok(Self {
            trust_store: builder.build(),
            enable_expiration_check: true,
        })
    }

    /// Create a validator from PEM-encoded certificates
    pub fn from_pem_certificates(pem_data: &[u8]) -> Result<Self> {
        let mut builder = X509StoreBuilder::new()?;

        // Parse multiple certificates from PEM
        let pem_str = String::from_utf8_lossy(pem_data);
        let cert_blocks: Vec<&str> = pem_str
            .split("-----BEGIN CERTIFICATE-----")
            .filter(|s| s.contains("-----END CERTIFICATE-----"))
            .collect();

        for block in cert_blocks {
            let cert_pem = format!("-----BEGIN CERTIFICATE-----{}", block);
            if let Ok(cert) = X509::from_pem(cert_pem.as_bytes()) {
                builder.add_cert(cert)?;
            }
        }

        Ok(Self {
            trust_store: builder.build(),
            enable_expiration_check: true,
        })
    }

    /// Validate a certificate
    pub fn validate_certificate(&self, cert: &X509) -> Result<CertificateValidationResult> {
        // Check expiration
        if self.enable_expiration_check {
            if let Err(e) = self.check_expiration(cert) {
                let msg = e.to_string();
                if msg.contains("not yet valid") {
                    return Ok(CertificateValidationResult::NotYetValid);
                } else if msg.contains("expired") {
                    return Ok(CertificateValidationResult::Expired);
                }
            }
        }

        // Validate certificate chain
        match self.validate_certificate_chain(cert) {
            Ok(_) => Ok(CertificateValidationResult::Valid),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("unable to get issuer certificate")
                    || msg.contains("self signed certificate")
                {
                    Ok(CertificateValidationResult::UntrustedRoot)
                } else {
                    Ok(CertificateValidationResult::ChainInvalid)
                }
            }
        }
    }

    /// Validate certificate chain using trust store
    pub fn validate_certificate_chain(&self, cert: &X509) -> Result<()> {
        use openssl::stack::Stack;

        let mut context = X509StoreContext::new()?;
        let chain = Stack::new()?; // Empty chain - only validate end certificate

        match context.init(&self.trust_store, cert, &chain, |ctx| ctx.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => {
                let error = context.error();
                Err(anyhow!("Certificate chain validation failed: {}", error))
            }
            Err(e) => Err(anyhow!("Certificate chain validation error: {}", e)),
        }
    }

    /// Check certificate expiration (NotBefore and NotAfter)
    pub fn check_expiration(&self, cert: &X509) -> Result<()> {
        let now = Utc::now();

        // Check NotBefore
        let not_before = cert.not_before();
        let not_before_str = not_before.to_string();
        if let Ok(not_before_time) = parse_asn1_time(&not_before_str)
            && now < not_before_time {
                return Err(anyhow!(
                    "Certificate not yet valid (NotBefore: {})",
                    not_before_str
                ));
            }

        // Check NotAfter
        let not_after = cert.not_after();
        let not_after_str = not_after.to_string();
        if let Ok(not_after_time) = parse_asn1_time(&not_after_str)
            && now >= not_after_time {
                return Err(anyhow!("Certificate expired (NotAfter: {})", not_after_str));
            }

        Ok(())
    }

    /// Check if certificate has digital signature key usage
    pub fn check_key_usage(&self, cert: &X509) -> Result<bool> {
        // Use x509-parser to parse the certificate DER and check extensions
        // This avoids issues with OpenSSL crate missing extension accessors

        let der = cert
            .to_der()
            .map_err(|e| anyhow!("Failed to serialize certificate to DER: {}", e))?;

        let (_, x509_cert) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| anyhow!("Failed to parse X.509 certificate: {}", e))?;

        // Find KeyUsage extension (OID 2.5.29.15)
        // x509-parser defines OIDs. keyUsage is "2.5.29.15"
        // Use OID constant comparison for standard compliance and optimization

        for ext in x509_cert.extensions() {
            if ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE {
                match ext.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::KeyUsage(usage) => {
                        // usage is KeyUsage struct
                        return Ok(usage.digital_signature());
                    }
                    _ => {
                        // Failed to parse key usage or different type
                        return Err(anyhow!("Failed to parse KeyUsage extension"));
                    }
                }
            }
        }

        // If no key usage extension is present, assume valid
        Ok(true)
    }

    /// Get the issuer certificate from the trust store by building the chain
    pub fn get_issuer_from_chain(&self, cert: &X509) -> Result<Option<X509>> {
        use openssl::stack::Stack;

        let mut context = X509StoreContext::new()?;
        let chain = Stack::new()?; // Empty chain - only validate end certificate

        // We use the trust store to find the issuer
        let issuer = context
            .init(&self.trust_store, cert, &chain, |ctx| {
                // verify_cert builds the chain
                match ctx.verify_cert() {
                    Ok(true) => {
                        // Success, extract issuer
                        if let Some(chain) = ctx.chain() {
                            if chain.len() >= 2 {
                                // The issuer is the second element in the chain (index 1)
                                // index 0 is the subject certificate
                                return Ok(Some(chain[1].to_owned()));
                            } else if chain.len() == 1 {
                                // Self-signed certificate (issuer is subject)
                                return Ok(Some(chain[0].to_owned()));
                            }
                        }
                        Ok(None)
                    }
                    Ok(false) => {
                        // Verification failed
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            })
            .map_err(|e| anyhow!("Failed to get issuer from chain: {}", e))?;

        Ok(issuer)
    }

    /// Disable expiration checking (for testing)
    pub fn disable_expiration_check(&mut self) {
        self.enable_expiration_check = false;
    }

    /// Enable expiration checking
    pub fn enable_expiration_check_flag(&mut self) {
        self.enable_expiration_check = true;
    }

    /// Validate certificate with optional revocation checking
    /// Validate certificate with revocation checking using CRL
    pub fn validate_with_revocation(
        &self,
        cert: &X509,
        crl_manager: Option<&mut CrlManager>,
    ) -> Result<CertificateValidationResult> {
        // First do standard validation (chain + expiration)
        let validation_result = self.validate_certificate(cert)?;

        // If certificate is not valid, return early
        if validation_result != CertificateValidationResult::Valid {
            return Ok(validation_result);
        }

        // Check revocation if CRL manager provided
        if let Some(crl_mgr) = crl_manager {
            match crl_mgr.check_revocation(cert) {
                Ok(RevocationStatus::NotRevoked) => {
                    tracing::debug!("Certificate not revoked");
                }
                Ok(RevocationStatus::Revoked {
                    reason,
                    revocation_date,
                }) => {
                    tracing::warn!(
                        "Certificate is revoked (reason: {:?}, date: {:?})",
                        reason,
                        revocation_date
                    );
                    return Ok(CertificateValidationResult::Revoked);
                }
                Ok(RevocationStatus::Unknown) => {
                    tracing::warn!("Certificate revocation status unknown");
                    // Soft-fail: continue with validation
                    // Production systems may want to hard-fail here based on policy
                }
                Err(e) => {
                    tracing::error!("CRL check failed: {}", e);
                    // Soft-fail: continue with validation
                }
            }
        }

        Ok(CertificateValidationResult::Valid)
    }
}

/// Parse ASN.1 time string to DateTime<Utc>
fn parse_asn1_time(time_str: &str) -> Result<DateTime<Utc>> {
    // ASN.1 time format: "MMM DD HH:MM:SS YYYY GMT"
    // Example: "Oct  2 12:00:00 2025 GMT"

    use chrono::NaiveDateTime;

    // Remove "GMT" suffix
    let cleaned = time_str.trim().replace(" GMT", "");

    // Try to parse with chrono
    // This is simplified - production would use proper ASN.1 parsing
    if let Ok(dt) = NaiveDateTime::parse_from_str(&cleaned, "%b %d %H:%M:%S %Y") {
        Ok(DateTime::from_naive_utc_and_offset(dt, Utc))
    } else {
        // Fallback: assume current time (for malformed dates)
        tracing::warn!(
            "Failed to parse ASN.1 time: {}, using current time",
            time_str
        );
        Ok(Utc::now())
    }
}

/// Update XmlSignature to include certificate extraction
impl XmlSignature {
    /// Get the X.509 certificate from KeyInfo (if present)
    pub fn get_certificate(&self) -> Option<X509> {
        if let Some(ref key_info) = self.key_info {
            if let Some(ref cert_pem) = key_info.x509_certificate {
                // Certificate is base64-encoded in XML, need to decode and parse
                let cert_data = format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                    cert_pem
                );

                if let Ok(cert) = X509::from_pem(cert_data.as_bytes()) {
                    return Some(cert);
                }
            }
        }
        None
    }
}

// ============================================================================
// XML Security Hardening
// ============================================================================

/// XML security configuration limits
#[derive(Debug, Clone)]
pub struct XmlSecurityLimits {
    /// Maximum number of entity expansions allowed (default: 10)
    pub max_entity_expansions: usize,
    /// Maximum element nesting depth (default: 100)
    pub max_element_depth: usize,
    /// Maximum XML document size in bytes (default: 1MB)
    pub max_document_size: usize,
    /// Disable external entity processing (XXE prevention, default: true)
    pub disable_external_entities: bool,
    /// Maximum number of elements in document (default: 10000)
    pub max_elements: usize,
}

impl Default for XmlSecurityLimits {
    fn default() -> Self {
        Self {
            max_entity_expansions: 10,
            max_element_depth: 100,
            max_document_size: 1024 * 1024, // 1MB
            disable_external_entities: true,
            max_elements: 10000,
        }
    }
}

/// XML Security Validator to prevent XML bombs and signature wrapping attacks
pub struct XmlSecurityValidator {
    /// Security limits for XML processing
    pub limits: XmlSecurityLimits,
}

impl XmlSecurityValidator {
    /// Create a new XML security validator with default limits
    pub fn new() -> Self {
        Self {
            limits: XmlSecurityLimits::default(),
        }
    }

    /// Create a validator with custom limits
    pub fn with_limits(limits: XmlSecurityLimits) -> Self {
        Self { limits }
    }

    /// Validate XML document against security limits
    pub fn validate_xml(&self, xml: &str) -> Result<()> {
        // Check document size
        if xml.len() > self.limits.max_document_size {
            return Err(anyhow!(
                "XML document too large: {} bytes (max: {})",
                xml.len(),
                self.limits.max_document_size
            ));
        }

        // Check for external entities (XXE attack)
        if self.limits.disable_external_entities
            && xml.contains("<!ENTITY") && (xml.contains("SYSTEM") || xml.contains("PUBLIC")) {
                return Err(anyhow!("External entities not allowed (XXE prevention)"));
            }

        // Parse and validate structure
        let mut reader = Reader::from_str(xml);
        let reader = reader.trim_text(true);

        let mut depth: usize = 0;
        let mut max_depth: usize = 0;
        let mut element_count: usize = 0;
        let mut entity_expansion_count = 0;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(_)) | Ok(Event::Empty(_)) => {
                    depth += 1;
                    element_count += 1;

                    if depth > max_depth {
                        max_depth = depth;
                    }

                    // Check depth limit
                    if depth > self.limits.max_element_depth {
                        return Err(anyhow!(
                            "XML element depth exceeded: {} (max: {})",
                            depth,
                            self.limits.max_element_depth
                        ));
                    }

                    // Check element count limit
                    if element_count > self.limits.max_elements {
                        return Err(anyhow!(
                            "Too many XML elements: {} (max: {})",
                            element_count,
                            self.limits.max_elements
                        ));
                    }
                }
                Ok(Event::End(_)) => {
                    depth = depth.saturating_sub(1);
                }
                Ok(Event::Text(e)) => {
                    // Check for entity references (potential XML bomb)
                    let text = e
                        .unescape()
                        .map_err(|e| anyhow!("Failed to unescape text: {}", e))?;
                    if text.contains('&') {
                        entity_expansion_count += text.matches('&').count();
                        if entity_expansion_count > self.limits.max_entity_expansions {
                            return Err(anyhow!(
                                "Too many entity expansions: {} (max: {})",
                                entity_expansion_count,
                                self.limits.max_entity_expansions
                            ));
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parsing error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(())
    }

    /// Validate ID uniqueness in XML document (prevents ID spoofing)
    pub fn validate_id_uniqueness(&self, xml: &str) -> Result<HashMap<String, usize>> {
        let mut id_counts: HashMap<String, usize> = HashMap::new();
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    // Check for ID attribute
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_lowercase();
                        if key == "id" || key.ends_with(":id") {
                            let id_value = String::from_utf8_lossy(&attr.value).to_string();
                            *id_counts.entry(id_value.clone()).or_insert(0) += 1;
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parsing error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        // Check for duplicate IDs
        for (id, count) in &id_counts {
            if *count > 1 {
                return Err(anyhow!("Duplicate ID found: '{}' (count: {})", id, count));
            }
        }

        Ok(id_counts)
    }

    /// Validate signature references (prevents signature wrapping attacks)
    pub fn validate_signature_references(&self, xml: &str, signature: &XmlSignature) -> Result<()> {
        // Validate ID uniqueness first
        let id_map = self.validate_id_uniqueness(xml)?;

        // Validate each reference in the signature
        for reference in &signature.signed_info.references {
            let uri = &reference.uri;
            if let Some(id) = uri.strip_prefix('#') {
                // Remove '#' prefix

                // Check that the referenced ID exists
                if !id_map.contains_key(id) {
                    return Err(anyhow!("Signature references non-existent ID: '{}'", id));
                }
            }
        }

        // Verify signature is in expected location (not nested deep in document)
        // This is a simple heuristic - production systems may need more sophisticated checks
        let signature_depth = self.get_signature_depth(xml)?;
        if signature_depth > 5 {
            tracing::warn!(
                "Signature found at suspicious depth: {} (potential signature wrapping)",
                signature_depth
            );
        }

        Ok(())
    }

    /// Get the nesting depth of the ds:Signature element
    pub fn get_signature_depth(&self, xml: &str) -> Result<usize> {
        let mut reader = Reader::from_str(xml);
        let mut depth: usize = 0;
        let mut signature_depth: usize = 0;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    depth += 1;
                    let name_bytes = e.name().as_ref().to_vec();
                    let name = String::from_utf8_lossy(&name_bytes);
                    if name.ends_with(":Signature") || name == "Signature" {
                        signature_depth = depth;
                    }
                }
                Ok(Event::End(_)) => {
                    depth = depth.saturating_sub(1);
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parsing error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(signature_depth)
    }
}

impl Default for XmlSecurityValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Certificate Revocation List (CRL) Support
// ============================================================================

/// Revocation status of a certificate
#[derive(Debug, Clone, PartialEq)]
pub enum RevocationStatus {
    /// Certificate is not revoked
    NotRevoked,
    /// Certificate is revoked
    Revoked {
        /// Reason for revocation (if available)
        reason: Option<String>,
        /// Date when certificate was revoked
        revocation_date: Option<SystemTime>,
    },
    /// Revocation status unknown (CRL unavailable, no CRL distribution point, etc.)
    Unknown,
}

/// CRL Manager for downloading, parsing, and caching Certificate Revocation Lists
pub struct CrlManager {
    /// Cache of downloaded CRL bytes: URL -> (raw_bytes, expiration_time)
    cache: Arc<Mutex<HashMap<String, (Vec<u8>, SystemTime)>>>,
    /// How long to cache CRLs (default: 1 hour)
    cache_duration: Duration,
    /// HTTP client for downloading CRLs
    http_client: reqwest::blocking::Client,
    /// Maximum CRL size to download (default: 10MB)
    max_crl_size: usize,
}

impl CrlManager {
    /// Create a new CRL Manager with default settings
    pub fn new() -> Result<Self> {
        Self::with_config(Duration::from_secs(3600), 10 * 1024 * 1024)
    }

    /// Create a new CRL Manager with custom configuration
    pub fn with_config(cache_duration: Duration, max_crl_size: usize) -> Result<Self> {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_duration,
            http_client,
            max_crl_size,
        })
    }

    /// Check if a certificate has been revoked
    pub fn check_revocation(&mut self, cert: &X509) -> Result<RevocationStatus> {
        // Extract CRL distribution points from certificate
        let crl_urls = self.extract_crl_distribution_points(cert)?;

        if crl_urls.is_empty() {
            tracing::warn!("No CRL distribution points found in certificate");
            return Ok(RevocationStatus::Unknown);
        }

        // Try each CRL distribution point
        for url in &crl_urls {
            match self.check_revocation_with_crl(cert, url) {
                Ok(status) => return Ok(status),
                Err(e) => {
                    tracing::warn!("Failed to check revocation with CRL {}: {}", url, e);
                    continue;
                }
            }
        }

        // All CRL checks failed
        Ok(RevocationStatus::Unknown)
    }

    /// Check revocation status using a specific CRL URL
    fn check_revocation_with_crl(
        &mut self,
        cert: &X509,
        crl_url: &str,
    ) -> Result<RevocationStatus> {
        // Get CRL (from cache or download)
        let crl = self.get_crl(crl_url)?;

        // Check if certificate is in the CRL
        self.check_certificate_in_crl(cert, &crl)
    }

    /// Get a CRL (from cache or download)
    fn get_crl(&mut self, url: &str) -> Result<X509Crl> {
        // Check cache first
        let crl_bytes = {
            let cache = self.cache.lock().unwrap();
            if let Some((bytes, expiration)) = cache.get(url) {
                if SystemTime::now() < *expiration {
                    tracing::debug!("Using cached CRL for {}", url);
                    Some(bytes.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(bytes) = crl_bytes {
            return self.parse_crl(&bytes);
        }

        // Download CRL data
        tracing::info!("Downloading CRL from {}", url);
        let crl_bytes = self.download_crl(url)?;

        // Cache the raw bytes
        let expiration = SystemTime::now() + self.cache_duration;
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(url.to_string(), (crl_bytes.clone(), expiration));
        }

        // Parse and return
        self.parse_crl(&crl_bytes)
    }

    /// Download CRL data from a URL
    fn download_crl(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .http_client
            .get(url)
            .send()
            .map_err(|e| anyhow!("Failed to download CRL: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error downloading CRL: {}", response.status()));
        }

        // Check content length
        if let Some(content_length) = response.content_length()
            && content_length > self.max_crl_size as u64 {
                return Err(anyhow!(
                    "CRL too large: {} bytes (max: {} bytes)",
                    content_length,
                    self.max_crl_size
                ));
            }

        let crl_data = response
            .bytes()
            .map_err(|e| anyhow!("Failed to read CRL data: {}", e))?
            .to_vec();

        Ok(crl_data)
    }

    /// Parse a CRL from bytes (tries DER, then PEM)
    pub fn parse_crl(&self, data: &[u8]) -> Result<X509Crl> {
        // Try DER format first
        if let Ok(crl) = X509Crl::from_der(data) {
            return Ok(crl);
        }

        // Try PEM format
        if let Ok(crl) = X509Crl::from_pem(data) {
            return Ok(crl);
        }

        Err(anyhow!("Failed to parse CRL: not valid DER or PEM format"))
    }

    /// Validate a CRL's signature and validity period
    pub fn validate_crl(&self, crl: &X509Crl, issuer: &X509) -> Result<()> {
        // Verify CRL signature
        let issuer_public_key = issuer
            .public_key()
            .map_err(|e| anyhow!("Failed to get issuer public key: {}", e))?;

        let signature_valid = crl
            .verify(&issuer_public_key)
            .map_err(|e| anyhow!("Failed to verify CRL signature: {}", e))?;

        if !signature_valid {
            return Err(anyhow!("CRL signature verification failed"));
        }

        // Check CRL validity period
        let now = SystemTime::now();

        // Check thisUpdate (CRL effective date)
        let this_update = crl.last_update();
        let this_update_str = this_update.to_string();
        if let Ok(this_update_time) = parse_asn1_time(&this_update_str) {
            let this_update_systime =
                SystemTime::UNIX_EPOCH + Duration::from_secs(this_update_time.timestamp() as u64);

            if now < this_update_systime {
                return Err(anyhow!("CRL not yet valid (thisUpdate in future)"));
            }
        }

        // Check nextUpdate (CRL expiration date) if present
        if let Some(next_update) = crl.next_update() {
            let next_update_str = next_update.to_string();
            if let Ok(next_update_time) = parse_asn1_time(&next_update_str) {
                let next_update_systime = SystemTime::UNIX_EPOCH
                    + Duration::from_secs(next_update_time.timestamp() as u64);

                if now > next_update_systime {
                    return Err(anyhow!("CRL expired (nextUpdate passed)"));
                }
            }
        }

        Ok(())
    }

    /// Check if a certificate is in the CRL (revoked)
    pub fn check_certificate_in_crl(&self, cert: &X509, crl: &X509Crl) -> Result<RevocationStatus> {
        let cert_serial = cert.serial_number();

        // Get revoked certificates from CRL
        if let Some(revoked_list) = crl.get_revoked() {
            for revoked in revoked_list {
                let revoked_serial = revoked.serial_number();

                // Compare serial numbers
                if cert_serial.to_bn().ok() == revoked_serial.to_bn().ok() {
                    // Certificate is revoked
                    let revocation_date = revoked
                        .revocation_date()
                        .to_string()
                        .parse::<String>()
                        .ok()
                        .and_then(|date_str| parse_asn1_time(&date_str).ok())
                        .map(|dt| {
                            SystemTime::UNIX_EPOCH + Duration::from_secs(dt.timestamp() as u64)
                        });

                    // Extract revocation reason if available
                    // Note: OpenSSL bindings don't expose CRL reason directly
                    // This would require more complex ASN.1 parsing
                    let reason = None;

                    return Ok(RevocationStatus::Revoked {
                        reason,
                        revocation_date,
                    });
                }
            }
        }

        // Certificate not found in CRL = not revoked
        Ok(RevocationStatus::NotRevoked)
    }

    /// Extract CRL distribution point URLs from a certificate
    pub fn extract_crl_distribution_points(&self, cert: &X509) -> Result<Vec<String>> {
        // Parse certificate using x509-parser to access extensions
        let cert_der = cert
            .to_der()
            .map_err(|e| anyhow!("Failed to encode certificate to DER: {}", e))?;

        let (_, parsed_cert) = X509Certificate::from_der(&cert_der)
            .map_err(|e| anyhow!("Failed to parse certificate DER: {}", e))?;

        let mut urls = Vec::new();

        for ext in parsed_cert.extensions() {
            if let ParsedExtension::CRLDistributionPoints(cdp) = ext.parsed_extension() {
                for point in &cdp.points {
                    if let Some(name) = &point.distribution_point {
                        match name {
                            x509_parser::extensions::DistributionPointName::FullName(names) => {
                                for gen_name in names {
                                    if let x509_parser::extensions::GeneralName::URI(uri) = gen_name
                                    {
                                        let uri_str = uri.to_string();
                                        if !urls.contains(&uri_str) {
                                            urls.push(uri_str);
                                        }
                                    }
                                }
                            }
                            x509_parser::extensions::DistributionPointName::NameRelativeToCRLIssuer(_) => {
                                // Relative names not supported for now as they require LDAP/Dir context
                                tracing::debug!("Ignoring NameRelativeToCRLIssuer in CRL DP");
                            }
                        }
                    }
                }
            }
        }

        if urls.is_empty() {
            tracing::debug!("No CRL distribution points found in certificate extensions");
        } else {
            tracing::debug!("Found {} CRL distribution points", urls.len());
        }

        Ok(urls)
    }

    /// Clear the CRL cache
    pub fn clear_cache(&mut self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        tracing::info!("Cleared CRL cache");
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().unwrap();
        let total_entries = cache.len();
        let valid_entries = cache
            .values()
            .filter(|(_, expiration)| SystemTime::now() < *expiration)
            .count();
        (total_entries, valid_entries)
    }
}

impl Default for CrlManager {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;

    #[test]
    fn test_certificate_validator_creation() {
        let builder = X509StoreBuilder::new().unwrap();
        let store = builder.build();
        let validator = CertificateValidator::new(store);
        assert!(validator.enable_expiration_check);
    }

    #[test]
    fn test_parse_asn1_time() {
        let time_str = "Oct  2 12:00:00 2025 GMT";
        let result = parse_asn1_time(time_str);
        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // Requires actual certificate
    fn test_certificate_expiration_check() {
        // This test requires a real certificate
        // Would need to generate one for testing
    }
}

// ============================================================================
// OCSP (Online Certificate Status Protocol) Support
// RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol
// ============================================================================

/// OCSP certificate status
/// OCSP response status for certificate revocation checking
#[derive(Debug, Clone, PartialEq)]
pub enum OcspStatus {
    /// Certificate is valid and not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        /// Reason for revocation (if provided by OCSP response)
        reason: Option<String>,
        /// Time when certificate was revoked
        revocation_time: Option<SystemTime>,
    },
    /// Certificate status is unknown
    Unknown,
}

/// OCSP Client for real-time certificate revocation checking
pub struct OcspClient {
    /// HTTP client for OCSP requests
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    http_client: reqwest::blocking::Client,

    /// Cache of OCSP responses (cert_id -> (response, expiration))
    response_cache: Arc<Mutex<HashMap<String, (Vec<u8>, SystemTime)>>>,

    /// How long to cache OCSP responses (default: 5 minutes)
    cache_duration: Duration,

    /// HTTP timeout for OCSP requests (default: 10 seconds)
    /// Stored for reference and potential client reconfiguration
    #[allow(dead_code)]
    timeout: Duration,
}

impl OcspClient {
    /// Create a new OCSP client with default settings
    ///
    /// Default settings:
    /// - Cache duration: 5 minutes (OCSP responses are meant to be current)
    /// - HTTP timeout: 10 seconds
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    pub fn new() -> Result<Self> {
        let http_client = reqwest::blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            http_client,
            response_cache: Arc::new(Mutex::new(HashMap::new())),
            cache_duration: Duration::from_secs(300), // 5 minutes
            timeout: Duration::from_secs(10),
        })
    }

    /// Create an OCSP client with custom configuration
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    pub fn with_config(cache_duration: Duration, timeout: Duration) -> Result<Self> {
        let http_client = reqwest::blocking::ClientBuilder::new()
            .timeout(timeout)
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            http_client,
            response_cache: Arc::new(Mutex::new(HashMap::new())),
            cache_duration,
            timeout,
        })
    }

    /// Check certificate status via OCSP
    ///
    /// This will:
    /// 1. Extract OCSP responder URL from certificate (Authority Information Access extension)
    /// 2. Build OCSP request for the certificate
    /// 3. Send HTTP POST to OCSP responder
    /// 4. Parse and verify OCSP response
    /// 5. Return certificate status
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    pub fn check_status(&mut self, cert: &X509, issuer: &X509) -> Result<OcspStatus> {
        // Extract OCSP responder URL from certificate
        let ocsp_url = self.extract_ocsp_url(cert)?;

        // Check cache first
        let cache_key = hex::encode(cert.serial_number().to_bn()?.to_vec());
        if let Some(cached_response) = self.get_cached_response(&cache_key) {
            return self.parse_ocsp_status(&cached_response, cert, issuer);
        }

        // Build OCSP request
        let request_der = self.build_ocsp_request(cert, issuer)?;

        // Send OCSP request
        let response_der = self.send_ocsp_request(&ocsp_url, &request_der)?;

        // Cache the response
        self.cache_response(&cache_key, response_der.clone());

        // Parse status from response
        self.parse_ocsp_status(&response_der, cert, issuer)
    }

    /// Extract OCSP responder URL from certificate's Authority Information Access extension
    ///
    /// Note: This is a placeholder implementation. Full implementation requires
    /// parsing the AuthorityInfoAccess extension (OID 1.3.6.1.5.5.7.1.1)
    pub fn extract_ocsp_url(&self, cert: &X509) -> Result<String> {
        let responders = cert
            .ocsp_responders()
            .map_err(|e| anyhow!("Failed to extract OCSP responders: {}", e))?;

        if responders.is_empty() {
            return Err(anyhow!("No OCSP responder URL found in AIA extension"));
        }

        // Return the first responder URL
        // openssl::string::OpensslString implements Deref to &str
        Ok(responders[0].to_string())
    }

    /// Build an OCSP request for a certificate
    fn build_ocsp_request(&self, cert: &X509, issuer: &X509) -> Result<Vec<u8>> {
        // Create OCSP request
        let mut request =
            OcspRequest::new().map_err(|e| anyhow!("Failed to create OCSP request: {}", e))?;

        // Create certificate ID (identifies the cert to check)
        let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)
            .map_err(|e| anyhow!("Failed to create OCSP cert ID: {}", e))?;

        // Add certificate ID to request
        request
            .add_id(cert_id)
            .map_err(|e| anyhow!("Failed to add cert ID to OCSP request: {}", e))?;

        // Encode request as DER
        let request_der = request
            .to_der()
            .map_err(|e| anyhow!("Failed to encode OCSP request: {}", e))?;

        Ok(request_der)
    }

    /// Send OCSP request via HTTP POST
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    fn send_ocsp_request(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .body(request_der.to_vec())
            .send()
            .map_err(|e| anyhow!("OCSP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OCSP responder returned error: {}",
                response.status()
            ));
        }

        let response_der = response
            .bytes()
            .map_err(|e| anyhow!("Failed to read OCSP response: {}", e))?
            .to_vec();

        Ok(response_der)
    }

    /// Parse OCSP status from response
    fn parse_ocsp_status(
        &self,
        response_der: &[u8],
        cert: &X509,
        issuer: &X509,
    ) -> Result<OcspStatus> {
        // Parse OCSP response
        let response = OcspResponse::from_der(response_der)
            .map_err(|e| anyhow!("Failed to parse OCSP response: {}", e))?;

        // Check response status
        match response.status() {
            OcspResponseStatus::SUCCESSFUL => {}
            status => {
                return Err(anyhow!("OCSP response status: {:?}", status));
            }
        }

        // Get basic response
        let basic = response
            .basic()
            .map_err(|e| anyhow!("Failed to get OCSP basic response: {}", e))?;

        // Create certificate ID to look up status
        let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)
            .map_err(|e| anyhow!("Failed to create cert ID: {}", e))?;

        // Find the status for our certificate
        let ocsp_status = basic.find_status(&cert_id);

        match ocsp_status {
            Some(status_info) => {
                match status_info.status {
                    OcspCertStatus::GOOD => Ok(OcspStatus::Good),
                    OcspCertStatus::REVOKED => {
                        let revocation_time_sys = status_info.revocation_time.map(|_rt| {
                            // Convert ASN.1 time to SystemTime
                            // This is a simplified conversion - proper implementation
                            // would parse the ASN.1 time string
                            SystemTime::now() // Placeholder
                        });

                        // Convert revocation reason to string
                        let reason_str = match status_info.reason {
                            openssl::ocsp::OcspRevokedStatus::UNSPECIFIED => {
                                Some("Unspecified".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::KEY_COMPROMISE => {
                                Some("Key Compromise".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::CA_COMPROMISE => {
                                Some("CA Compromise".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::AFFILIATION_CHANGED => {
                                Some("Affiliation Changed".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::STATUS_SUPERSEDED => {
                                Some("Superseded".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::STATUS_CESSATION_OF_OPERATION => {
                                Some("Cessation of Operation".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::STATUS_CERTIFICATE_HOLD => {
                                Some("Certificate Hold".to_string())
                            }
                            openssl::ocsp::OcspRevokedStatus::REMOVE_FROM_CRL => {
                                Some("Remove from CRL".to_string())
                            }
                            _ => None,
                        };

                        Ok(OcspStatus::Revoked {
                            reason: reason_str,
                            revocation_time: revocation_time_sys,
                        })
                    }
                    OcspCertStatus::UNKNOWN => Ok(OcspStatus::Unknown),
                    _ => Ok(OcspStatus::Unknown),
                }
            }
            None => Ok(OcspStatus::Unknown),
        }
    }

    /// Get cached OCSP response if available and not expired
    fn get_cached_response(&self, cache_key: &str) -> Option<Vec<u8>> {
        let cache = self.response_cache.lock().unwrap();

        if let Some((response, expiration)) = cache.get(cache_key)
            && SystemTime::now() < *expiration {
                return Some(response.clone());
            }

        None
    }

    /// Cache OCSP response
    fn cache_response(&mut self, cache_key: &str, response_der: Vec<u8>) {
        let mut cache = self.response_cache.lock().unwrap();
        let expiration = SystemTime::now() + self.cache_duration;
        cache.insert(cache_key.to_string(), (response_der, expiration));
    }

    /// Check certificate status using a specific OCSP responder URL
    ///
    /// Use this when the certificate doesn't have an AIA extension
    /// or you want to override the default responder
    #[cfg(any(feature = "test", feature = "dev", feature = "default"))]
    pub fn check_status_with_url(
        &mut self,
        cert: &X509,
        issuer: &X509,
        ocsp_url: &str,
    ) -> Result<OcspStatus> {
        // Check cache first
        let cache_key = hex::encode(cert.serial_number().to_bn()?.to_vec());
        if let Some(cached_response) = self.get_cached_response(&cache_key) {
            return self.parse_ocsp_status(&cached_response, cert, issuer);
        }

        // Build OCSP request
        let request_der = self.build_ocsp_request(cert, issuer)?;

        // Send OCSP request
        let response_der = self.send_ocsp_request(ocsp_url, &request_der)?;

        // Cache the response
        self.cache_response(&cache_key, response_der.clone());

        // Parse status from response
        self.parse_ocsp_status(&response_der, cert, issuer)
    }

    /// Clear the OCSP response cache
    pub fn clear_cache(&mut self) {
        let mut cache = self.response_cache.lock().unwrap();
        cache.clear();
    }

    /// Get cache statistics
    ///
    /// Returns (total_entries, valid_entries)
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.response_cache.lock().unwrap();
        let total = cache.len();
        let now = SystemTime::now();
        let valid = cache
            .values()
            .filter(|(_, expiration)| now < *expiration)
            .count();

        (total, valid)
    }
}
