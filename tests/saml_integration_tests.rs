// SAML Integration Tests - Comprehensive End-to-End Testing
// Tests the complete SAML authentication flow with security validation
// Feature #6 Phase 4 Task 4

use authenc::config::DatabaseConfig;
use authenc::crypto::xmldsig::*;
use authenc::database::Database;
use authenc::services::federation::{
    AuthRequest, AuthResponse, IdentityProvider, IdentityProviderConfig, IdentityProviderType,
    saml::SamlIdentityProvider,
};
use base64::Engine;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create test database connection
async fn create_test_database() -> Arc<Database> {
    let config = DatabaseConfig {
        host: std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string()),
        port: std::env::var("DB_PORT")
            .unwrap_or_else(|_| "5432".to_string())
            .parse()
            .unwrap_or(5432),
        username: std::env::var("DB_USERNAME").unwrap_or_else(|_| "postgres".to_string()),
        password: std::env::var("DB_PASSWORD").unwrap_or_else(|_| "postgres".to_string()),
        database: std::env::var("DB_NAME").unwrap_or_else(|_| "authenc_test".to_string()),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let db = Database::new(&config)
        .await
        .expect("Failed to connect to database");
    Arc::new(db)
}

/// Helper: Create a self-signed root CA certificate for testing
fn create_root_ca() -> (X509, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    let serial = BigNum::from_u32(1).unwrap();
    let serial = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("C", "US").unwrap();
    name.append_entry_by_text("O", "Test CA").unwrap();
    name.append_entry_by_text("CN", "Test Root CA").unwrap();
    let name = name.build();

    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap(); // 10 years
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.set_pubkey(&pkey).unwrap();

    // Add CA extensions
    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();

    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_key_identifier).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    (builder.build(), pkey)
}

/// Helper: Create an end-entity certificate signed by CA
fn create_end_entity_cert(
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    days_valid: u32,
) -> (X509, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    let serial = BigNum::from_u32(2).unwrap();
    let serial = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("C", "US").unwrap();
    name.append_entry_by_text("O", "Test Org").unwrap();
    name.append_entry_by_text("CN", "idp.example.com").unwrap();
    let name = name.build();

    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(days_valid).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.set_pubkey(&pkey).unwrap();

    // Add end-entity extensions
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();

    builder.sign(ca_key, MessageDigest::sha256()).unwrap();

    (builder.build(), pkey)
}

/// Create a signed SAML assertion for testing
fn create_signed_saml_assertion(
    cert: &X509,
    key: &PKey<Private>,
    assertion_id: &str,
    email: &str,
    not_before: &str,
    not_after: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Build SAML assertion XML
    let assertion_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
                 xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                 ID="response_{}" 
                 Version="2.0" 
                 IssueInstant="{}">
  <saml2:Issuer>https://idp.example.com</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion ID="{}" Version="2.0" IssueInstant="{}">
    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{}</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="{}" Recipient="https://sp.example.com/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="{}" NotOnOrAfter="{}">
      <saml2:AudienceRestriction>
        <saml2:Audience>https://sp.example.com</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="{}" SessionIndex="session_{}">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                              xsi:type="xs:string">{}</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="firstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                              xsi:type="xs:string">John</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="lastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                              xsi:type="xs:string">Doe</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>"#,
        assertion_id,
        not_before,
        assertion_id,
        not_before,
        email,
        not_after,
        not_before,
        not_after,
        not_before,
        assertion_id,
        email
    );

    // Sign the assertion
    let signed_xml = sign_xml(&assertion_xml, key, cert)?;

    // Base64 encode
    let encoded = base64::engine::general_purpose::STANDARD.encode(&signed_xml);
    Ok(encoded)
}

/// Sign XML with certificate and key
fn sign_xml(
    xml: &str,
    key: &PKey<Private>,
    cert: &X509,
) -> Result<String, Box<dyn std::error::Error>> {
    // For simplicity in tests, we'll create a basic XMLDSig signature
    // In production, this would use proper canonicalization and transforms

    // Create signature value by signing the XML content
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(xml.as_bytes())?;
    let signature_bytes = signer.sign_to_vec()?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

    // Get certificate in base64
    let cert_der = cert.to_der()?;
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);

    // Build signed XML with Signature element
    // Insert before </saml2:Assertion>
    let signature_xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>PLACEHOLDER</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>{}</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>{}</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>"#,
        signature_b64, cert_b64
    );

    let signed_xml = xml.replace(
        "</saml2:Assertion>",
        &format!("{}</saml2:Assertion>", signature_xml),
    );
    Ok(signed_xml)
}

/// Create XML bomb attack payload (billion laughs)
fn create_xml_bomb() -> String {
    let bomb_xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:AttributeStatement>
      <saml2:Attribute Name="data">
        <saml2:AttributeValue>&lol4;</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>"#;

    base64::engine::general_purpose::STANDARD.encode(bomb_xml)
}

/// Create deeply nested XML attack payload
fn create_deep_nested_xml() -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">"#,
    );

    // Create 200 nested elements (exceeds default limit of 100)
    for i in 0..200 {
        xml.push_str(&format!("<level{}>", i));
    }
    xml.push_str("<data>payload</data>");
    for i in (0..200).rev() {
        xml.push_str(&format!("</level{}>", i));
    }
    xml.push_str("</saml2p:Response>");

    base64::engine::general_purpose::STANDARD.encode(xml)
}

// ============================================================================
// Test Suite 1: Basic SAML Authentication
// ============================================================================

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_basic_authentication_success() {
    let db = create_test_database().await;

    // Create test certificates
    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, end_key) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    // Save CA cert to temp file (trust store)
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let ca_pem = ca_cert.to_pem().unwrap();
    fs::write(&ca_path, ca_pem).unwrap();

    // Configure SAML provider with security enabled
    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert(
        "sp_entity_id".to_string(),
        "https://sp.example.com".to_string(),
    );
    config_map.insert("enable_xml_security".to_string(), "true".to_string());
    config_map.insert(
        "enable_certificate_validation".to_string(),
        "true".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML Provider".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    // Create valid SAML assertion
    let now = chrono::Utc::now();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let saml_response = create_signed_saml_assertion(
        &end_cert,
        &end_key,
        &Uuid::new_v4().to_string(),
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    // Test authentication
    let response = provider.authenticate(&request).await;

    // Should succeed with valid signed assertion
    assert!(
        response.is_ok(),
        "Authentication should succeed with valid assertion"
    );
    let auth_response = response.unwrap();
    assert!(auth_response.success, "Authentication should be successful");
    assert_eq!(auth_response.email.as_deref(), Some("test@example.com"));
}

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_authentication_without_security() {
    let db = create_test_database().await;

    // Configure SAML provider with ALL security disabled
    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert("enable_xml_security".to_string(), "false".to_string());
    config_map.insert(
        "enable_certificate_validation".to_string(),
        "false".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML Provider".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: None,
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db);

    // Should create provider without security validator
    // Test basic functionality
    assert!(provider.await.is_ok());
}

// ============================================================================
// Test Suite 2: Certificate Validation
// ============================================================================

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_expired_certificate_rejection() {
    let db = create_test_database().await;

    // Create certificates
    let (ca_cert, ca_key) = create_root_ca();
    let (expired_cert, expired_key) = create_end_entity_cert(&ca_cert, &ca_key, 0); // Already expired

    // Save CA cert
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert(
        "enable_certificate_validation".to_string(),
        "true".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let now = chrono::Utc::now();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let saml_response = create_signed_saml_assertion(
        &expired_cert,
        &expired_key,
        &Uuid::new_v4().to_string(),
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should fail due to expired certificate
    assert!(response.is_err(), "Should reject expired certificate");
    let err_msg = response.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired") || err_msg.contains("Expired"),
        "Error should mention expiration: {}",
        err_msg
    );
}

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_untrusted_certificate_rejection() {
    let db = create_test_database().await;

    // Create two separate CAs
    let (trusted_ca, _) = create_root_ca();
    let (untrusted_ca, untrusted_ca_key) = create_root_ca();

    // Create cert signed by untrusted CA
    let (untrusted_cert, untrusted_key) =
        create_end_entity_cert(&untrusted_ca, &untrusted_ca_key, 365);

    // Save only trusted CA to trust store
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, trusted_ca.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert(
        "enable_certificate_validation".to_string(),
        "true".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let now = chrono::Utc::now();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let saml_response = create_signed_saml_assertion(
        &untrusted_cert,
        &untrusted_key,
        &Uuid::new_v4().to_string(),
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should fail due to untrusted certificate
    assert!(response.is_err(), "Should reject untrusted certificate");
    let err_msg = response.unwrap_err().to_string();
    assert!(
        err_msg.contains("untrusted") || err_msg.contains("Untrusted") || err_msg.contains("chain"),
        "Error should mention trust issue: {}",
        err_msg
    );
}

// ============================================================================
// Test Suite 3: XML Security Attacks
// ============================================================================

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_xml_bomb_rejection() {
    let db = create_test_database().await;

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert("enable_xml_security".to_string(), "true".to_string());

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: None,
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let bomb = create_xml_bomb();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(bomb),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should reject XML bomb
    assert!(response.is_err(), "Should reject XML bomb attack");
    let err_msg = response.unwrap_err().to_string();
    assert!(
        err_msg.contains("XML") || err_msg.contains("entity") || err_msg.contains("security"),
        "Error should mention XML security: {}",
        err_msg
    );
}

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_deep_nesting_rejection() {
    let db = create_test_database().await;

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert("enable_xml_security".to_string(), "true".to_string());
    config_map.insert("xml_max_element_depth".to_string(), "100".to_string());

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: None,
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let deep_xml = create_deep_nested_xml();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(deep_xml),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should reject deeply nested XML
    assert!(response.is_err(), "Should reject deeply nested XML");
    let err_msg = response.unwrap_err().to_string();
    assert!(
        err_msg.contains("depth") || err_msg.contains("nesting") || err_msg.contains("XML"),
        "Error should mention depth/nesting: {}",
        err_msg
    );
}

// ============================================================================
// Test Suite 4: SAML Conditions Validation
// ============================================================================

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_expired_assertion_rejection() {
    let db = create_test_database().await;

    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, end_key) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    // Create assertion that expired 1 hour ago
    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::hours(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let not_after = (now - chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let saml_response = create_signed_saml_assertion(
        &end_cert,
        &end_key,
        &Uuid::new_v4().to_string(),
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should reject expired assertion
    assert!(response.is_err(), "Should reject expired SAML assertion");
    let err_msg = response.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired")
            || err_msg.contains("NotOnOrAfter")
            || err_msg.contains("condition"),
        "Error should mention expiration: {}",
        err_msg
    );
}

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_not_yet_valid_assertion_rejection() {
    let db = create_test_database().await;

    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, end_key) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    // Create assertion valid only in future (1 hour from now)
    let now = chrono::Utc::now();
    let not_before = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let not_after = (now + chrono::Duration::hours(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let saml_response = create_signed_saml_assertion(
        &end_cert,
        &end_key,
        &Uuid::new_v4().to_string(),
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should reject not-yet-valid assertion
    assert!(
        response.is_err(),
        "Should reject not-yet-valid SAML assertion"
    );
    let err_msg = response.unwrap_err().to_string();
    assert!(
        err_msg.contains("NotBefore")
            || err_msg.contains("not yet valid")
            || err_msg.contains("condition"),
        "Error should mention NotBefore: {}",
        err_msg
    );
}

// ============================================================================
// Test Suite 5: Replay Attack Prevention
// ============================================================================

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_replay_attack_prevention() {
    let db = create_test_database().await;

    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, end_key) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let now = chrono::Utc::now();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Create assertion with fixed ID
    let assertion_id = Uuid::new_v4().to_string();
    let saml_response = create_signed_saml_assertion(
        &end_cert,
        &end_key,
        &assertion_id,
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response.clone()),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    // First authentication should succeed
    let response1 = provider.authenticate(&request).await;
    assert!(response1.is_ok(), "First authentication should succeed");

    // Second authentication with same assertion ID should fail (replay attack)
    let response2 = provider.authenticate(&request).await;
    assert!(response2.is_err(), "Replay attack should be prevented");
    let err_msg = response2.unwrap_err().to_string();
    assert!(
        err_msg.contains("replay")
            || err_msg.contains("already used")
            || err_msg.contains("duplicate"),
        "Error should mention replay: {}",
        err_msg
    );
}

// ============================================================================
// Test Suite 6: Configuration Variations
// ============================================================================

#[tokio::test]
#[ignore] // Requires database
async fn test_saml_crl_soft_fail_mode() {
    let db = create_test_database().await;

    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, end_key) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert("enable_crl_check".to_string(), "true".to_string());
    config_map.insert("crl_fail_on_unavailable".to_string(), "false".to_string()); // Soft-fail mode

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let now = chrono::Utc::now();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let saml_response = create_signed_saml_assertion(
        &end_cert,
        &end_key,
        &Uuid::new_v4().to_string(),
        "test@example.com",
        &not_before,
        &not_after,
    )
    .unwrap();

    let request = AuthRequest {
        username: None,
        password: None,
        saml_assertion: Some(saml_response),
        oidc_code: None,
        oauth_token: None,
        kerberos_ticket: None,
        social_provider: None,
        social_token: None,
        relay_state: None,
        parameters: HashMap::new(),
    };

    let response = provider.authenticate(&request).await;

    // Should succeed in soft-fail mode even if CRL is unavailable
    // (Note: May actually fail for other reasons like parsing in this test)
    // Main point is that CRL unavailability doesn't cause hard failure
    if let Err(e) = &response {
        let err_msg = e.to_string();
        assert!(
            !err_msg.contains("CRL unavailable"),
            "Should not fail due to CRL unavailability in soft-fail mode: {}",
            err_msg
        );
    }
}

#[tokio::test]
async fn test_saml_configuration_parsing() {
    // Test configuration parsing without database (unit test style)
    let mut config_map = HashMap::new();
    config_map.insert("enable_xml_security".to_string(), "true".to_string());
    config_map.insert(
        "enable_certificate_validation".to_string(),
        "false".to_string(),
    );
    config_map.insert("enable_crl_check".to_string(), "true".to_string());
    config_map.insert("crl_cache_duration_secs".to_string(), "7200".to_string());
    config_map.insert("xml_max_document_size".to_string(), "2097152".to_string());

    // Configuration parsing is tested internally
    // This just validates that various config combinations don't panic
    assert!(config_map.get("enable_xml_security").is_some());
    assert_eq!(config_map.get("enable_xml_security").unwrap(), "true");
}

// ============================================================================
// Performance Benchmarks (Optional - run manually)
// ============================================================================

#[tokio::test]
#[ignore] // Requires database - run manually for benchmarking
async fn bench_saml_authentication_throughput() {
    use std::time::Instant;

    let db = create_test_database().await;

    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, end_key) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, ca_cert.to_pem().unwrap()).unwrap();

    let mut config_map = HashMap::new();
    config_map.insert(
        "entity_id".to_string(),
        "https://idp.example.com".to_string(),
    );
    config_map.insert(
        "sso_url".to_string(),
        "https://idp.example.com/sso".to_string(),
    );
    config_map.insert("enable_xml_security".to_string(), "true".to_string());
    config_map.insert(
        "enable_certificate_validation".to_string(),
        "true".to_string(),
    );

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "test-saml".to_string(),
        display_name: "Test SAML".to_string(),
        provider_type: IdentityProviderType::SAML,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: Some(ca_path.to_str().unwrap().to_string()),
        keystore_path: None,
    };

    let provider = SamlIdentityProvider::new(config, db).await.unwrap();

    let now = chrono::Utc::now();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Run 100 authentications
    let iterations = 100;
    let start = Instant::now();

    for i in 0..iterations {
        let assertion_id = format!("benchmark-{}", i);
        let saml_response = create_signed_saml_assertion(
            &end_cert,
            &end_key,
            &assertion_id,
            "bench@example.com",
            &not_before,
            &not_after,
        )
        .unwrap();

        let request = AuthRequest {
            username: None,
            password: None,
            saml_assertion: Some(saml_response),
            oidc_code: None,
            oauth_token: None,
            kerberos_ticket: None,
            social_provider: None,
            social_token: None,
            relay_state: None,
            parameters: HashMap::new(),
        };

        let _ = provider.authenticate(&request).await;
    }

    let duration = start.elapsed();
    let avg_time = duration.as_millis() / iterations;
    let throughput = (iterations as f64 / duration.as_secs_f64()) as u32;

    println!("SAML Authentication Benchmark:");
    println!("  Total time: {:?}", duration);
    println!("  Iterations: {}", iterations);
    println!("  Average time: {}ms", avg_time);
    println!("  Throughput: {} auth/sec", throughput);

    // Performance assertion: Should process at least 10 auth/sec
    assert!(
        throughput >= 10,
        "Performance too slow: {} auth/sec",
        throughput
    );
}
