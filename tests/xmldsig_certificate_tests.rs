// Certificate Validation Integration Tests
// Tests for X.509 certificate chain validation, expiration, and trust store

use authenc::crypto::xmldsig::*;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Builder, X509NameBuilder, X509};

/// Helper: Create a self-signed root CA certificate
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
    name.append_entry_by_text("CN", "test.example.com").unwrap();
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

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .unwrap();
    builder.append_extension(subject_key_identifier).unwrap();

    builder.sign(ca_key, MessageDigest::sha256()).unwrap();

    (builder.build(), pkey)
}

/// Helper: Create an expired certificate (expires in 1 second for testing)
fn create_expired_cert(ca_cert: &X509, ca_key: &PKey<Private>) -> (X509, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    let serial = BigNum::from_u32(3).unwrap();
    let serial = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("C", "US").unwrap();
    name.append_entry_by_text("O", "Test Org").unwrap();
    name.append_entry_by_text("CN", "expired.example.com")
        .unwrap();
    let name = name.build();

    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();

    // Create cert that expires immediately
    // Use manual ASN1 time construction for past dates
    let not_before_str = "200101000000Z"; // Jan 1, 2020
    let not_after_str = "200102000000Z"; // Jan 2, 2020 (expired)
    let not_before = Asn1Time::from_str(not_before_str).unwrap();
    let not_after = Asn1Time::from_str(not_after_str).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.set_pubkey(&pkey).unwrap();

    builder.sign(ca_key, MessageDigest::sha256()).unwrap();

    (builder.build(), pkey)
}

#[test]
fn test_certificate_validator_creation_with_trust_store() {
    let mut store_builder = X509StoreBuilder::new().unwrap();
    let (ca_cert, _) = create_root_ca();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);
    assert!(validator.enable_expiration_check);
}

#[test]
fn test_validate_valid_certificate_chain() {
    // Create CA and end-entity certificate
    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, _) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    // Create trust store with CA
    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);

    // Validate end-entity certificate
    let result = validator.validate_certificate(&end_cert);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), CertificateValidationResult::Valid);
}

#[test]
fn test_validate_expired_certificate() {
    // Create CA and expired certificate
    let (ca_cert, ca_key) = create_root_ca();
    let (expired_cert, _) = create_expired_cert(&ca_cert, &ca_key);

    // Create trust store with CA
    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);

    // Validate expired certificate
    let result = validator.validate_certificate(&expired_cert);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), CertificateValidationResult::Expired);
}

#[test]
fn test_validate_self_signed_without_trust() {
    // Create self-signed certificate
    let (self_signed_cert, _) = create_root_ca();

    // Create empty trust store (no CA)
    let store_builder = X509StoreBuilder::new().unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);

    // Validate self-signed certificate without trust
    let result = validator.validate_certificate(&self_signed_cert);
    assert!(result.is_ok());
    // Should fail validation due to untrusted root
    let validation_result = result.unwrap();
    assert!(
        validation_result == CertificateValidationResult::UntrustedRoot
            || validation_result == CertificateValidationResult::ChainInvalid
    );
}

#[test]
fn test_certificate_expiration_check() {
    let (ca_cert, ca_key) = create_root_ca();
    let (expired_cert, _) = create_expired_cert(&ca_cert, &ca_key);

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);

    // Check expiration directly
    let result = validator.check_expiration(&expired_cert);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}

#[test]
fn test_certificate_validator_with_disabled_expiration_check() {
    let (ca_cert, ca_key) = create_root_ca();
    let (expired_cert, _) = create_expired_cert(&ca_cert, &ca_key);

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let mut validator = CertificateValidator::new(store);
    validator.disable_expiration_check();

    // Even with expiration check disabled in our code, OpenSSL's chain validation
    // will still reject expired certificates, so this will fail chain validation
    let result = validator.validate_certificate(&expired_cert);
    assert!(result.is_ok());
    // OpenSSL will mark it as chain invalid due to expiration
    let validation_result = result.unwrap();
    assert!(
        validation_result == CertificateValidationResult::ChainInvalid
            || validation_result == CertificateValidationResult::Expired
    );
}

#[test]
fn test_certificate_from_pem() {
    let (ca_cert, _) = create_root_ca();
    let pem = ca_cert.to_pem().unwrap();

    let result = CertificateValidator::from_pem_certificates(&pem);
    assert!(result.is_ok());
}

#[test]
fn test_multiple_certificates_in_pem() {
    let (ca_cert1, _) = create_root_ca();
    let (ca_cert2, _) = create_root_ca();

    let pem1 = ca_cert1.to_pem().unwrap();
    let pem2 = ca_cert2.to_pem().unwrap();

    // Combine PEMs
    let mut combined = Vec::new();
    combined.extend_from_slice(&pem1);
    combined.extend_from_slice(b"\n");
    combined.extend_from_slice(&pem2);

    let result = CertificateValidator::from_pem_certificates(&combined);
    assert!(result.is_ok());
}

#[test]
fn test_key_usage_check() {
    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, _) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);

    // Check key usage (currently returns true - simplified)
    let result = validator.check_key_usage(&end_cert);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_xml_signature_get_certificate() {
    // Create a certificate
    let (cert, _) = create_root_ca();
    let cert_pem = cert.to_pem().unwrap();
    let cert_pem_str = String::from_utf8_lossy(&cert_pem);

    // Extract just the base64 part (remove BEGIN/END lines)
    let lines: Vec<&str> = cert_pem_str.lines().collect();
    let base64_lines: Vec<&str> = lines
        .iter()
        .filter(|l| !l.contains("BEGIN") && !l.contains("END"))
        .copied()
        .collect();
    let base64_cert = base64_lines.join("");

    // Create XmlSignature with certificate
    let key_info = KeyInfo {
        x509_certificate: Some(base64_cert),
    };

    let signature = XmlSignature {
        signed_info: SignedInfo {
            canonicalization_method: CanonicalizationMethod::C14n,
            signature_method: SignatureMethod::RsaSha256,
            references: vec![],
            raw_xml: String::new(),
        },
        signature_value: vec![1, 2, 3],
        key_info: Some(key_info),
    };

    // Extract certificate
    let extracted_cert = signature.get_certificate();
    assert!(extracted_cert.is_some());
}

#[test]
fn test_certificate_chain_validation_direct() {
    let (ca_cert, ca_key) = create_root_ca();
    let (end_cert, _) = create_end_entity_cert(&ca_cert, &ca_key, 365);

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let validator = CertificateValidator::new(store);

    // Direct chain validation
    let result = validator.validate_certificate_chain(&end_cert);
    assert!(result.is_ok());
}
