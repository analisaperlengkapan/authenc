// XMLDSig CRL (Certificate Revocation List) Tests
// Tests for CRL download, parsing, caching, and revocation checking

use authenc::crypto::xmldsig::{CrlManager, RevocationStatus};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Builder, X509Extension, X509NameBuilder};
use std::time::Duration;

// Helper: Create a test CA key pair
fn create_test_ca_key() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

// Helper: Create a test CA certificate
fn create_test_ca(key: &PKey<Private>) -> X509 {
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "Test CA").unwrap();
    let name = name_builder.build();

    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_subject_name(&name).unwrap();
    cert_builder.set_issuer_name(&name).unwrap();
    cert_builder.set_pubkey(key).unwrap();

    // Use serial number 1
    let serial = openssl::bn::BigNum::from_u32(1).unwrap();
    let serial_asn1 = serial.to_asn1_integer().unwrap();
    cert_builder.set_serial_number(&serial_asn1).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    // Mark as CA
    let basic_constraints = X509Extension::new_nid(
        None,
        None,
        openssl::nid::Nid::BASIC_CONSTRAINTS,
        "critical,CA:TRUE",
    )
    .unwrap();
    cert_builder.append_extension(basic_constraints).unwrap();

    cert_builder.sign(key, MessageDigest::sha256()).unwrap();
    cert_builder.build()
}

// Helper: Create an end-entity certificate
fn create_test_cert(ca_key: &PKey<Private>, ca_cert: &X509, serial: u32) -> X509 {
    let key = create_test_ca_key();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", &format!("Test Cert {}", serial))
        .unwrap();
    let name = name_builder.build();

    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_subject_name(&name).unwrap();
    cert_builder
        .set_issuer_name(ca_cert.subject_name())
        .unwrap();
    cert_builder.set_pubkey(&key).unwrap();

    let serial_bn = openssl::bn::BigNum::from_u32(serial).unwrap();
    let serial_asn1 = serial_bn.to_asn1_integer().unwrap();
    cert_builder.set_serial_number(&serial_asn1).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    cert_builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    cert_builder.build()
}

// Note: Creating CRLs requires X509CrlBuilder which is not available in all OpenSSL versions
// We'll test with pre-existing CRL data or focus on the parsing/validation logic

#[test]
fn test_crl_manager_creation() {
    let crl_manager = CrlManager::new();
    assert!(crl_manager.is_ok());
}

#[test]
fn test_crl_manager_custom_config() {
    let cache_duration = Duration::from_secs(1800); // 30 minutes
    let max_size = 5 * 1024 * 1024; // 5MB
    let crl_manager = CrlManager::with_config(cache_duration, max_size);
    assert!(crl_manager.is_ok());
}

#[test]
fn test_crl_parse_invalid_data() {
    let crl_manager = CrlManager::new().unwrap();
    let invalid_data = b"not a valid CRL";

    // Should fail to parse invalid data
    let result = crl_manager.parse_crl(invalid_data);
    assert!(result.is_err(), "Should fail to parse invalid CRL data");
}

#[test]
fn test_crl_cache_stats() {
    let crl_manager = CrlManager::new().unwrap();

    // Initially cache should be empty
    let (total, valid) = crl_manager.cache_stats();
    assert_eq!(total, 0);
    assert_eq!(valid, 0);
}

#[test]
fn test_crl_cache_clear() {
    let mut crl_manager = CrlManager::new().unwrap();

    // Clear cache (should not panic even if empty)
    crl_manager.clear_cache();

    let (total, valid) = crl_manager.cache_stats();
    assert_eq!(total, 0);
    assert_eq!(valid, 0);
}

#[test]
fn test_extract_crl_distribution_points_empty() {
    let ca_key = create_test_ca_key();
    let ca_cert = create_test_ca(&ca_key);
    let cert = create_test_cert(&ca_key, &ca_cert, 100);

    let crl_manager = CrlManager::new().unwrap();
    let urls = crl_manager.extract_crl_distribution_points(&cert).unwrap();

    // Currently returns empty (not fully implemented)
    assert_eq!(urls.len(), 0);
}

#[tokio::test]
async fn test_check_revocation_no_crl_urls() {
    let ca_key = create_test_ca_key();
    let ca_cert = create_test_ca(&ca_key);
    let cert = create_test_cert(&ca_key, &ca_cert, 100);

    let mut crl_manager = CrlManager::new().unwrap();

    // Certificate has no CRL distribution points
    // Should return Unknown status
    let result = crl_manager.check_revocation(&cert).await.unwrap();
    assert_eq!(result, RevocationStatus::Unknown);
}

#[test]
fn test_crl_manager_default() {
    // Test Default trait implementation
    let _crl_manager = CrlManager::default();
    // Should create successfully
}
