// OCSP (Online Certificate Status Protocol) Tests
// Tests for RFC 6960 OCSP implementation

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
use authenc::crypto::xmldsig::OcspClient;
use authenc::crypto::xmldsig::OcspStatus;

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
#[test]
fn test_ocsp_client_creation() {
    let client = OcspClient::new();
    assert!(client.is_ok(), "Should create OCSP client");
}

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
#[test]
fn test_ocsp_client_custom_config() {
    use std::time::Duration;

    let client = OcspClient::with_config(
        Duration::from_secs(180), // 3 minute cache
        Duration::from_secs(5),   // 5 second timeout
    );

    assert!(
        client.is_ok(),
        "Should create OCSP client with custom config"
    );
}

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
#[test]
fn test_ocsp_extract_url_not_implemented() {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509;
    use openssl::x509::X509NameBuilder;

    let client = OcspClient::new().unwrap();

    // Create a simple test certificate
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Certificate").unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let cert = builder.build();

    // OCSP URL extraction not yet implemented
    let result = client.extract_ocsp_url(&cert);
    assert!(result.is_err(), "Should return error - not yet implemented");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("not yet implemented")
    );
}

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
#[test]
fn test_ocsp_cache_stats() {
    let client = OcspClient::new().unwrap();

    let (total, valid) = client.cache_stats();
    assert_eq!(total, 0, "Fresh client should have empty cache");
    assert_eq!(valid, 0, "Fresh client should have no valid entries");
}

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
#[test]
fn test_ocsp_cache_clear() {
    let mut client = OcspClient::new().unwrap();

    // Clear empty cache (should not panic)
    client.clear_cache();

    let (total, valid) = client.cache_stats();
    assert_eq!(total, 0);
    assert_eq!(valid, 0);
}

#[test]
fn test_ocsp_status_enum() {
    // Test OcspStatus variants
    let good = OcspStatus::Good;
    assert!(matches!(good, OcspStatus::Good));

    let revoked = OcspStatus::Revoked {
        reason: Some("Key Compromise".to_string()),
        revocation_time: None,
    };
    assert!(matches!(revoked, OcspStatus::Revoked { .. }));

    let unknown = OcspStatus::Unknown;
    assert!(matches!(unknown, OcspStatus::Unknown));
}

#[cfg(any(feature = "test", feature = "dev", feature = "default"))]
#[test]
fn test_ocsp_check_status_no_url() {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509;
    use openssl::x509::X509NameBuilder;

    let mut client = OcspClient::new().unwrap();

    // Create test certificates (self-signed CA and end-entity cert)
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test CA").unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let ca_cert = builder.build();

    // Create end-entity cert
    let rsa2 = Rsa::generate(2048).unwrap();
    let pkey2 = PKey::from_rsa(rsa2).unwrap();

    let mut name2 = X509NameBuilder::new().unwrap();
    name2
        .append_entry_by_text("CN", "Test Certificate")
        .unwrap();
    let name2 = name2.build();

    let mut builder2 = X509::builder().unwrap();
    builder2.set_version(2).unwrap();
    builder2.set_subject_name(&name2).unwrap();
    builder2.set_issuer_name(&name).unwrap();
    builder2.set_pubkey(&pkey2).unwrap();
    builder2
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder2
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder2.sign(&pkey, MessageDigest::sha256()).unwrap();

    let cert = builder2.build();

    // Try to check status (will fail because no OCSP URL)
    let result = client.check_status(&cert, &ca_cert);
    assert!(result.is_err(), "Should fail - no OCSP URL in certificate");
}

// Note: Full OCSP integration tests would require:
// 1. Mock OCSP responder (HTTP server)
// 2. Test certificates with AIA extension containing OCSP URL
// 3. Valid OCSP responses signed by test CA
//
// These are complex to set up in unit tests and are better suited for
// integration tests with external test infrastructure.
