// XMLDSig (XML Digital Signature) Tests
// Tests for W3C XML Signature implementation

use authenc::crypto::xmldsig::*;

#[test]
fn test_canonicalization_method_from_uri() {
    // Valid C14N
    let result =
        CanonicalizationMethod::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), CanonicalizationMethod::C14n);

    // Valid Exclusive C14N
    let result = CanonicalizationMethod::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), CanonicalizationMethod::ExclusiveC14n);

    // Invalid method
    let result = CanonicalizationMethod::from_uri("http://invalid.method");
    assert!(result.is_err());
}

#[test]
fn test_digest_method_from_uri() {
    // Valid SHA-256
    let result = DigestMethod::from_uri("http://www.w3.org/2001/04/xmlenc#sha256");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), DigestMethod::Sha256);

    // Valid SHA-384
    let result = DigestMethod::from_uri("http://www.w3.org/2001/04/xmldsig-more#sha384");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), DigestMethod::Sha384);

    // Valid SHA-512
    let result = DigestMethod::from_uri("http://www.w3.org/2001/04/xmlenc#sha512");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), DigestMethod::Sha512);

    // SHA-1 should be rejected (insecure)
    let result = DigestMethod::from_uri("http://www.w3.org/2000/09/xmldsig#sha1");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("deprecated"));
}

#[test]
fn test_signature_method_from_uri() {
    // Valid RSA-SHA256
    let result = SignatureMethod::from_uri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), SignatureMethod::RsaSha256);

    // Valid RSA-SHA384
    let result = SignatureMethod::from_uri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), SignatureMethod::RsaSha384);

    // Valid RSA-SHA512
    let result = SignatureMethod::from_uri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), SignatureMethod::RsaSha512);

    // RSA-SHA1 should be rejected (insecure)
    let result = SignatureMethod::from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("deprecated"));
}

#[test]
fn test_reject_insecure_algorithms() {
    // SHA-1 in DigestMethod - should be rejected
    let result = DigestMethod::from_uri("http://www.w3.org/2000/09/xmldsig#sha1");
    assert!(result.is_err());

    // RSA-SHA1 in SignatureMethod - should be rejected
    let result = SignatureMethod::from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    assert!(result.is_err());
}

#[test]
fn test_multiple_signature_algorithms() {
    // Test that we support RSA-SHA256, RSA-SHA384, RSA-SHA512
    let algorithms = vec![
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            SignatureMethod::RsaSha256,
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            SignatureMethod::RsaSha384,
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            SignatureMethod::RsaSha512,
        ),
    ];

    for (uri, expected) in algorithms {
        let result = SignatureMethod::from_uri(uri);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }
}

#[test]
fn test_multiple_digest_algorithms() {
    // Test that we support SHA-256, SHA-384, SHA-512
    let algorithms = vec![
        (
            "http://www.w3.org/2001/04/xmlenc#sha256",
            DigestMethod::Sha256,
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#sha384",
            DigestMethod::Sha384,
        ),
        (
            "http://www.w3.org/2001/04/xmlenc#sha512",
            DigestMethod::Sha512,
        ),
    ];

    for (uri, expected) in algorithms {
        let result = DigestMethod::from_uri(uri);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }
}
