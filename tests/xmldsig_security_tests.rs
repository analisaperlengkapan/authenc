// XMLDSig Security Tests
use authenc::crypto::xmldsig::{XmlSecurityLimits, XmlSecurityValidator};

#[test]
fn test_validator_creation() {
    let validator = XmlSecurityValidator::new();
    assert_eq!(validator.limits.max_entity_expansions, 10);
}

#[test]
fn test_simple_xml() {
    let validator = XmlSecurityValidator::new();
    let xml = "<root><element>Test</element></root>";
    assert!(validator.validate_xml(xml).is_ok());
}

#[test]
fn test_id_uniqueness() {
    let validator = XmlSecurityValidator::new();
    let xml = r#"<root><e id="a">X</e><e id="b">Y</e></root>"#;
    assert!(validator.validate_id_uniqueness(xml).is_ok());
}
