use authenc_services::services::security::password_policy::PasswordPolicy;

#[test]
fn test_password_policy_enforcement() {
    let policy = PasswordPolicy::default();

    // Valid password
    assert!(policy.validate("StrongPass123!").is_ok());

    // Too short
    let res = policy.validate("Short1!");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("at least 12 characters"));

    // No uppercase
    let res = policy.validate("validpass123!");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("uppercase letter"));

    // No lowercase
    let res = policy.validate("VALIDPASS123!");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("lowercase letter"));

    // No digit
    let res = policy.validate("ValidPassword!");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("digit"));

    // No special character
    let res = policy.validate("ValidPass123");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("special character"));

    // Blacklisted
    let res = policy.validate("Password123!");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("too common or blacklisted"));
}
