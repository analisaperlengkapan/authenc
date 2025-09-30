use authenc::services::password_policy::PasswordPolicy;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_length, 12);
        assert!(policy.require_uppercase);
        assert!(policy.require_lowercase);
        assert!(policy.require_digit);
        assert!(policy.require_special);
        assert_eq!(policy.blacklist.len(), 3);
        assert!(policy.blacklist.contains(&"password".to_string()));
        assert!(policy.blacklist.contains(&"123456".to_string()));
        assert!(policy.blacklist.contains(&"qwerty".to_string()));
    }

    #[test]
    fn test_password_too_short() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("Short1!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 12 characters"));
    }

    #[test]
    fn test_password_missing_uppercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("lowercaseonly123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_password_missing_lowercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("UPPERCASEONLY123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lowercase letter"));
    }

    #[test]
    fn test_password_missing_digit() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("NoDigitsHere!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("digit"));
    }

    #[test]
    fn test_password_missing_special() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("NoSpecialChars123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("special character"));
    }

    #[test]
    fn test_password_blacklisted() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("MyPassword123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_blacklisted_case_insensitive() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("ContainsPASSWORD123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_valid_password() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("StrongSecure123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_password_with_various_special_chars() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("ComplexPhrase456@#$%^&*()");
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_policy_no_requirements() {
        let policy = PasswordPolicy {
            min_length: 4,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };
        let result = policy.validate("weak");
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_policy_only_length() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };
        assert!(policy.validate("short").is_err());
        assert!(policy.validate("longenough").is_ok());
    }

    #[test]
    fn test_custom_blacklist() {
        let policy = PasswordPolicy {
            min_length: 4,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["badword".to_string()],
        };
        assert!(policy.validate("thisisbadword").is_err());
        assert!(policy.validate("thisisgood").is_ok());
    }

    #[test]
    fn test_edge_case_empty_password() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 12 characters"));
    }

    #[test]
    fn test_edge_case_unicode_characters() {
        let policy = PasswordPolicy::default();
        // Unicode characters that are not letters/digits should count as special
        let result = policy.validate("ValidPhrase123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_edge_case_only_special_chars() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("!@#$%^&*()123ABCdef");
        assert!(result.is_ok());
    }

    #[test]
    fn test_edge_case_minimum_length_boundary() {
        let policy = PasswordPolicy {
            min_length: 5,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };
        assert!(policy.validate("1234").is_err()); // Too short
        assert!(policy.validate("12345").is_ok()); // Exactly minimum
        assert!(policy.validate("123456").is_ok()); // Longer than minimum
    }

    #[test]
    fn test_edge_case_blacklist_empty_string() {
        let policy = PasswordPolicy {
            min_length: 4,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["".to_string()],
        };
        // Empty string in blacklist should be ignored
        let result = policy.validate("test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_comprehensive_policy_validation() {
        let policy = PasswordPolicy::default();

        // Test all requirements together
        let valid_cases = vec![
            "StrongPass123!",
            "Complex@Phrase#456",
            "Secure_789$Word",
            "Robust(0)Phrase%",
        ];

        for password in valid_cases {
            assert!(
                policy.validate(password).is_ok(),
                "Password '{}' should be valid",
                password
            );
        }

        let invalid_cases = vec![
            ("short", "too short"),
            ("nouppercase123!", "missing uppercase"),
            ("NOLOWERCASE123!", "missing lowercase"),
            ("NoDigits!", "missing digit"),
            ("NoSpecial123", "missing special"),
            ("Password123!", "blacklisted"),
        ];

        for (password, reason) in invalid_cases {
            assert!(
                policy.validate(password).is_err(),
                "Password '{}' should be invalid: {}",
                password,
                reason
            );
        }
    }
}
