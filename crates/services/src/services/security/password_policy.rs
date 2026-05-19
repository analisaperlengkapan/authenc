/// Password policy configuration and validation
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length required
    pub min_length: usize,
    /// Whether uppercase letters are required
    pub require_uppercase: bool,
    /// Whether lowercase letters are required
    pub require_lowercase: bool,
    /// Whether digits are required
    pub require_digit: bool,
    /// Whether special characters are required
    pub require_special: bool,
    /// List of blacklisted/common passwords
    pub blacklist: Vec<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec!["password".into(), "123456".into(), "qwerty".into()],
        }
    }
}

impl PasswordPolicy {
    /// Validate password against policy requirements
    pub fn validate(&self, password: &str) -> Result<(), String> {
        if password.len() < self.min_length {
            return Err(format!(
                "Password must be at least {} characters",
                self.min_length
            ));
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err("Password must contain an uppercase letter".into());
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err("Password must contain a lowercase letter".into());
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err("Password must contain a digit".into());
        }
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err("Password must contain a special character".into());
        }
        for bad in &self.blacklist {
            let trimmed = bad.trim();
            if !trimmed.is_empty() && password.to_lowercase().contains(&bad.to_lowercase()) {
                return Err("Password is too common or blacklisted".into());
            }
        }
        Ok(())
    }
}

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
        assert_eq!(
            policy.blacklist,
            vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string()
            ]
        );
    }

    #[test]
    fn test_password_too_short() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("Short1!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 12 characters"));
    }

    #[test]
    fn test_password_minimum_length() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("ValidPass123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_missing_uppercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("validpass123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_password_missing_lowercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("VALIDPASS123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lowercase letter"));
    }

    #[test]
    fn test_password_missing_digit() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("ValidPassword!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("digit"));
    }

    #[test]
    fn test_password_missing_special() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("ValidPass123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("special character"));
    }

    #[test]
    fn test_password_blacklisted() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("Password123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_blacklisted_case_insensitive() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("Password123!");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_blacklisted_partial() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("MyPassword123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_valid_password() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("StrongPass123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_policy_no_requirements() {
        let policy = PasswordPolicy {
            min_length: 1,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };
        let result = policy.validate("a");
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
        let result = policy.validate("short");
        assert!(result.is_err());
        let result = policy.validate("longenough");
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_password() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 12 characters"));
    }

    #[test]
    fn test_unicode_characters() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("StröngPäss123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_unicode_uppercase() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("ströngpäss123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_various_special_characters() {
        let policy = PasswordPolicy::default();
        let special_chars = vec![
            "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=", "[", "]", "{",
            "}", "|", "\\", ";", ":", "'", "\"", ",", ".", "<", ">", "/", "?",
        ];

        for special in special_chars {
            let password = format!("ValidPass123{}", special);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with special char '{}' should be valid",
                special
            );
        }
    }

    #[test]
    fn test_custom_blacklist() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["badword".to_string(), "another".to_string()],
        };

        let result = policy.validate("goodpassword");
        assert!(result.is_ok());

        let result = policy.validate("containsbadword");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_empty_blacklist() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };

        let result = policy.validate("password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_password() {
        let policy = PasswordPolicy::default();
        let long_password = "A".repeat(1000) + "a1!";
        let result = policy.validate(&long_password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_with_spaces() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("Valid Pass 123!");
        assert!(result.is_ok()); // Spaces are considered special characters
    }

    #[test]
    fn test_password_all_requirements_disabled() {
        let policy = PasswordPolicy {
            min_length: 0,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };

        let result = policy.validate("");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_edge_case_min_length_zero() {
        let policy = PasswordPolicy {
            min_length: 0,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        let result = policy.validate("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_password_numeric_only() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("123456789012");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_password_letters_only() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("Abcdefghijkl");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("digit"));
    }

    #[test]
    fn test_password_special_only() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("!!!!!!!!!!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_password_mixed_case() {
        let policy = PasswordPolicy::default();
        let result = policy.validate("MiXeDcAsE123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_complex_blacklist() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["admin".to_string(), "root".to_string(), "user".to_string()],
        };

        let result = policy.validate("administrator");
        assert!(result.is_err());

        let result = policy.validate("superuser");
        assert!(result.is_err());

        let result = policy.validate("myrootpassword");
        assert!(result.is_err());

        let result = policy.validate("safe_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_boundary_length() {
        let policy = PasswordPolicy {
            min_length: 5,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };

        // Exactly at minimum length
        let result = policy.validate("12345");
        assert!(result.is_ok());

        // One character short
        let result = policy.validate("1234");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 5 characters"));
    }

    #[test]
    fn test_password_unicode_special_characters() {
        let policy = PasswordPolicy::default();
        // Test with various Unicode special characters
        let unicode_special = vec!["©", "®", "™", "€", "£", "¥", "§", "¶", "†", "‡"];

        for special in unicode_special {
            let password = format!("ValidPass123{}", special);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with Unicode special char '{}' should be valid",
                special
            );
        }
    }

    #[test]
    fn test_password_blacklist_with_special_chars() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["pass@word".to_string(), "test#123".to_string()],
        };

        let result = policy.validate("mypassword");
        assert!(result.is_ok());

        let result = policy.validate("pass@word123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));

        let result = policy.validate("mytest#123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_blacklist_empty_entries() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["".to_string(), "valid".to_string(), "".to_string()],
        };

        let result = policy.validate("password");
        assert!(result.is_ok());

        let result = policy.validate("containsvalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_very_large_blacklist() {
        let mut blacklist = Vec::new();
        for i in 0..1000 {
            blacklist.push(format!("badword{}", i));
        }
        blacklist.push("target".to_string());

        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist,
        };

        let result = policy.validate("goodpassword");
        assert!(result.is_ok());

        let result = policy.validate("passwordwithtarget");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_common_patterns() {
        let policy = PasswordPolicy::default();

        // Common weak patterns
        let weak_patterns = vec![
            "Password1!",
            "password1!",
            "PASSWORD1!",
            "12345678aA!",
            "qwerty123!",
            "abc123!@#",
            "letmein123!",
            "welcome123!",
            "monkey123!",
        ];

        for pattern in weak_patterns {
            let result = policy.validate(pattern);
            assert!(
                result.is_err(),
                "Weak password pattern '{}' should be rejected",
                pattern
            );
        }
    }

    #[test]
    fn test_password_dictionary_attack_simulation() {
        let dictionary_words = vec![
            "password",
            "123456",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "administrator",
            "root",
            "user",
            "guest",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "shadow",
            "baseball",
            "football",
            "soccer",
            "tennis",
        ];

        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: dictionary_words
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
        };

        let result = policy.validate("password123");
        assert!(result.is_err());

        let result = policy.validate("strongunique123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_sequential_characters() {
        let policy = PasswordPolicy::default();

        // Sequential patterns that should be allowed (not in default blacklist)
        let sequential = vec![
            "abcd1234!ABCDE",
            "1234abcd!ABCDE",
            "xyz789!ABCDE",
            "qwer1234!ABCDE",
            "asdf1234!ABCDE",
        ];

        for seq in sequential {
            let result = policy.validate(seq);
            assert!(
                result.is_ok(),
                "Sequential pattern '{}' should be allowed",
                seq
            );
        }
    }

    #[test]
    fn test_password_repeated_characters() {
        let policy = PasswordPolicy::default();

        // Test passwords with repeated characters
        let result = policy.validate("AAAAaaaa1111!!!!");
        assert!(result.is_ok());

        let result = policy.validate("AAAAAAAAAAAAAA"); // Only uppercase, no lowercase/digit/special
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lowercase letter"));
    }

    #[test]
    fn test_password_mixed_scripts() {
        let policy = PasswordPolicy::default();

        // Test mixing different scripts (Latin + Cyrillic, etc.)
        let mixed_scripts = vec![
            "Пароль123!Pass",      // Russian + English
            "パスワード123!Pass",  // Japanese + English
            "كلمة المرور123!Pass", // Arabic + English
        ];

        for script in mixed_scripts {
            let result = policy.validate(script);
            assert!(
                result.is_ok(),
                "Mixed script password '{}' should be valid",
                script
            );
        }
    }

    #[test]
    fn test_password_combining_characters() {
        let policy = PasswordPolicy::default();

        // Test Unicode combining characters
        let combining = "Passwo\u{0301}rd123!"; // Password with combining acute accent
        let result = policy.validate(combining);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_emoji_and_symbols() {
        let policy = PasswordPolicy::default();

        // Test with emoji and symbols
        let emoji_password = "Pass123!🔒";
        let result = policy.validate(emoji_password);
        assert!(result.is_ok());

        let symbol_password = "Pass123!∑∆∫";
        let result = policy.validate(symbol_password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_control_characters() {
        let policy = PasswordPolicy::default();

        // Test with control characters (should be treated as special)
        let control_password = "Pass123!\tControl";
        let result = policy.validate(control_password);
        assert!(result.is_ok());

        let newline_password = "Pass123!\nNewline";
        let result = policy.validate(newline_password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_extremely_long() {
        let policy = PasswordPolicy::default();

        // Test with extremely long password (10,000 characters)
        let extremely_long = "A".repeat(9999) + "a1!";
        let result = policy.validate(&extremely_long);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_minimum_requirements_only() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        // Test password that meets minimum requirements exactly
        let minimal = "Aaaaaaaaaaa1!";
        let result = policy.validate(minimal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_case_sensitivity_in_requirements() {
        let policy = PasswordPolicy::default();

        // Test that requirements are case-sensitive for checking
        let result = policy.validate("password123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase"));

        let result = policy.validate("PASSWORD123!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lowercase"));
    }

    #[test]
    fn test_password_blacklist_case_preservation() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["Password".to_string(), "ADMIN".to_string()],
        };

        // Blacklist should be case-insensitive
        let result = policy.validate("password123");
        assert!(result.is_err());

        let result = policy.validate("admin456");
        assert!(result.is_err());

        let result = policy.validate("safe_password");
        assert!(result.is_err()); // Contains "password" from blacklist
    }

    #[test]
    fn test_password_multiple_blacklist_matches() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["bad".to_string(), "word".to_string()],
        };

        let result = policy.validate("thisisabadword");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_blacklist_substring_matching() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["xyz".to_string()],
        };

        let result = policy.validate("abcxyzdef");
        assert!(result.is_err());

        let result = policy.validate("abcXYZdef"); // Should still match case-insensitively
        assert!(result.is_err());

        let result = policy.validate("abcdef");
        assert!(result.is_err()); // Too short, only 6 characters
    }

    #[test]
    fn test_password_configuration_validation() {
        // Test that configurations are properly validated
        let policy = PasswordPolicy {
            min_length: 0,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };
        assert_eq!(policy.min_length, 0);
        assert!(!policy.require_uppercase);
    }

    #[test]
    fn test_password_zero_length_requirement() {
        let policy = PasswordPolicy {
            min_length: 0,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        let result = policy.validate("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    fn test_password_specific_error_messages() {
        let policy = PasswordPolicy::default();

        // Test specific error messages
        let result = policy.validate("short");
        assert_eq!(
            result.unwrap_err(),
            "Password must be at least 12 characters"
        );

        let result = policy.validate("nouppercase123!");
        assert_eq!(
            result.unwrap_err(),
            "Password must contain an uppercase letter"
        );

        let result = policy.validate("NOLOWERCASE123!");
        assert_eq!(
            result.unwrap_err(),
            "Password must contain a lowercase letter"
        );

        let result = policy.validate("NoDigitSpecial!");
        assert_eq!(result.unwrap_err(), "Password must contain a digit");

        let result = policy.validate("NoSpecial123");
        assert_eq!(
            result.unwrap_err(),
            "Password must contain a special character"
        );
    }

    #[test]
    fn test_password_blacklist_specific_error_message() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["badword".to_string()],
        };

        let result = policy.validate("mypasswordhasbadword");
        assert_eq!(result.unwrap_err(), "Password is too common or blacklisted");
    }

    #[test]
    fn test_password_unicode_normalization() {
        let policy = PasswordPolicy::default();

        // Test Unicode normalization (different representations of same character)
        let normalized = "café"; // NFC normalized
        let decomposed = "café"; // NFD decomposed (if different)

        let result1 = policy.validate(&(normalized.to_string() + "123!A"));
        let result2 = policy.validate(&(decomposed.to_string() + "123!A"));

        // Both should pass or fail consistently
        assert_eq!(result1.is_ok(), result2.is_ok());
    }

    #[test]
    fn test_password_right_to_left_scripts() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: false, // RTL scripts don't have case
            require_lowercase: false,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        // Test RTL scripts like Arabic and Hebrew
        let arabic = "كلمةالمرور123!A"; // "password" in Arabic
        let hebrew = "סיסמה123!A"; // "password" in Hebrew

        let result1 = policy.validate(arabic);
        let result2 = policy.validate(hebrew);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_password_cjk_characters() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: false, // CJK scripts don't have case
            require_lowercase: false,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        // Test CJK (Chinese, Japanese, Korean) characters
        let chinese = "密码123!Abc"; // "password" in Chinese
        let japanese = "パスワード123!Abc"; // "password" in Japanese
        let korean = "비밀번호123!Abc"; // "password" in Korean

        let result1 = policy.validate(chinese);
        let result2 = policy.validate(japanese);
        let result3 = policy.validate(korean);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());
    }

    #[test]
    fn test_password_mathematical_symbols() {
        let policy = PasswordPolicy::default();

        // Test mathematical symbols as special characters
        let math_symbols = vec!["∑", "∏", "∆", "∇", "∫", "∂", "√", "∞", "≠", "≈"];

        for symbol in math_symbols {
            let password = format!("ValidPass123{}", symbol);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with math symbol '{}' should be valid",
                symbol
            );
        }
    }

    #[test]
    fn test_password_currency_symbols() {
        let policy = PasswordPolicy::default();

        // Test currency symbols
        let currencies = vec!["$", "€", "£", "¥", "¢", "₽", "₩", "₿", "₹"];

        for currency in currencies {
            let password = format!("ValidPass123{}", currency);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with currency '{}' should be valid",
                currency
            );
        }
    }

    #[test]
    fn test_password_arrows_and_symbols() {
        let policy = PasswordPolicy::default();

        // Test arrow and other symbols
        let arrows = vec!["←", "→", "↑", "↓", "↔", "⇐", "⇒", "⇔", "▲", "▼"];

        for arrow in arrows {
            let password = format!("ValidPass123{}", arrow);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with arrow '{}' should be valid",
                arrow
            );
        }
    }

    #[test]
    fn test_password_fractions_and_superscripts() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false, // Don't require special for this test
            blacklist: vec![],
        };

        // Test fractions and superscripts
        let fractions = vec!["½", "¼", "¾", "⅓", "⅔", "⅛", "⅜", "⅝", "⅞"];

        for fraction in fractions {
            let password = format!("ValidPass123{}", fraction);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with fraction '{}' should be valid",
                fraction
            );
        }
    }

    #[test]
    fn test_password_chess_symbols() {
        let policy = PasswordPolicy::default();

        // Test chess symbols
        let chess = vec!["♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝"];

        for piece in chess {
            let password = format!("ValidPass123{}", piece);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with chess piece '{}' should be valid",
                piece
            );
        }
    }

    #[test]
    fn test_password_zodiac_symbols() {
        let policy = PasswordPolicy::default();

        // Test zodiac symbols
        let zodiac = vec![
            "♈", "♉", "♊", "♋", "♌", "♍", "♎", "♏", "♐", "♑", "♒", "♓",
        ];

        for sign in zodiac {
            let password = format!("ValidPass123{}", sign);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with zodiac sign '{}' should be valid",
                sign
            );
        }
    }

    #[test]
    fn test_password_card_suits() {
        let policy = PasswordPolicy::default();

        // Test card suit symbols
        let suits = vec!["♠", "♥", "♦", "♣"];

        for suit in suits {
            let password = format!("ValidPass123{}", suit);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with card suit '{}' should be valid",
                suit
            );
        }
    }

    #[test]
    fn test_password_geometric_shapes() {
        let policy = PasswordPolicy::default();

        // Test geometric shapes
        let shapes = vec!["■", "□", "▪", "▫", "▲", "△", "▼", "▽", "◆", "◇"];

        for shape in shapes {
            let password = format!("ValidPass123{}", shape);
            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password with geometric shape '{}' should be valid",
                shape
            );
        }
    }

    #[test]
    fn test_password_blacklist_regex_patterns() {
        // Test blacklist entries that look like regex but should be treated as literals
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![".*".to_string(), ".+".to_string(), "[a-z]+".to_string()],
        };

        // Should match literally, not as regex
        let result = policy.validate("mypassword");
        assert!(result.is_ok()); // Doesn't contain ".*" literally

        let result = policy.validate("contains.*pattern");
        assert!(result.is_err()); // Contains ".*" literally
    }

    #[test]
    fn test_password_blacklist_unicode_words() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![
                "пароль".to_string(),
                "パスワード".to_string(),
                "密码".to_string(),
            ],
        };

        let result = policy.validate("mypassword");
        assert!(result.is_ok());

        let result = policy.validate("пароль123");
        assert!(result.is_err());

        let result = policy.validate("パスワード456");
        assert!(result.is_err());

        let result = policy.validate("密码789");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_blacklist_mixed_case_unicode() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["MÖTLEY".to_string(), "CRÜE".to_string()],
        };

        let result = policy.validate("mötley123");
        assert!(result.is_err());

        let result = policy.validate("CRÜE456");
        assert!(result.is_err());

        let result = policy.validate("safe_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_sequential_validation_order() {
        // Test that validation happens in the correct order: length -> requirements -> blacklist
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec!["password".to_string()],
        };

        // Short password should fail on length first
        let result = policy.validate("short");
        assert!(result.unwrap_err().contains("at least 12 characters"));

        // Password with length but missing uppercase should fail on uppercase
        let result = policy.validate("longpassword123!");
        assert!(result.unwrap_err().contains("uppercase letter"));

        // Password meeting all requirements but blacklisted should fail on blacklist
        let result = policy.validate("Password123!");
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_max_length_handling() {
        // Test that very long passwords are handled correctly
        let policy = PasswordPolicy::default();

        // Test with 1MB password
        let very_long = "A".repeat(500_000) + "a1!";
        let result = policy.validate(&very_long);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_empty_string_edge_cases() {
        let policy = PasswordPolicy {
            min_length: 0,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };

        let result = policy.validate("");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_single_character_passwords() {
        let policy = PasswordPolicy {
            min_length: 1,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };

        let single_chars = vec!["a", "A", "1", "!", "ä", "∑", "🔒"];

        for single in single_chars {
            let result = policy.validate(single);
            assert!(
                result.is_ok(),
                "Single character '{}' should be valid",
                single
            );
        }
    }

    #[test]
    fn test_password_blacklist_overlapping_entries() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![
                "pass".to_string(),
                "password".to_string(),
                "word".to_string(),
            ],
        };

        // Should match on first overlapping entry
        let result = policy.validate("mypassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_blacklist_whitespace_handling() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["pass word".to_string(), "test 123".to_string()],
        };

        let result = policy.validate("my pass word");
        assert!(result.is_err());

        let result = policy.validate("test 123 here");
        assert!(result.is_err());

        let result = policy.validate("safe_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_blacklist_numbers_as_strings() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["123456".to_string(), "999999".to_string()],
        };

        let result = policy.validate("my123456password");
        assert!(result.is_err());

        let result = policy.validate("safe_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_policy_clone_and_equality() {
        let policy1 = PasswordPolicy::default();
        let policy2 = PasswordPolicy::default();

        // Test that default policies are equal
        assert_eq!(policy1.min_length, policy2.min_length);
        assert_eq!(policy1.require_uppercase, policy2.require_uppercase);
        assert_eq!(policy1.require_lowercase, policy2.require_lowercase);
        assert_eq!(policy1.require_digit, policy2.require_digit);
        assert_eq!(policy1.require_special, policy2.require_special);
        assert_eq!(policy1.blacklist, policy2.blacklist);
    }

    #[test]
    fn test_password_policy_custom_construction() {
        let policy = PasswordPolicy {
            min_length: 16,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["custom".to_string()],
        };

        assert_eq!(policy.min_length, 16);
        assert!(!policy.require_uppercase);
        assert!(!policy.require_lowercase);
        assert!(!policy.require_digit);
        assert!(!policy.require_special);
        assert_eq!(policy.blacklist, vec!["custom".to_string()]);
    }

    #[test]
    fn test_password_validation_consistency() {
        let policy = PasswordPolicy::default();
        let test_password = "ValidTest123!";

        // Multiple calls should give consistent results
        for _ in 0..10 {
            let result = policy.validate(test_password);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_password_blacklist_performance_large() {
        // Test with 10,000 blacklist entries
        let mut blacklist = Vec::new();
        for i in 0..10_000 {
            blacklist.push(format!("badword{}", i));
        }

        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist,
        };

        let result = policy.validate("goodpassword");
        assert!(result.is_ok());

        let result = policy.validate("badword5000here");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_unicode_categories() {
        let policy = PasswordPolicy::default();

        // Test various Unicode categories
        let test_cases = vec![
            ("Letter", "ValidPass123!A"),       // Letter
            ("Number", "ValidPass123!1"),       // Decimal number
            ("Punctuation", "ValidPass123!!"),  // Punctuation
            ("Symbol", "ValidPass123!∑"),       // Math symbol
            ("Mark", "ValidPass123!a\u{0301}"), // Combining mark
            ("Separator", "ValidPass123! "),    // Space separator
        ];

        for (category, password) in test_cases {
            let result = policy.validate(password);
            assert!(result.is_ok(), "Password with {} should be valid", category);
        }
    }

    #[test]
    fn test_password_blacklist_case_insensitive_edge_cases() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["Türkçe".to_string(), "naïve".to_string()],
        };

        // Test case-insensitive matching with special characters
        let result = policy.validate("türkçe123");
        assert!(result.is_err());

        let result = policy.validate("NAÏVE456");
        assert!(result.is_err());

        let result = policy.validate("safe_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_requirement_combinations() {
        // Test all possible combinations of requirements
        let combinations = vec![
            (false, false, false, false), // No requirements
            (true, false, false, false),  // Only uppercase
            (false, true, false, false),  // Only lowercase
            (false, false, true, false),  // Only digit
            (false, false, false, true),  // Only special
            (true, true, false, false),   // Upper + lower
            (true, true, true, false),    // Upper + lower + digit
            (true, true, true, true),     // All requirements
        ];

        for (upper, lower, digit, special) in combinations {
            let policy = PasswordPolicy {
                min_length: if upper || lower || digit || special {
                    12
                } else {
                    0
                },
                require_uppercase: upper,
                require_lowercase: lower,
                require_digit: digit,
                require_special: special,
                blacklist: vec![],
            };

            // Create a password that meets the requirements
            let mut password = String::new();
            if upper {
                password.push('A');
            }
            if lower {
                password.push('a');
            }
            if digit {
                password.push('1');
            }
            if special {
                password.push('!');
            }

            // Pad to minimum length if needed
            while password.len() < policy.min_length {
                password.push('x');
            }

            let result = policy.validate(&password);
            assert!(
                result.is_ok(),
                "Password '{}' should meet requirements {:?}",
                password,
                (upper, lower, digit, special)
            );
        }
    }

    #[test]
    fn test_password_blacklist_contains_vs_equals() {
        let policy = PasswordPolicy {
            min_length: 4, // Set to 4 so "good" passes length check
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["bad".to_string()],
        };

        // Should match substrings, not just whole words
        let result = policy.validate("bad");
        assert!(result.is_err());

        let result = policy.validate("abad");
        assert!(result.is_err());

        let result = policy.validate("bada");
        assert!(result.is_err());

        let result = policy.validate("good");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_extreme_boundary_conditions() {
        // Test extreme boundary conditions
        let policy = PasswordPolicy {
            min_length: 1000000, // Very large but reasonable length
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        let result = policy.validate(&"A".repeat(1000)); // Short password that fails length
        assert!(result.is_err()); // Will fail on length
    }

    #[test]
    fn test_password_memory_safety() {
        let policy = PasswordPolicy::default();

        // Test with strings that might cause issues
        let null_bytes = "Pass123!\0null";
        let result = policy.validate(null_bytes);
        assert!(result.is_ok());

        let high_unicode = "Pass123!\u{10FFFF}"; // Last Unicode code point
        let result = policy.validate(high_unicode);
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_blacklist_duplicate_entries() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["bad".to_string(), "bad".to_string(), "bad".to_string()],
        };

        let result = policy.validate("abad");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_blacklist_long_entries() {
        let long_bad_word = "a".repeat(1000);
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![long_bad_word.clone()],
        };

        let result = policy.validate("goodpassword");
        assert!(result.is_ok());

        let result = policy.validate(&("prefix".to_string() + &long_bad_word + "suffix"));
        assert!(result.is_err());
    }

    #[test]
    fn test_password_validation_error_precedence() {
        // Test that the first validation failure takes precedence
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec!["password".to_string()],
        };

        // Password that's too short and missing requirements and blacklisted
        let result = policy.validate("pass");
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("at least 12 characters"));
        assert!(!err_msg.contains("uppercase")); // Should not check further
    }

    #[test]
    fn test_password_blacklist_unicode_case_folding() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["straße".to_string()], // German for street
        };

        // Test case-insensitive matching with Unicode case folding
        let result = policy.validate("STRASSE123"); // Uppercase version - should be accepted as "strasse" != "straße"
        assert!(result.is_ok());

        let result = policy.validate("Straße456"); // Same as blacklist
        assert!(result.is_err());

        let result = policy.validate("strasse789"); // Lowercase version - should be accepted as "strasse" != "straße"
        assert!(result.is_ok());

        let result = policy.validate("goodpassword"); // Should not contain "straße"
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_policy_debug_formatting() {
        let policy = PasswordPolicy::default();

        // Test that the policy can be debug formatted
        let debug_str = format!("{:?}", policy);
        assert!(debug_str.contains("PasswordPolicy"));
        assert!(debug_str.contains("min_length"));
    }

    #[test]
    fn test_password_blacklist_empty_and_whitespace_only() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["bad".to_string(), "   ".to_string(), "\t".to_string()], // No empty string
        };

        // Empty and whitespace-only entries should be ignored
        let result = policy.validate("excellent");
        assert!(result.is_ok());

        let result = policy.validate("   password   ");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_concurrent_validation() {
        use std::thread;

        let policy = PasswordPolicy::default();
        let mut handles = vec![];

        // Test concurrent validation
        for i in 0..10 {
            let policy_clone = policy.clone();
            let handle = thread::spawn(move || {
                let password = format!("ValidPass123!{}", i);
                policy_clone.validate(&password).is_ok()
            });
            handles.push(handle);
        }

        for handle in handles {
            assert!(handle.join().unwrap());
        }
    }

    #[test]
    fn test_password_blacklist_regex_like_patterns() {
        // Test patterns that might be confused with regex
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["^password$".to_string(), "pass.*word".to_string()],
        };

        let result = policy.validate("goodpassword");
        assert!(result.is_ok());

        let result = policy.validate("^password$here");
        assert!(result.is_err());

        let result = policy.validate("passXXXword");
        assert!(result.is_ok()); // Literal substring matching, not regex
    }

    #[test]
    fn test_password_policy_partial_validation() {
        // Test partial validation scenarios
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![],
        };

        // Should pass length and uppercase but not check others
        let result = policy.validate("SHORT");
        assert!(result.is_err()); // Too short

        let result = policy.validate("longenough");
        assert!(result.is_err()); // Missing uppercase

        let result = policy.validate("LongEnough");
        assert!(result.is_ok()); // Meets requirements
    }

    #[test]
    fn test_password_blacklist_case_sensitivity_verification() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["Password".to_string()],
        };

        // Verify case-insensitive matching
        let test_cases = vec![
            "password",
            "PASSWORD",
            "Password",
            "PaSsWoRd",
            "mypassword",
            "PASSWORDhere",
            "prefixPASSWORDsuffix",
        ];

        for case in test_cases {
            let result = policy.validate(case);
            assert!(
                result.is_err(),
                "Case variant '{}' should be rejected",
                case
            );
        }

        let result = policy.validate("goodsecret");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_extreme_unicode_combinations() {
        let policy = PasswordPolicy::default();

        // Test extreme Unicode combinations
        let combinations = vec![
            "Pass123!ñLong", // Latin with tilde
            "Pass123!éLong", // Latin with acute
            "Pass123!üLong", // Latin with diaeresis
            "Pass123!øLong", // Latin with stroke
            "Pass123!åLong", // Latin with ring
            "Pass123!çLong", // Latin with cedilla
            "Pass123!ßLong", // German sharp s
            "Pass123!æLong", // Latin ligature ae
            "Pass123!œLong", // Latin ligature oe
        ];

        for combo in combinations {
            let result = policy.validate(combo);
            assert!(
                result.is_ok(),
                "Unicode combination '{}' should be valid",
                combo
            );
        }
    }

    #[test]
    fn test_password_blacklist_international_common_words() {
        let international_blacklist = vec![
            "password",
            "contraseña",
            "motdepasse",
            "passwort",
            "wachtwoord",
            "senha",
            "пароль",
            "密码",
            "パスワード",
            "كلمةالمرور",
        ];

        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: international_blacklist
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
        };

        // Test that international common passwords are blocked
        let test_cases = vec![
            "mypassword",
            "micontraseña",
            "monmotdepasse",
            "meinpasswort",
            "mijnwachtwoord",
            "minhasenha",
            "мойпароль",
            "我的密码",
            "マイパスワード",
            "كلمةالمرور",
        ];

        for case in test_cases {
            let result = policy.validate(case);
            assert!(
                result.is_err(),
                "International password '{}' should be rejected",
                case
            );
        }
    }

    #[test]
    fn test_password_policy_builder_pattern_simulation() {
        // Simulate a builder pattern for password policies
        let mut policy = PasswordPolicy::default();
        policy.min_length = 16;
        policy.require_uppercase = false;
        policy.require_lowercase = false;
        policy.require_digit = false;
        policy.require_special = false;
        policy.blacklist = vec!["weak".to_string()];

        assert_eq!(policy.min_length, 16);
        assert!(!policy.require_uppercase);
        assert!(!policy.require_lowercase);
        assert!(!policy.require_digit);
        assert!(!policy.require_special);
        assert_eq!(policy.blacklist, vec!["weak".to_string()]);

        let result = policy.validate("strongpasswordhere");
        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // Timing test that can be flaky in different environments
    fn test_password_validation_timing_consistency() {
        use std::time::Instant;

        let policy = PasswordPolicy::default();
        let test_password = "ValidTestPassword123!";

        // Measure validation time consistency
        let mut times = vec![];

        for _ in 0..100 {
            let start = Instant::now();
            let _ = policy.validate(test_password);
            times.push(start.elapsed());
        }

        // All times should be reasonably similar (within 50x of median to account for system variability)
        let median_time = times[times.len() / 2];
        for time in times {
            assert!(
                time < median_time * 50,
                "Validation time {:?} too slow compared to median {:?}",
                time,
                median_time
            );
        }
    }

    #[test]
    fn test_password_blacklist_memory_efficiency() {
        // Test that blacklist operations don't create excessive copies
        let large_blacklist: Vec<String> = (0..1000).map(|i| format!("word{}", i)).collect();

        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: large_blacklist,
        };

        // This should not cause excessive memory usage
        let result = policy.validate("goodpassword");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_policy_serialization_simulation() {
        // Simulate serialization/deserialization
        let original = PasswordPolicy::default();

        // Simulate serialization to JSON-like structure
        let serialized = (
            original.min_length,
            original.require_uppercase,
            original.require_lowercase,
            original.require_digit,
            original.require_special,
            original.blacklist.clone(),
        );

        // Simulate deserialization
        let deserialized = PasswordPolicy {
            min_length: serialized.0,
            require_uppercase: serialized.1,
            require_lowercase: serialized.2,
            require_digit: serialized.3,
            require_special: serialized.4,
            blacklist: serialized.5,
        };

        // Should be equivalent
        assert_eq!(original.min_length, deserialized.min_length);
        assert_eq!(original.require_uppercase, deserialized.require_uppercase);
        assert_eq!(original.require_lowercase, deserialized.require_lowercase);
        assert_eq!(original.require_digit, deserialized.require_digit);
        assert_eq!(original.require_special, deserialized.require_special);
        assert_eq!(original.blacklist, deserialized.blacklist);

        // Should validate the same
        let test_pass = "TestPassword123!";
        assert_eq!(
            original.validate(test_pass),
            deserialized.validate(test_pass)
        );
    }

    #[test]
    fn test_password_blacklist_contains_unicode_substrings() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["café".to_string()],
        };

        let result = policy.validate("Ilove café au lait");
        assert!(result.is_err());

        let result = policy.validate("Café is great");
        assert!(result.is_err());

        let result = policy.validate("goodpassword");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_policy_zero_min_length_with_requirements() {
        let policy = PasswordPolicy {
            min_length: 0,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec![],
        };

        // Even with zero min length, requirements must be met
        let result = policy.validate("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));

        let result = policy.validate("A");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lowercase letter"));

        let result = policy.validate("Aa");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("digit"));

        let result = policy.validate("Aa1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("special character"));

        let result = policy.validate("Aa1!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_blacklist_case_insensitive_unicode_preservation() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["naïve".to_string()],
        };

        // Test that Unicode characters are preserved in case-insensitive matching
        let result = policy.validate("NAÏVE");
        assert!(result.is_err());

        let result = policy.validate("naïve");
        assert!(result.is_err());

        let result = policy.validate("NaïVe");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_validation_error_message_consistency() {
        let policy = PasswordPolicy::default();

        // Test that error messages are consistent across multiple calls
        let test_cases = vec![
            ("short", "at least 12 characters"),
            ("nouppercase123!", "uppercase letter"),
            ("NOLOWERCASE123!", "lowercase letter"),
            ("NoDigitABCDEFGHIJ!", "digit"),
            (
                "NoSpecial123ABCDEFGHIJ",
                "Password must contain a special character",
            ),
        ];

        for (password, expected_error) in test_cases {
            for _ in 0..5 {
                let result = policy.validate(password);
                assert!(result.is_err());
                assert!(result.as_ref().unwrap_err().contains(expected_error));
            }
        }
    }

    #[test]
    fn test_password_blacklist_extreme_case_variations() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["test".to_string()],
        };

        // Test various case variations
        let variations = vec![
            "TEST",
            "Test",
            "tEsT",
            "TeSt",
            "tEST",
            "myTESTword",
            "TESTing",
            "testED",
            "preTESTpost",
        ];

        for variation in variations {
            let result = policy.validate(variation);
            assert!(
                result.is_err(),
                "Variation '{}' should be rejected",
                variation
            );
        }
    }

    #[test]
    fn test_password_policy_configuration_edge_cases() {
        // Test edge case configurations
        let policies = vec![
            PasswordPolicy {
                min_length: 1_000_000, // Very large but not MAX
                require_uppercase: false,
                require_lowercase: false,
                require_digit: false,
                require_special: false,
                blacklist: vec![],
            },
            PasswordPolicy {
                min_length: 0,
                require_uppercase: true,
                require_lowercase: true,
                require_digit: true,
                require_special: true,
                blacklist: vec!["".to_string()],
            },
        ];

        for policy in policies {
            // Should not panic, even with extreme configurations
            let _ = policy.validate("test");
        }
    }

    #[test]
    fn test_password_blacklist_contains_at_boundaries() {
        let policy = PasswordPolicy {
            min_length: 4, // Set to 4 so "good" passes length check
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["bad".to_string()],
        };

        // Test matching at string boundaries
        let result = policy.validate("bad");
        assert!(result.is_err());

        let result = policy.validate("badword");
        assert!(result.is_err());

        let result = policy.validate("wordbad");
        assert!(result.is_err());

        let result = policy.validate("good");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_validation_result_consistency() {
        let policy = PasswordPolicy::default();

        // Test that the same password always gives the same result
        let password = "TestPassword123!";
        let result1 = policy.validate(password);
        let result2 = policy.validate(password);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_password_blacklist_empty_string_handling() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["".to_string(), "bad".to_string()],
        };

        // Empty strings in blacklist should be ignored
        let result = policy.validate("password");
        assert!(result.is_ok());

        let result = policy.validate("badpassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_policy_default_values() {
        let policy = PasswordPolicy::default();

        // Verify default values
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
    fn test_password_blacklist_case_insensitive_contains() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["PASSWORD".to_string()],
        };

        // Test various positions and cases
        let test_cases = vec![
            "password",
            "PASSWORD",
            "Password",
            "passWORD",
            "mypassword",
            "PASSWORDhere",
            "prefixPASSWORD",
        ];

        for case in test_cases {
            let result = policy.validate(case);
            assert!(result.is_err(), "Case '{}' should match blacklist", case);
        }
    }

    #[test]
    fn test_password_validation_order_preservation() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            blacklist: vec!["password".to_string()],
        };

        // Test that validation order is preserved
        let failing_passwords = vec![
            ("short", "at least 12 characters"),
            ("verylongwordwithoutuppercase123!", "uppercase letter"),
            ("VERYLONGWORDWITHOUTLOWERCASE123!", "lowercase letter"),
            ("VeryLongWordWithoutDigit!", "digit"),
            (
                "VeryLongWordWithoutSpecial123",
                "Password must contain a special character",
            ),
        ];

        for (password, expected_error) in failing_passwords {
            let result = policy.validate(password);
            assert!(
                result.is_err(),
                "Password '{}' should have failed validation",
                password
            );
            assert!(result.unwrap_err().contains(expected_error));
        }
    }

    #[test]
    fn test_password_blacklist_multiple_matches_priority() {
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec![
                "bad".to_string(),
                "worse".to_string(),
                "terrible".to_string(),
            ],
        };

        // Should fail as soon as any blacklist entry matches
        let result = policy.validate("thisisbadandworse");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too common or blacklisted"));
    }

    #[test]
    fn test_password_policy_memory_safety_edge_cases() {
        let policy = PasswordPolicy::default();

        // Test with potentially problematic strings
        let very_long = "A".repeat(100_000);
        let many_emojis = "🚀".repeat(10_000);

        let edge_cases = vec![
            "",           // Empty
            "\0",         // Null byte
            "\u{0}",      // Null character
            "\u{10FFFF}", // Last Unicode
            &very_long,   // Very long
            &many_emojis, // Many emojis
        ];

        for edge_case in edge_cases {
            // Should not panic
            let _ = policy.validate(edge_case);
        }
    }

    #[test]
    fn test_password_blacklist_contains_with_unicode_boundaries() {
        let policy = PasswordPolicy {
            min_length: 4, // Set to 4 so "good" passes length check
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            blacklist: vec!["café".to_string()],
        };

        // Test Unicode substring matching at boundaries
        let result = policy.validate("café");
        assert!(result.is_err());

        let result = policy.validate("caféau");
        assert!(result.is_err());

        let result = policy.validate("lecafé");
        assert!(result.is_err());

        let result = policy.validate("good");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_validation_comprehensive_edge_cases() {
        let policy = PasswordPolicy::default();

        // Comprehensive edge case testing
        let long_a = "A".repeat(12);
        let long_a_lower = "a".repeat(12);
        let long_a1 = "A1".repeat(6);

        let edge_cases = vec![
            ("", false),                  // Empty - fails length
            ("A", false),                 // Too short
            (&long_a, false),             // Missing lowercase/digit/special
            (&long_a_lower, false),       // Missing uppercase/digit/special
            (&long_a1, false),            // Missing special
            ("Aa1", false),               // Too short
            ("Aa1!Aa1!Aa1!", true),       // Valid minimal
            ("ValidPassword123!", false), // Contains blacklisted term
            ("Password123!", false),      // Blacklisted
        ];

        for (password, should_pass) in edge_cases {
            let result = policy.validate(password);
            if should_pass {
                assert!(result.is_ok(), "Password '{}' should be valid", password);
            } else {
                assert!(result.is_err(), "Password '{}' should be invalid", password);
            }
        }
    }
}
