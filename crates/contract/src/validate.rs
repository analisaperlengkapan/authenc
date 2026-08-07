//! Validation rules shared by the browser and the server.
//!
//! This module is the concrete pay-off of a Rust frontend: the check that greys
//! out the submit button and the check that guards the database are the same
//! code, so they cannot drift. The server still runs every rule — the browser
//! copy is a convenience, never a trust boundary.

use crate::error::{AppError, Result};

/// Longest accepted username.
pub const USERNAME_MAX: usize = 64;
/// Shortest accepted username.
pub const USERNAME_MIN: usize = 3;
/// Longest accepted email address (RFC 5321 limit).
pub const EMAIL_MAX: usize = 254;
/// Shortest accepted password. NIST SP 800-63B recommends at least 8.
pub const PASSWORD_MIN: usize = 12;
/// Longest accepted password. Argon2 handles long input, but bound it so a
/// megabyte-long password cannot be used to burn CPU.
pub const PASSWORD_MAX: usize = 1024;

/// Validate a username: ASCII letters, digits, and `._-`, not starting or
/// ending with a separator.
pub fn username(value: &str) -> Result<()> {
    if value.len() < USERNAME_MIN {
        return Err(AppError::field(
            "username",
            format!("must be at least {USERNAME_MIN} characters"),
        ));
    }
    if value.len() > USERNAME_MAX {
        return Err(AppError::field(
            "username",
            format!("must be at most {USERNAME_MAX} characters"),
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(AppError::field(
            "username",
            "may only contain letters, digits, and . _ -",
        ));
    }
    let starts_or_ends_with_separator = value
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '.' | '_' | '-'))
        || value
            .chars()
            .next_back()
            .is_some_and(|c| matches!(c, '.' | '_' | '-'));
    if starts_or_ends_with_separator {
        return Err(AppError::field(
            "username",
            "may not start or end with . _ -",
        ));
    }
    Ok(())
}

/// Validate an email address.
///
/// Deliberately permissive: exactly one `@`, a non-empty local part, and a
/// domain containing a dot with non-empty labels. Anything stricter rejects
/// addresses that are legal in practice, and the only real proof that an
/// address works is sending mail to it.
pub fn email(value: &str) -> Result<()> {
    if value.len() > EMAIL_MAX {
        return Err(AppError::field(
            "email",
            format!("must be at most {EMAIL_MAX} characters"),
        ));
    }
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(AppError::field("email", "must contain exactly one @"));
    };
    if local.is_empty() {
        return Err(AppError::field("email", "is missing the part before @"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(AppError::field("email", "may not contain whitespace"));
    }
    if !domain.contains('.') || domain.split('.').any(str::is_empty) {
        return Err(AppError::field("email", "domain is not valid"));
    }
    Ok(())
}

/// How strong a password is, for the strength meter in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Fails policy; cannot be used.
    TooWeak,
    /// Meets policy, but only just.
    Fair,
    /// Comfortably above policy.
    Strong,
}

/// Validate a password against policy, returning its strength.
///
/// Follows NIST SP 800-63B: length is the primary control, and there are no
/// composition rules (no "must contain a symbol"), because those push users
/// towards predictable substitutions without adding real entropy.
pub fn password(value: &str) -> Result<Strength> {
    let length = value.chars().count();
    if length < PASSWORD_MIN {
        return Err(AppError::field(
            "password",
            format!("must be at least {PASSWORD_MIN} characters"),
        ));
    }
    if value.len() > PASSWORD_MAX {
        return Err(AppError::field(
            "password",
            format!("must be at most {PASSWORD_MAX} bytes"),
        ));
    }
    if is_single_repeated_character(value) {
        return Err(AppError::field(
            "password",
            "may not be a single repeated character",
        ));
    }

    let classes = character_classes(value);
    Ok(match (length, classes) {
        (0..=15, _) | (_, 1) => Strength::Fair,
        _ => Strength::Strong,
    })
}

fn is_single_repeated_character(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| chars.all(|c| c == first))
}

fn character_classes(value: &str) -> u8 {
    let has_lower = value.chars().any(char::is_lowercase);
    let has_upper = value.chars().any(char::is_uppercase);
    let has_digit = value.chars().any(|c| c.is_numeric());
    let has_other = value
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());
    u8::from(has_lower) + u8::from(has_upper) + u8::from(has_digit) + u8::from(has_other)
}

/// Validate a realm name: a URL-safe slug, since it appears in OIDC issuer URLs.
pub fn realm_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 {
        return Err(AppError::field(
            "realm",
            "must be between 1 and 64 characters",
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::field(
            "realm",
            "may only contain lowercase letters, digits, and -",
        ));
    }
    if value.starts_with('-') || value.ends_with('-') {
        return Err(AppError::field("realm", "may not start or end with -"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_usernames() {
        for ok in ["alice", "bob.smith", "carol_1", "dave-x", "a1b"] {
            assert!(username(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn rejects_malformed_usernames() {
        for bad in [
            "ab",
            "_alice",
            "alice_",
            "al ice",
            "al/ice",
            "a".repeat(65).as_str(),
        ] {
            assert!(username(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn accepts_ordinary_emails() {
        for ok in ["a@b.co", "first.last+tag@example.com", "x@sub.domain.org"] {
            assert!(email(ok).is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn rejects_malformed_emails() {
        for bad in [
            "",
            "no-at-sign",
            "@example.com",
            "a@b",
            "a@@b.co",
            "a b@c.co",
            "a@.com",
        ] {
            assert!(email(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn enforces_password_length_not_composition() {
        assert!(password("short").is_err());
        // A long passphrase of only lowercase letters is fine — no symbol rule.
        assert!(password("correct horse battery staple").is_ok());
    }

    #[test]
    fn rejects_repeated_character_passwords() {
        assert!(password(&"a".repeat(20)).is_err());
    }

    #[test]
    fn grades_strength() {
        assert_eq!(password("passwordpass").unwrap(), Strength::Fair);
        assert_eq!(
            password("correct horse battery staple 7!").unwrap(),
            Strength::Strong
        );
    }

    #[test]
    fn password_length_counts_characters_but_bounds_bytes() {
        // 12 multi-byte characters satisfy the minimum even though they are
        // 24 bytes — the minimum counts characters, the maximum counts bytes.
        let twelve_chars = "éàüñöâêîôûçß";
        assert_eq!(twelve_chars.chars().count(), 12);
        assert!(twelve_chars.len() > 12);
        assert!(password(twelve_chars).is_ok());
        assert!(password(&"a".repeat(PASSWORD_MAX + 1)).is_err());
    }

    #[test]
    fn realm_names_are_url_safe_slugs() {
        assert!(realm_name("master").is_ok());
        assert!(realm_name("acme-corp").is_ok());
        for bad in ["", "-x", "x-", "Acme", "acme_corp", "acme/corp"] {
            assert!(realm_name(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
