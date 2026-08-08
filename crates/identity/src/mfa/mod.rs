//! Second factors.
//!
//! # The shape that makes a bypass impossible
//!
//! The dangerous way to build this is to authenticate the password, open a
//! session, and then ask for a code — because now the session exists, and every
//! route that reads the session cookie is reachable by anyone who guessed a
//! password. Whether the code is ever checked becomes a property of the login
//! page rather than of the system.
//!
//! So [`crate::login::authenticate`] does not return a session at all when a
//! second factor is enrolled. It returns a [`challenge::Pending`], which lives
//! in its own table, has its own short lifetime and its own attempt budget, and
//! is understood by exactly one function. Nothing that reads a session cookie
//! can be handed one by mistake, because it is not the same type and not the
//! same table.
//!
//! # What counts as enrolled
//!
//! Only credentials that are finished. An enrolment that was started and
//! abandoned — a TOTP secret shown but never confirmed, a passkey ceremony
//! that never came back — must not gate a login, or a user who closed the tab
//! halfway through has locked themselves out of their own account.

pub mod challenge;
pub mod passkey;
pub mod recovery;
pub mod totp;

use authenc_contract::{AppError, Result, UserId};
use serde::{Deserialize, Serialize};

use crate::db::Db;

/// A way of proving a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    /// A time-based one-time password.
    Totp,
    /// A WebAuthn passkey.
    Passkey,
    /// One of the codes issued for when the others are unavailable.
    RecoveryCode,
}

impl Factor {
    /// The RFC 8176 authentication-method value for this factor, if one
    /// exists.
    ///
    /// Recovery codes have none, and none is invented: a relying party reading
    /// `hwk` or `otp` for a code the user read off a printout would draw a
    /// stronger conclusion than the facts support. They contribute `mfa` and
    /// nothing more.
    #[must_use]
    pub const fn amr(self) -> Option<&'static str> {
        match self {
            Self::Totp => Some("otp"),
            Self::Passkey => Some("hwk"),
            Self::RecoveryCode => None,
        }
    }
}

/// The `amr` value for a password.
pub const AMR_PASSWORD: &str = "pwd";

/// The `amr` value asserting that more than one factor was used.
pub const AMR_MULTI_FACTOR: &str = "mfa";

/// How a session was authenticated, in the form OIDC's `amr` claim wants.
///
/// Built here rather than at the protocol layer so that the session row and
/// the ID token cannot disagree about what actually happened.
#[must_use]
pub fn amr_for(second: Option<Factor>) -> Vec<String> {
    let mut values = vec![AMR_PASSWORD.to_owned()];
    if let Some(factor) = second {
        if let Some(name) = factor.amr() {
            values.push(name.to_owned());
        }
        values.push(AMR_MULTI_FACTOR.to_owned());
    }
    values
}

/// What a user currently has enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolment {
    /// Whether a **confirmed** TOTP credential exists.
    pub totp: bool,
    /// How many passkeys are registered.
    pub passkeys: i64,
    /// How many recovery codes remain unused.
    pub recovery_codes: i64,
}

impl Enrolment {
    /// Nothing enrolled.
    pub const NONE: Self = Self {
        totp: false,
        passkeys: 0,
        recovery_codes: 0,
    };

    /// Whether a second factor must be presented before a session is opened.
    ///
    /// Recovery codes deliberately do not count. They are a way *past* a lost
    /// factor, not a factor — if they were enough on their own, generating
    /// them would silently turn on MFA for an account that has no authenticator
    /// and no passkey, and lock the user out at the next login.
    #[must_use]
    pub const fn is_required(self) -> bool {
        self.totp || self.passkeys > 0
    }

    /// The factors the user could present right now.
    #[must_use]
    pub fn available(self) -> Vec<Factor> {
        let mut factors = Vec::new();
        if self.totp {
            factors.push(Factor::Totp);
        }
        if self.passkeys > 0 {
            factors.push(Factor::Passkey);
        }
        if self.recovery_codes > 0 {
            factors.push(Factor::RecoveryCode);
        }
        factors
    }
}

/// What this user has enrolled.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn enrolment(db: &Db, user_id: UserId) -> Result<Enrolment> {
    let row = sqlx::query!(
        r#"
        SELECT
            EXISTS (
                SELECT 1 FROM totp_credentials
                WHERE user_id = $1 AND confirmed_at IS NOT NULL
            ) AS "totp!",
            (SELECT count(*) FROM passkeys WHERE user_id = $1) AS "passkeys!",
            (
                SELECT count(*) FROM recovery_codes
                WHERE user_id = $1 AND used_at IS NULL
            ) AS "recovery_codes!"
        "#,
        user_id.0,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("reading MFA enrolment", e))?;

    Ok(Enrolment {
        totp: row.totp,
        passkeys: row.passkeys,
        recovery_codes: row.recovery_codes,
    })
}

/// Remove every second factor from an account.
///
/// Used when an administrator has to get a locked-out user back in, and by the
/// account page itself. It is deliberately all-or-nothing: leaving one factor
/// behind after a "disable MFA" is the kind of partial state that produces a
/// user who believes they are protected and is not.
///
/// # Errors
///
/// Returns an internal error if any delete fails.
pub async fn clear(db: &Db, user_id: UserId) -> Result<()> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("clearing MFA", e))?;

    for statement in [
        "DELETE FROM totp_credentials WHERE user_id = $1",
        "DELETE FROM passkeys WHERE user_id = $1",
        "DELETE FROM recovery_codes WHERE user_id = $1",
        "DELETE FROM webauthn_ceremonies WHERE user_id = $1",
    ] {
        sqlx::query(statement)
            .bind(user_id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal_from("clearing MFA", e))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("clearing MFA", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_enrolled_means_nothing_is_required() {
        assert!(!Enrolment::NONE.is_required());
        assert!(Enrolment::NONE.available().is_empty());
    }

    #[test]
    fn a_confirmed_authenticator_or_a_passkey_requires_a_second_factor() {
        assert!(
            Enrolment {
                totp: true,
                ..Enrolment::NONE
            }
            .is_required()
        );
        assert!(
            Enrolment {
                passkeys: 1,
                ..Enrolment::NONE
            }
            .is_required()
        );
    }

    #[test]
    fn recovery_codes_alone_do_not_turn_on_mfa() {
        // Otherwise generating recovery codes locks out an account that has no
        // authenticator to recover *to*.
        let only_codes = Enrolment {
            recovery_codes: 10,
            ..Enrolment::NONE
        };
        assert!(!only_codes.is_required());
    }

    #[test]
    fn available_factors_track_what_is_enrolled() {
        let all = Enrolment {
            totp: true,
            passkeys: 2,
            recovery_codes: 8,
        };
        assert_eq!(
            all.available(),
            vec![Factor::Totp, Factor::Passkey, Factor::RecoveryCode],
        );

        let codes_gone = Enrolment {
            recovery_codes: 0,
            ..all
        };
        assert_eq!(codes_gone.available(), vec![Factor::Totp, Factor::Passkey]);
    }

    #[test]
    fn a_password_alone_claims_one_factor() {
        assert_eq!(amr_for(None), vec!["pwd"]);
    }

    #[test]
    fn a_second_factor_is_named_and_asserted() {
        assert_eq!(amr_for(Some(Factor::Totp)), vec!["pwd", "otp", "mfa"]);
        assert_eq!(amr_for(Some(Factor::Passkey)), vec!["pwd", "hwk", "mfa"]);
    }

    #[test]
    fn a_recovery_code_claims_multi_factor_but_names_no_method() {
        // `mfa` is true — two things were presented. Naming it `otp` or `hwk`
        // would tell a relying party something that is not.
        assert_eq!(amr_for(Some(Factor::RecoveryCode)), vec!["pwd", "mfa"]);
    }

    #[test]
    fn every_amr_value_is_one_rfc_8176_registered() {
        // Registered values only; an unrecognised one is worse than silence
        // because a relying party may match on it.
        const REGISTERED: &[&str] = &["pwd", "otp", "hwk", "swk", "mfa", "pin", "user"];
        for factor in [Factor::Totp, Factor::Passkey, Factor::RecoveryCode] {
            for value in amr_for(Some(factor)) {
                assert!(REGISTERED.contains(&value.as_str()), "{value}");
            }
        }
    }
}
