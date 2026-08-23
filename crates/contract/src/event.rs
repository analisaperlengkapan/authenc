//! The audit event model.
//!
//! **One** model. The previous tree had three competing event types in
//! different crates, none of which was written to durable storage by anything,
//! so "what happened to this account?" had no answer at all.
//!
//! # Why the action is an enum
//!
//! Same reason [`Permission`](crate::Permission) is. A string action is a typo
//! away from an event nobody can query for, and there is no way to enumerate
//! what the system can record. [`Action::ALL`] is the complete, reviewable
//! list, and a renamed variant is a compile error rather than a silent gap in
//! the trail.
//!
//! # What an audit record is for
//!
//! Answering, after the fact, *who did what to whom, from where, and did it
//! work*. Every field here exists to serve one of those; anything that does
//! not is noise that makes the log more expensive to keep and harder to read.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::id::{RealmId, UserId};

/// Something worth recording.
///
/// Serialised as its stored name — `login.succeeded`, not `login_succeeded` —
/// for the reason [`Permission`](crate::Permission) is: a derived spelling is a
/// second name for the same thing, and only one of the two parses back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    // --- Authentication ---
    /// A password was accepted and a session opened.
    LoginSucceeded,
    /// A password was refused.
    LoginFailed,
    /// An attempt was refused because the identifier or address is locked out.
    LoginLockedOut,
    /// A password was accepted but a second factor is still required.
    SecondFactorRequired,
    /// A second factor was accepted and a session opened.
    SecondFactorSucceeded,
    /// A second factor was refused.
    SecondFactorFailed,
    /// A session was ended deliberately.
    LoggedOut,

    // --- Credential recovery ---
    /// Someone asked for a password-reset link.
    PasswordResetRequested,
    /// A reset link was used and the password changed.
    PasswordResetCompleted,
    /// An email address was proved.
    EmailVerified,

    // --- Second factors ---
    /// An authenticator was enrolled and confirmed.
    TotpEnrolled,
    /// An authenticator was removed.
    TotpRemoved,
    /// A fresh set of recovery codes was issued.
    RecoveryCodesGenerated,
    /// A recovery code was spent to sign in.
    RecoveryCodeUsed,
    /// A passkey was registered.
    PasskeyRegistered,
    /// A passkey was removed.
    PasskeyRemoved,

    // --- Directory administration ---
    /// A user was created.
    UserCreated,
    /// A user's details or status changed.
    UserUpdated,
    /// A user was deleted.
    UserDeleted,
    /// A role was created.
    RoleCreated,
    /// A role's permissions were replaced.
    RoleUpdated,
    /// A role was deleted.
    RoleDeleted,
    /// A role was granted to a user.
    RoleGranted,
    /// A role was taken from a user.
    RoleRevoked,
    /// A realm was created.
    RealmCreated,
    /// A group was created.
    GroupCreated,
    /// A group was moved or renamed.
    GroupUpdated,
    /// A group and its subtree were deleted.
    GroupDeleted,
    /// A user was put in a group.
    GroupMemberAdded,
    /// A user was taken out of a group.
    GroupMemberRemoved,
    /// An organisation was created.
    OrganizationCreated,
    /// An organisation was suspended or restored.
    OrganizationEnabledChanged,
    /// An organisation was deleted.
    OrganizationDeleted,
    /// Someone was added to an organisation, or their role there changed.
    OrganizationMemberSet,
    /// Someone was removed from an organisation.
    OrganizationMemberRemoved,
    /// An address was invited to an organisation.
    OrganizationInvited,
    /// An invitation was accepted.
    OrganizationInvitationAccepted,
    /// An invitation was withdrawn.
    OrganizationInvitationRevoked,
    /// A role was granted to a group.
    GroupRoleGranted,
    /// A role was taken from a group.
    GroupRoleRevoked,

    // --- OAuth ---
    /// An OAuth client was registered.
    ClientRegistered,
    /// An OAuth client's configuration changed.
    ClientUpdated,
    /// An OAuth client was deleted.
    ClientDeleted,
    /// An OAuth client's secret was replaced.
    ClientSecretRotated,
    /// A user approved a client's request for scopes.
    ConsentGranted,
    /// A user withdrew a client's approval.
    ConsentRevoked,
    /// Tokens were issued to a client.
    TokenIssued,
    /// A token was revoked.
    TokenRevoked,
    /// A spent refresh token was presented again, and its family was revoked.
    RefreshTokenReuseDetected,
    /// A realm's signing key was rotated.
    SigningKeyRotated,
}

/// Where an action belongs, for filtering a long list down to a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Signing in and out.
    Authentication,
    /// Recovering access to an account.
    Recovery,
    /// Second factors.
    MultiFactor,
    /// Changes to users, roles, and realms.
    Directory,
    /// OAuth clients, consent, and tokens.
    Oauth,
}

impl Action {
    /// Every action. The complete list of what this system records.
    pub const ALL: &'static [Self] = &[
        Self::LoginSucceeded,
        Self::LoginFailed,
        Self::LoginLockedOut,
        Self::SecondFactorRequired,
        Self::SecondFactorSucceeded,
        Self::SecondFactorFailed,
        Self::LoggedOut,
        Self::PasswordResetRequested,
        Self::PasswordResetCompleted,
        Self::EmailVerified,
        Self::TotpEnrolled,
        Self::TotpRemoved,
        Self::RecoveryCodesGenerated,
        Self::RecoveryCodeUsed,
        Self::PasskeyRegistered,
        Self::PasskeyRemoved,
        Self::UserCreated,
        Self::UserUpdated,
        Self::UserDeleted,
        Self::RoleCreated,
        Self::RoleUpdated,
        Self::RoleDeleted,
        Self::RoleGranted,
        Self::RoleRevoked,
        Self::RealmCreated,
        Self::GroupCreated,
        Self::GroupUpdated,
        Self::GroupDeleted,
        Self::GroupMemberAdded,
        Self::GroupMemberRemoved,
        Self::OrganizationCreated,
        Self::OrganizationEnabledChanged,
        Self::OrganizationDeleted,
        Self::OrganizationMemberSet,
        Self::OrganizationMemberRemoved,
        Self::OrganizationInvited,
        Self::OrganizationInvitationAccepted,
        Self::OrganizationInvitationRevoked,
        Self::GroupRoleGranted,
        Self::GroupRoleRevoked,
        Self::ClientRegistered,
        Self::ClientUpdated,
        Self::ClientDeleted,
        Self::ClientSecretRotated,
        Self::ConsentGranted,
        Self::ConsentRevoked,
        Self::TokenIssued,
        Self::TokenRevoked,
        Self::RefreshTokenReuseDetected,
        Self::SigningKeyRotated,
    ];

    /// The stable name stored in the database and shown in the console.
    ///
    /// Stored rather than derived from the variant name, so renaming the
    /// variant does not silently orphan every row already written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginSucceeded => "login.succeeded",
            Self::LoginFailed => "login.failed",
            Self::LoginLockedOut => "login.locked_out",
            Self::SecondFactorRequired => "mfa.required",
            Self::SecondFactorSucceeded => "mfa.succeeded",
            Self::SecondFactorFailed => "mfa.failed",
            Self::LoggedOut => "session.logged_out",
            Self::PasswordResetRequested => "recovery.reset_requested",
            Self::PasswordResetCompleted => "recovery.reset_completed",
            Self::EmailVerified => "recovery.email_verified",
            Self::TotpEnrolled => "mfa.totp_enrolled",
            Self::TotpRemoved => "mfa.totp_removed",
            Self::RecoveryCodesGenerated => "mfa.recovery_codes_generated",
            Self::RecoveryCodeUsed => "mfa.recovery_code_used",
            Self::PasskeyRegistered => "mfa.passkey_registered",
            Self::PasskeyRemoved => "mfa.passkey_removed",
            Self::UserCreated => "user.created",
            Self::UserUpdated => "user.updated",
            Self::UserDeleted => "user.deleted",
            Self::RoleCreated => "role.created",
            Self::RoleUpdated => "role.updated",
            Self::RoleDeleted => "role.deleted",
            Self::RoleGranted => "role.granted",
            Self::RoleRevoked => "role.revoked",
            Self::RealmCreated => "realm.created",
            Self::GroupCreated => "group.created",
            Self::GroupUpdated => "group.updated",
            Self::GroupDeleted => "group.deleted",
            Self::GroupMemberAdded => "group.member_added",
            Self::GroupMemberRemoved => "group.member_removed",
            Self::OrganizationCreated => "organization.created",
            Self::OrganizationEnabledChanged => "organization.enabled_changed",
            Self::OrganizationDeleted => "organization.deleted",
            Self::OrganizationMemberSet => "organization.member_set",
            Self::OrganizationMemberRemoved => "organization.member_removed",
            Self::OrganizationInvited => "organization.invited",
            Self::OrganizationInvitationAccepted => "organization.invitation_accepted",
            Self::OrganizationInvitationRevoked => "organization.invitation_revoked",
            Self::GroupRoleGranted => "group.role_granted",
            Self::GroupRoleRevoked => "group.role_revoked",
            Self::ClientRegistered => "client.registered",
            Self::ClientUpdated => "client.updated",
            Self::ClientDeleted => "client.deleted",
            Self::ClientSecretRotated => "client.secret_rotated",
            Self::ConsentGranted => "consent.granted",
            Self::ConsentRevoked => "consent.revoked",
            Self::TokenIssued => "token.issued",
            Self::TokenRevoked => "token.revoked",
            Self::RefreshTokenReuseDetected => "token.refresh_reuse_detected",
            Self::SigningKeyRotated => "keyring.rotated",
        }
    }

    /// Which part of the system this belongs to.
    #[must_use]
    pub const fn category(self) -> Category {
        match self {
            Self::LoginSucceeded | Self::LoginFailed | Self::LoginLockedOut | Self::LoggedOut => {
                Category::Authentication
            }
            Self::PasswordResetRequested | Self::PasswordResetCompleted | Self::EmailVerified => {
                Category::Recovery
            }
            Self::SecondFactorRequired
            | Self::SecondFactorSucceeded
            | Self::SecondFactorFailed
            | Self::TotpEnrolled
            | Self::TotpRemoved
            | Self::RecoveryCodesGenerated
            | Self::RecoveryCodeUsed
            | Self::PasskeyRegistered
            | Self::PasskeyRemoved => Category::MultiFactor,
            Self::UserCreated
            | Self::UserUpdated
            | Self::UserDeleted
            | Self::RoleCreated
            | Self::RoleUpdated
            | Self::RoleDeleted
            | Self::RoleGranted
            | Self::RoleRevoked
            | Self::RealmCreated
            | Self::GroupCreated
            | Self::GroupUpdated
            | Self::GroupDeleted
            | Self::GroupMemberAdded
            | Self::GroupMemberRemoved
            | Self::OrganizationCreated
            | Self::OrganizationEnabledChanged
            | Self::OrganizationDeleted
            | Self::OrganizationMemberSet
            | Self::OrganizationMemberRemoved
            | Self::OrganizationInvited
            | Self::OrganizationInvitationAccepted
            | Self::OrganizationInvitationRevoked
            | Self::GroupRoleGranted
            | Self::GroupRoleRevoked => Category::Directory,
            Self::ClientRegistered
            | Self::ClientUpdated
            | Self::ClientDeleted
            | Self::ClientSecretRotated
            | Self::ConsentGranted
            | Self::ConsentRevoked
            | Self::TokenIssued
            | Self::TokenRevoked
            | Self::RefreshTokenReuseDetected
            | Self::SigningKeyRotated => Category::Oauth,
        }
    }

    /// Whether this action is, on its own, evidence of an attack.
    ///
    /// Not "did it fail" — a mistyped password is a daily event. These are the
    /// ones where the *success* of the mechanism is the bad news: a lockout
    /// fired, a spent refresh token came back. The console surfaces them, and
    /// they are the reason the log is worth keeping.
    #[must_use]
    pub const fn is_security_signal(self) -> bool {
        matches!(
            self,
            Self::LoginLockedOut | Self::SecondFactorFailed | Self::RefreshTokenReuseDetected
        )
    }

    /// A one-line description, for the console.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::LoginSucceeded => "Signed in with a password",
            Self::LoginFailed => "Password refused",
            Self::LoginLockedOut => "Refused: too many recent failures",
            Self::SecondFactorRequired => "Password accepted; second factor requested",
            Self::SecondFactorSucceeded => "Second factor accepted",
            Self::SecondFactorFailed => "Second factor refused",
            Self::LoggedOut => "Signed out",
            Self::PasswordResetRequested => "Password reset requested",
            Self::PasswordResetCompleted => "Password reset completed",
            Self::EmailVerified => "Email address verified",
            Self::TotpEnrolled => "Authenticator enrolled",
            Self::TotpRemoved => "Authenticator removed",
            Self::RecoveryCodesGenerated => "Recovery codes issued",
            Self::RecoveryCodeUsed => "Recovery code used to sign in",
            Self::PasskeyRegistered => "Passkey registered",
            Self::PasskeyRemoved => "Passkey removed",
            Self::UserCreated => "User created",
            Self::UserUpdated => "User changed",
            Self::UserDeleted => "User deleted",
            Self::RoleCreated => "Role created",
            Self::RoleUpdated => "Role permissions replaced",
            Self::RoleDeleted => "Role deleted",
            Self::RoleGranted => "Role granted",
            Self::RoleRevoked => "Role revoked",
            Self::RealmCreated => "Realm created",
            Self::GroupCreated => "Group created",
            Self::GroupUpdated => "Group moved or renamed",
            Self::GroupDeleted => "Group deleted, with its subtree",
            Self::GroupMemberAdded => "User added to a group",
            Self::GroupMemberRemoved => "User removed from a group",
            Self::OrganizationCreated => "Organisation created",
            Self::OrganizationEnabledChanged => "Organisation suspended or restored",
            Self::OrganizationDeleted => "Organisation deleted",
            Self::OrganizationMemberSet => "Organisation membership set",
            Self::OrganizationMemberRemoved => "Removed from an organisation",
            Self::OrganizationInvited => "Invited to an organisation",
            Self::OrganizationInvitationAccepted => "Organisation invitation accepted",
            Self::OrganizationInvitationRevoked => "Organisation invitation withdrawn",
            Self::GroupRoleGranted => "Role granted to a group",
            Self::GroupRoleRevoked => "Role revoked from a group",
            Self::ClientRegistered => "OAuth client registered",
            Self::ClientUpdated => "OAuth client changed",
            Self::ClientDeleted => "OAuth client deleted",
            Self::ClientSecretRotated => "OAuth client secret rotated",
            Self::ConsentGranted => "Consent granted to a client",
            Self::ConsentRevoked => "Consent withdrawn from a client",
            Self::TokenIssued => "Tokens issued",
            Self::TokenRevoked => "Token revoked",
            Self::RefreshTokenReuseDetected => "Spent refresh token replayed; family revoked",
            Self::SigningKeyRotated => "Signing key rotated",
        }
    }
}

impl Serialize for Action {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = <std::borrow::Cow<'_, str>>::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when an action name from the database matches nothing known.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown audit action: {0}")]
pub struct UnknownAction(pub String);

impl FromStr for Action {
    type Err = UnknownAction;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|action| action.as_str() == value)
            .ok_or_else(|| UnknownAction(value.to_owned()))
    }
}

/// Whether the thing being recorded worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It happened.
    Success,
    /// It was refused.
    Failure,
}

impl Outcome {
    /// The stable name stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A recorded event, as the console and the API see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Stable identifier.
    pub id: uuid::Uuid,
    /// Realm the event belongs to.
    pub realm_id: RealmId,
    /// What happened.
    pub action: Action,
    /// Whether it worked.
    pub outcome: Outcome,
    /// Who did it, if a known user did.
    pub actor_id: Option<UserId>,
    /// Their username **as it was at the time**.
    ///
    /// Stored rather than joined. An audit record has to outlive the account it
    /// names, and a foreign key that nulls on delete answers "somebody" — which
    /// is exactly the question the record exists to answer.
    pub actor_name: Option<String>,
    /// What kind of thing it was done to, if anything.
    pub target_type: Option<String>,
    /// Which one, as a display string.
    pub target: Option<String>,
    /// Where the request came from.
    pub ip_address: Option<String>,
    /// What client made it.
    pub user_agent: Option<String>,
    /// When, RFC 3339.
    pub occurred_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_action_round_trips_through_its_name() {
        for action in Action::ALL {
            assert_eq!(action.as_str().parse(), Ok(*action));
        }
    }

    #[test]
    fn action_names_are_unique() {
        let names: HashSet<_> = Action::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(
            names.len(),
            Action::ALL.len(),
            "two actions share a stored name, so one cannot be queried for",
        );
    }

    #[test]
    fn an_unknown_name_is_an_error_not_a_default() {
        // Mapping an unrecognised row onto some default action would put a
        // wrong answer in an audit trail, which is worse than no answer.
        assert!("login.maybe".parse::<Action>().is_err());
        assert!("".parse::<Action>().is_err());
    }

    #[test]
    fn every_action_has_a_description() {
        for action in Action::ALL {
            assert!(!action.description().is_empty(), "{action}");
        }
    }

    #[test]
    fn names_are_namespaced_and_lowercase() {
        // The prefix is what makes `action LIKE 'mfa.%'` a usable query.
        for action in Action::ALL {
            let name = action.as_str();
            assert!(name.contains('.'), "{name} has no namespace");
            assert_eq!(name, name.to_lowercase(), "{name}");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_'),
                "{name}",
            );
        }
    }

    #[test]
    fn the_all_list_is_actually_complete() {
        // A variant added without being listed is invisible to the console's
        // filter and to anything enumerating what can be recorded. There is no
        // reflection to check this with, so the guard is that every listed
        // action is distinct and the count is asserted here — update both
        // together, deliberately.
        assert_eq!(Action::ALL.len(), 50);
        let unique: HashSet<_> = Action::ALL.iter().collect();
        assert_eq!(unique.len(), Action::ALL.len(), "a duplicate in ALL");
    }

    #[test]
    fn security_signals_are_the_ones_worth_waking_up_for() {
        // Not simply "everything that failed": a mistyped password is a daily
        // event, and treating it as a signal is how a log stops being read.
        assert!(Action::LoginLockedOut.is_security_signal());
        assert!(Action::RefreshTokenReuseDetected.is_security_signal());
        assert!(!Action::LoginFailed.is_security_signal());
        assert!(!Action::LoginSucceeded.is_security_signal());
        // Suspending an organisation cuts off every one of its members, which
        // is dramatic — and entirely routine. An administrator doing their job
        // is not an attack, and marking it red is how the red stops meaning
        // anything.
        assert!(!Action::OrganizationEnabledChanged.is_security_signal());
    }

    #[test]
    fn every_category_has_at_least_one_action() {
        for category in [
            Category::Authentication,
            Category::Recovery,
            Category::MultiFactor,
            Category::Directory,
            Category::Oauth,
        ] {
            assert!(
                Action::ALL.iter().any(|a| a.category() == category),
                "{category:?} has no actions",
            );
        }
    }

    #[test]
    fn the_wire_name_is_the_stored_name_and_round_trips() {
        // One name. A derived `rename_all` gave `login_succeeded` on the wire
        // while the database, `FromStr`, and the REST DTO all said
        // `login.succeeded` — two spellings for one thing, and only one of them
        // parsed back.
        for action in Action::ALL {
            let json = serde_json::to_string(action).unwrap();
            assert_eq!(json, format!("\"{}\"", action.as_str()));
            assert_eq!(
                serde_json::from_str::<Action>(&json).unwrap(),
                *action,
                "{action} does not survive a round trip",
            );
        }

        assert_eq!(
            serde_json::to_string(&Outcome::Failure).unwrap(),
            "\"failure\"",
        );
    }

    #[test]
    fn an_unknown_action_name_fails_to_deserialise() {
        // Rather than becoming some default, which would put a wrong answer in
        // an audit trail.
        assert!(serde_json::from_str::<Action>("\"login.maybe\"").is_err());
    }
}
