//! Entities and DTOs that cross the wire.
//!
//! These are deliberately *not* the database rows. A row carries a password
//! hash and a lockout counter; the type that reaches a browser must not be able
//! to. Keeping them distinct is what makes it impossible to leak a credential
//! by adding a field to a query.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::id::{RealmId, RoleId, UserId};

/// An isolated tenant. Users, roles, and OAuth clients all live inside one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Realm {
    /// Stable identifier.
    pub id: RealmId,
    /// URL-safe slug; appears in the OIDC issuer URL.
    pub name: String,
    /// Human-facing name.
    pub display_name: String,
    /// Whether authentication against this realm is currently permitted.
    pub enabled: bool,
    /// When the realm was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A user, as seen by anything outside the identity crate.
///
/// There is no `password_hash` field, and there is no way to add one without
/// changing this type — which is the point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Stable identifier.
    pub id: UserId,
    /// Realm this user belongs to.
    pub realm_id: RealmId,
    /// Login name, unique within the realm.
    pub username: String,
    /// Email address, unique within the realm.
    pub email: String,
    /// Whether the email address has been proven.
    pub email_verified: bool,
    /// Given name, if provided.
    pub first_name: Option<String>,
    /// Family name, if provided.
    pub last_name: Option<String>,
    /// Whether the user may authenticate.
    pub enabled: bool,
    /// When the account was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl User {
    /// Best available human-readable name, falling back to the username.
    #[must_use]
    pub fn display_name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => format!("{first} {last}"),
            (Some(first), None) => first.clone(),
            (None, Some(last)) => last.clone(),
            (None, None) => self.username.clone(),
        }
    }
}

/// A named bundle of permissions inside a realm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Stable identifier.
    pub id: RoleId,
    /// Realm this role belongs to.
    pub realm_id: RealmId,
    /// Machine name, unique within the realm.
    pub name: String,
    /// What the role is for.
    pub description: Option<String>,
}

/// The authenticated principal behind a request.
///
/// Every use case takes one of these and decides for itself whether the actor
/// may proceed. Authorisation is not a middleware concern here: the previous
/// codebase gated on URL prefixes, which meant a route added to the wrong
/// router silently lost its access control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Who is acting.
    pub user_id: UserId,
    /// Which realm they authenticated against.
    pub realm_id: RealmId,
    /// Their login name, for audit records.
    pub username: String,
    /// Role names granted to them, resolved at authentication time.
    pub roles: Vec<String>,
}

impl Actor {
    /// Whether the actor holds the named role.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|held| held == role)
    }

    /// Whether the actor is a realm administrator.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.has_role(ROLE_ADMIN)
    }
}

/// Role granting full administrative access within a realm.
pub const ROLE_ADMIN: &str = "admin";

/// Credentials submitted by a login form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Realm slug to authenticate against.
    pub realm: String,
    /// Username or email.
    pub identifier: String,
    /// The submitted password.
    pub password: String,
}

/// What the browser learns after a successful login.
///
/// Note there is no token: the session lives in an `HttpOnly` cookie the
/// browser cannot read. The previous frontend kept a JWT in `localStorage`,
/// where any injected script could take it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    /// The now-authenticated user.
    pub user: User,
    /// Role names the session carries.
    pub roles: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RealmId;

    fn user(first: Option<&str>, last: Option<&str>) -> User {
        User {
            id: UserId::new(),
            realm_id: RealmId::new(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            email_verified: true,
            first_name: first.map(Into::into),
            last_name: last.map(Into::into),
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn display_name_prefers_full_name_then_falls_back() {
        assert_eq!(user(Some("Alice"), Some("Ng")).display_name(), "Alice Ng");
        assert_eq!(user(Some("Alice"), None).display_name(), "Alice");
        assert_eq!(user(None, Some("Ng")).display_name(), "Ng");
        assert_eq!(user(None, None).display_name(), "alice");
    }

    #[test]
    fn actor_role_checks() {
        let actor = Actor {
            user_id: UserId::new(),
            realm_id: RealmId::new(),
            username: "alice".into(),
            roles: vec!["admin".into(), "auditor".into()],
        };
        assert!(actor.is_admin());
        assert!(actor.has_role("auditor"));
        assert!(!actor.has_role("operator"));
    }

    #[test]
    fn user_dto_has_no_credential_fields() {
        // Serialising a user must never produce a hash-shaped field.
        let json = serde_json::to_string(&user(None, None)).unwrap();
        for forbidden in ["password", "hash", "secret", "totp"] {
            assert!(!json.contains(forbidden), "{forbidden} leaked into the DTO");
        }
    }
}
