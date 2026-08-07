//! Entities and DTOs that cross the wire.
//!
//! These are deliberately *not* the database rows. A row carries a password
//! hash and a lockout counter; the type that reaches a browser must not be able
//! to. Keeping them distinct is what makes it impossible to leak a credential
//! by adding a field to a query.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    error::{AppError, Result},
    id::{RealmId, RoleId, UserId},
    permission::Permission,
};

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
    /// Role names granted to them, resolved from the database.
    pub roles: Vec<String>,
    /// Permissions those roles carry, resolved from the database.
    ///
    /// Resolved at the point of use rather than carried in a token. The
    /// previous system minted tokens with `roles: None` and then checked
    /// `roles.contains("admin")`, so no token it issued could ever satisfy an
    /// admin check.
    pub permissions: Vec<Permission>,
}

impl Actor {
    /// Whether the actor holds the named role.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|held| held == role)
    }

    /// Whether the actor holds a permission, directly or by implication.
    #[must_use]
    pub fn can(&self, permission: Permission) -> bool {
        self.permissions
            .iter()
            .any(|&held| held == permission || held.implies() == Some(permission))
    }

    /// Require a permission.
    ///
    /// Every use case that changes or reveals something calls this first. The
    /// error is [`AppError::Forbidden`] — 403 — because the caller *is*
    /// authenticated; 401 would tell them to log in again, which will not
    /// help.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Forbidden`] if the actor lacks the permission.
    pub fn require(&self, permission: Permission) -> Result<()> {
        if self.can(permission) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
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
    /// Permissions the session carries.
    ///
    /// Sent so the console can hide actions it would only be refused for. It
    /// is a display hint, never the check — every server function and endpoint
    /// re-derives this from the database.
    pub permissions: Vec<Permission>,
}

impl LoginResponse {
    /// Whether this session holds a permission, by the same rule the server
    /// uses.
    ///
    /// Shared deliberately: if the console decided visibility with a different
    /// rule from the one that decides access, it would offer buttons that are
    /// then refused, or hide actions that would in fact have worked.
    #[must_use]
    pub fn can(&self, permission: Permission) -> bool {
        holds(&self.permissions, permission)
    }
}

/// The one permission rule: a permission is held directly, or implied by one
/// that is.
fn holds(held: &[Permission], wanted: Permission) -> bool {
    held.iter()
        .any(|&have| have == wanted || have.implies() == Some(wanted))
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
            permissions: vec![],
        };
        assert!(actor.has_role("admin"));
        assert!(actor.has_role("auditor"));
        assert!(!actor.has_role("operator"));
    }

    fn actor_with(permissions: Vec<Permission>) -> Actor {
        Actor {
            user_id: UserId::new(),
            realm_id: RealmId::new(),
            username: "alice".into(),
            roles: vec![],
            permissions,
        }
    }

    #[test]
    fn a_held_permission_is_allowed() {
        let actor = actor_with(vec![Permission::UserRead]);
        assert!(actor.can(Permission::UserRead));
        assert!(actor.require(Permission::UserRead).is_ok());
    }

    #[test]
    fn an_absent_permission_is_forbidden_not_unauthenticated() {
        // 403, not 401: the caller is authenticated, so telling them to log in
        // again would be misleading.
        let actor = actor_with(vec![Permission::UserRead]);
        assert!(!actor.can(Permission::UserWrite));
        assert_eq!(
            actor.require(Permission::UserWrite).unwrap_err().status(),
            403,
        );
    }

    #[test]
    fn write_carries_read_with_it() {
        let actor = actor_with(vec![Permission::UserWrite]);
        assert!(actor.can(Permission::UserRead), "write must imply read");
    }

    #[test]
    fn permissions_do_not_leak_across_resources() {
        let actor = actor_with(vec![Permission::UserWrite]);
        assert!(!actor.can(Permission::RealmRead));
        assert!(!actor.can(Permission::RoleWrite));
    }

    #[test]
    fn an_actor_with_nothing_can_do_nothing() {
        let actor = actor_with(vec![]);
        for permission in Permission::ALL {
            assert!(!actor.can(*permission), "{permission} should be denied");
        }
    }

    #[test]
    fn the_console_and_the_server_apply_the_same_rule() {
        // The hint the console renders must agree with the check that decides,
        // including the write-implies-read part.
        let response = LoginResponse {
            user: user(None, None),
            roles: vec![],
            permissions: vec![Permission::UserWrite],
        };
        let actor = actor_with(vec![Permission::UserWrite]);

        for permission in Permission::ALL {
            assert_eq!(
                response.can(*permission),
                actor.can(*permission),
                "disagreement on {permission}",
            );
        }
    }

    #[test]
    fn holding_a_role_named_admin_grants_nothing_by_itself() {
        // Permissions come from role_permissions rows, not from a magic name.
        // The old code branched on `roles.contains("admin")`, which meant the
        // string was the authorisation.
        let actor = Actor {
            roles: vec![ROLE_ADMIN.into()],
            ..actor_with(vec![])
        };
        assert!(!actor.can(Permission::UserRead));
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
