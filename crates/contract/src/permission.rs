//! Permissions, and the check that enforces them.
//!
//! Authorisation is decided by asking an [`Actor`](crate::model::Actor)
//! whether it holds a permission, at the point the work is about to happen.
//! It is deliberately *not* a middleware that matches URL prefixes: in the
//! previous codebase that is exactly what it was, so a route registered on the
//! wrong router silently lost its access control, and about thirty-eight
//! endpoints expected an extension that the middleware they were never wrapped
//! in would have inserted.
//!
//! The permission is an enum rather than a string, so a typo is a compile
//! error and `Permission::ALL` is the complete, reviewable list of everything
//! this system can authorise.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Something an actor may be allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// View realms.
    RealmRead,
    /// Create, change, and delete realms.
    RealmWrite,
    /// View users.
    UserRead,
    /// Create, change, and delete users.
    UserWrite,
    /// View roles and their grants.
    RoleRead,
    /// Create and delete roles, and grant or revoke them.
    RoleWrite,
}

impl Permission {
    /// Every permission. The complete list of what can be authorised.
    pub const ALL: &'static [Self] = &[
        Self::RealmRead,
        Self::RealmWrite,
        Self::UserRead,
        Self::UserWrite,
        Self::RoleRead,
        Self::RoleWrite,
    ];

    /// The stable name stored in the database and shown in the console.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealmRead => "realm:read",
            Self::RealmWrite => "realm:write",
            Self::UserRead => "user:read",
            Self::UserWrite => "user:write",
            Self::RoleRead => "role:read",
            Self::RoleWrite => "role:write",
        }
    }

    /// A one-line description, for the console and the OpenAPI document.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::RealmRead => "View realms",
            Self::RealmWrite => "Create, change, and delete realms",
            Self::UserRead => "View users",
            Self::UserWrite => "Create, change, and delete users",
            Self::RoleRead => "View roles and their grants",
            Self::RoleWrite => "Create and delete roles, and grant or revoke them",
        }
    }

    /// The read permission implied by this one.
    ///
    /// Being allowed to change something implies being allowed to see it;
    /// granting `user:write` without `user:read` produces a console that can
    /// edit a list it cannot display.
    #[must_use]
    pub const fn implies(self) -> Option<Self> {
        match self {
            Self::RealmWrite => Some(Self::RealmRead),
            Self::UserWrite => Some(Self::UserRead),
            Self::RoleWrite => Some(Self::RoleRead),
            _ => None,
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when a permission name from the database matches nothing known.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown permission: {0}")]
pub struct UnknownPermission(pub String);

impl FromStr for Permission {
    type Err = UnknownPermission;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|permission| permission.as_str() == value)
            .ok_or_else(|| UnknownPermission(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_permission_round_trips_through_its_name() {
        for permission in Permission::ALL {
            assert_eq!(permission.as_str().parse(), Ok(*permission));
        }
    }

    #[test]
    fn permission_names_are_unique() {
        let mut names: Vec<_> = Permission::ALL.iter().map(|p| p.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two permissions share a name");
    }

    #[test]
    fn an_unknown_name_is_an_error_not_a_default() {
        // Silently mapping an unknown name to some permission is how a renamed
        // row turns into either a lockout or an escalation.
        assert!("user:destroy".parse::<Permission>().is_err());
        assert!("".parse::<Permission>().is_err());
    }

    #[test]
    fn write_implies_read_and_read_implies_nothing() {
        assert_eq!(Permission::UserWrite.implies(), Some(Permission::UserRead));
        assert_eq!(Permission::RoleWrite.implies(), Some(Permission::RoleRead));
        assert_eq!(
            Permission::RealmWrite.implies(),
            Some(Permission::RealmRead)
        );
        assert_eq!(Permission::UserRead.implies(), None);
    }

    #[test]
    fn every_permission_has_a_description() {
        for permission in Permission::ALL {
            assert!(!permission.description().is_empty(), "{permission}");
        }
    }
}
