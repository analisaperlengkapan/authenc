//! Typed identifiers.
//!
//! Every aggregate gets its own id type so a `RealmId` can never be passed
//! where a `UserId` is expected. The previous codebase threaded bare `Uuid`
//! and `String` everywhere, which is how `realm_id` and `realm_name` ended up
//! being used interchangeably at different layers.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generate a fresh random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map(Self)
            }
        }
    };
}

typed_id!(
    /// Identifies a realm (an isolated tenant).
    RealmId
);
typed_id!(
    /// Identifies a user within a realm.
    UserId
);
typed_id!(
    /// Identifies a role within a realm.
    RoleId
);
typed_id!(
    /// Identifies a permission within a realm.
    PermissionId
);
typed_id!(
    /// Identifies an authenticated session.
    SessionId
);
typed_id!(
    /// Identifies a registered passkey.
    PasskeyId
);
typed_id!(
    /// Identifies a group within a realm.
    GroupId
);
typed_id!(
    /// Identifies an organisation within a realm.
    OrganizationId
);
typed_id!(
    /// Identifies an outstanding invitation to an organisation.
    InvitationId
);
typed_id!(
    /// Identifies a configured upstream identity provider.
    IdentityProviderId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_roundtrip_through_strings() {
        let id = UserId::new();
        assert_eq!(id.to_string().parse::<UserId>().unwrap(), id);
    }

    #[test]
    fn ids_serialise_transparently() {
        let id = RealmId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
    }
}
