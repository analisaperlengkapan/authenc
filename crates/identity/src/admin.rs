//! Administrative operations on realms, users, and roles.
//!
//! Every function here takes an [`Actor`] and calls
//! [`Actor::require`](authenc_contract::model::Actor::require) before touching
//! anything. That is the whole authorisation model: there is no middleware
//! deciding access by URL prefix, so a function cannot lose its check by being
//! mounted on the wrong router.
//!
//! Realm scoping is enforced on top of permissions. Holding `user:write` lets
//! an actor manage users **in their own realm**; it is not a licence to reach
//! into another tenant.

use authenc_contract::{
    AppError, Permission, RealmId, Result, RoleId, UserId,
    model::{Actor, Realm, Role, User},
};

use crate::{db::Db, password::PasswordHasher, role, session, user};

/// Reject an actor reaching outside its own realm.
///
/// Checked separately from the permission, and always after it, because the
/// two failures mean different things: one is "you may not do this", the other
/// is "this is not yours".
fn same_realm(actor: &Actor, realm_id: RealmId) -> Result<()> {
    if actor.realm_id == realm_id {
        Ok(())
    } else {
        // Deliberately `NotFound`, not `Forbidden`: confirming that a resource
        // exists in another tenant is itself a disclosure.
        Err(AppError::NotFound("realm"))
    }
}

/// List the users in a realm.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `user:read`, [`AppError::NotFound`] for
/// another realm, or an internal error if the query fails.
pub async fn list_users(
    db: &Db,
    actor: &Actor,
    realm_id: RealmId,
    limit: i64,
    offset: i64,
) -> Result<Vec<User>> {
    actor.require(Permission::UserRead)?;
    same_realm(actor, realm_id)?;

    // Bounded regardless of what the caller asks for: an unbounded list is a
    // denial-of-service waiting for the first large tenant.
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);

    let rows = sqlx::query!(
        r#"
        SELECT id, realm_id, username, email, email_verified,
               first_name, last_name, enabled, created_at
        FROM users
        WHERE realm_id = $1
        ORDER BY lower(username)
        LIMIT $2 OFFSET $3
        "#,
        realm_id.0,
        limit,
        offset,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing users", e))?;

    Ok(rows
        .into_iter()
        .map(|row| User {
            id: UserId(row.id),
            realm_id: RealmId(row.realm_id),
            username: row.username,
            email: row.email,
            email_verified: row.email_verified,
            first_name: row.first_name,
            last_name: row.last_name,
            enabled: row.enabled,
            created_at: row.created_at,
        })
        .collect())
}

/// Count the users in a realm, for pagination.
///
/// # Errors
///
/// As [`list_users`].
pub async fn count_users(db: &Db, actor: &Actor, realm_id: RealmId) -> Result<i64> {
    actor.require(Permission::UserRead)?;
    same_realm(actor, realm_id)?;

    sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM users WHERE realm_id = $1"#,
        realm_id.0,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting users", e))
}

/// Create a user.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `user:write`, a field error on invalid
/// input, [`AppError::Conflict`] on a duplicate, or an internal error.
pub async fn create_user(
    db: &Db,
    actor: &Actor,
    hasher: &PasswordHasher,
    new: user::NewUser<'_>,
) -> Result<User> {
    actor.require(Permission::UserWrite)?;
    same_realm(actor, new.realm_id)?;
    user::create(db, hasher, new).await
}

/// Enable or disable a user.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `user:write`, [`AppError::NotFound`] if the
/// user is not in the actor's realm, or an internal error.
pub async fn set_user_enabled(
    db: &Db,
    actor: &Actor,
    user_id: UserId,
    enabled: bool,
) -> Result<User> {
    actor.require(Permission::UserWrite)?;

    let target = user::by_id(db, user_id).await?;
    same_realm(actor, target.realm_id)?;

    if !enabled && target.id == actor.user_id {
        // Locking yourself out is never what was meant, and recovering needs
        // another administrator or database access.
        return Err(AppError::validation("you cannot disable your own account"));
    }

    sqlx::query!(
        "UPDATE users SET enabled = $2, updated_at = now() WHERE id = $1",
        user_id.0,
        enabled,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("updating user", e))?;

    if !enabled {
        // A disabled account must stop working now, not when its session
        // happens to expire.
        session::revoke_all_for_user(db, user_id).await?;
    }

    user::by_id(db, user_id).await
}

/// Delete a user.
///
/// # Errors
///
/// As [`set_user_enabled`], plus a validation error if the actor is the target.
pub async fn delete_user(db: &Db, actor: &Actor, user_id: UserId) -> Result<()> {
    actor.require(Permission::UserWrite)?;

    let target = user::by_id(db, user_id).await?;
    same_realm(actor, target.realm_id)?;

    if target.id == actor.user_id {
        return Err(AppError::validation("you cannot delete your own account"));
    }

    sqlx::query!("DELETE FROM users WHERE id = $1", user_id.0)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("deleting user", e))?;

    Ok(())
}

/// List the roles in a realm.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `role:read`, or an internal error.
pub async fn list_roles(db: &Db, actor: &Actor, realm_id: RealmId) -> Result<Vec<Role>> {
    actor.require(Permission::RoleRead)?;
    same_realm(actor, realm_id)?;

    let rows = sqlx::query!(
        "SELECT id, realm_id, name, description FROM roles WHERE realm_id = $1 ORDER BY name",
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing roles", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Role {
            id: RoleId(row.id),
            realm_id: RealmId(row.realm_id),
            name: row.name,
            description: row.description,
        })
        .collect())
}

/// Create a role.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `role:write`, or an internal error.
pub async fn create_role(
    db: &Db,
    actor: &Actor,
    realm_id: RealmId,
    name: &str,
    description: Option<&str>,
) -> Result<Role> {
    actor.require(Permission::RoleWrite)?;
    same_realm(actor, realm_id)?;
    role::ensure(db, realm_id, name, description).await
}

/// Grant a role to a user.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `role:write`, [`AppError::NotFound`] if
/// either side is outside the actor's realm, or an internal error.
pub async fn grant_role(db: &Db, actor: &Actor, user_id: UserId, role_id: RoleId) -> Result<()> {
    actor.require(Permission::RoleWrite)?;

    let target = user::by_id(db, user_id).await?;
    same_realm(actor, target.realm_id)?;
    same_realm(actor, role_realm(db, role_id).await?)?;

    role::grant(db, user_id, role_id).await
}

/// Revoke a role from a user.
///
/// # Errors
///
/// As [`grant_role`].
pub async fn revoke_role(db: &Db, actor: &Actor, user_id: UserId, role_id: RoleId) -> Result<()> {
    actor.require(Permission::RoleWrite)?;

    let target = user::by_id(db, user_id).await?;
    same_realm(actor, target.realm_id)?;
    same_realm(actor, role_realm(db, role_id).await?)?;

    role::revoke(db, user_id, role_id).await
}

/// The realm a role belongs to.
async fn role_realm(db: &Db, role_id: RoleId) -> Result<RealmId> {
    sqlx::query_scalar!("SELECT realm_id FROM roles WHERE id = $1", role_id.0)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::internal_from("looking up role realm", e))?
        .map(RealmId)
        .ok_or(AppError::NotFound("role"))
}

/// The realm the actor belongs to.
///
/// # Errors
///
/// [`AppError::Forbidden`] without `realm:read`, or an internal error.
pub async fn own_realm(db: &Db, actor: &Actor) -> Result<Realm> {
    actor.require(Permission::RealmRead)?;

    let row = sqlx::query!(
        "SELECT id, name, display_name, enabled, created_at FROM realms WHERE id = $1",
        actor.realm_id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading realm", e))?
    .ok_or(AppError::NotFound("realm"))?;

    Ok(Realm {
        id: RealmId(row.id),
        name: row.name,
        display_name: row.display_name,
        enabled: row.enabled,
        created_at: row.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{realm, user::NewUser};

    const PASSWORD: &str = "correct horse battery staple";

    /// An actor in `realm_id` holding exactly `permissions`.
    fn actor(realm_id: RealmId, user_id: UserId, permissions: &[Permission]) -> Actor {
        Actor {
            user_id,
            realm_id,
            username: "operator".into(),
            roles: vec![],
            permissions: permissions.to_vec(),
        }
    }

    async fn a_realm_with_a_user(db: &Db, slug: &str) -> (RealmId, UserId) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, slug, slug).await.unwrap();
        let user = user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: &format!("alice@{slug}.example"),
                password: PASSWORD,
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();
        (realm.id, user.id)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn listing_users_needs_the_read_permission(db: Db) {
        let (realm_id, user_id) = a_realm_with_a_user(&db, "acme").await;

        let denied = actor(realm_id, user_id, &[]);
        assert_eq!(
            list_users(&db, &denied, realm_id, 50, 0)
                .await
                .unwrap_err()
                .status(),
            403,
        );

        let allowed = actor(realm_id, user_id, &[Permission::UserRead]);
        assert_eq!(
            list_users(&db, &allowed, realm_id, 50, 0)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn write_implies_read_here_too(db: Db) {
        let (realm_id, user_id) = a_realm_with_a_user(&db, "acme").await;
        let writer = actor(realm_id, user_id, &[Permission::UserWrite]);

        assert!(list_users(&db, &writer, realm_id, 50, 0).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_actor_cannot_read_another_realm(db: Db) {
        let (mine, me) = a_realm_with_a_user(&db, "acme").await;
        let (theirs, _) = a_realm_with_a_user(&db, "other").await;

        let me = actor(mine, me, &[Permission::UserRead, Permission::UserWrite]);

        // NotFound, not Forbidden: confirming the tenant exists is itself a
        // disclosure.
        assert_eq!(
            list_users(&db, &me, theirs, 50, 0)
                .await
                .unwrap_err()
                .status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_actor_cannot_disable_a_user_in_another_realm(db: Db) {
        let (mine, me) = a_realm_with_a_user(&db, "acme").await;
        let (_, theirs) = a_realm_with_a_user(&db, "other").await;

        let me = actor(mine, me, &[Permission::UserWrite]);

        assert_eq!(
            set_user_enabled(&db, &me, theirs, false)
                .await
                .unwrap_err()
                .status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn disabling_a_user_ends_their_sessions_immediately(db: Db) {
        let hasher = PasswordHasher::new();
        let (realm_id, admin_id) = a_realm_with_a_user(&db, "acme").await;
        let victim = user::create(
            &db,
            &hasher,
            NewUser {
                realm_id,
                username: "bob",
                email: "bob@acme.example",
                password: PASSWORD,
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();

        let live = session::create(&db, victim.id, realm_id, session::Origin::default())
            .await
            .unwrap();

        let admin = actor(realm_id, admin_id, &[Permission::UserWrite]);
        set_user_enabled(&db, &admin, victim.id, false)
            .await
            .unwrap();

        assert!(
            session::lookup(&db, &live.token).await.unwrap().is_none(),
            "a disabled account must stop working now, not at session expiry",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_actor_cannot_disable_or_delete_itself(db: Db) {
        let (realm_id, me) = a_realm_with_a_user(&db, "acme").await;
        let actor = actor(realm_id, me, &[Permission::UserWrite]);

        assert_eq!(
            set_user_enabled(&db, &actor, me, false)
                .await
                .unwrap_err()
                .status(),
            400,
        );
        assert_eq!(
            delete_user(&db, &actor, me).await.unwrap_err().status(),
            400
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn listing_is_bounded_however_much_the_caller_asks_for(db: Db) {
        let hasher = PasswordHasher::new();
        let (realm_id, user_id) = a_realm_with_a_user(&db, "acme").await;
        for n in 0..5 {
            user::create(
                &db,
                &hasher,
                NewUser {
                    realm_id,
                    username: &format!("user{n}"),
                    email: &format!("user{n}@acme.example"),
                    password: PASSWORD,
                    first_name: None,
                    last_name: None,
                },
            )
            .await
            .unwrap();
        }

        let reader = actor(realm_id, user_id, &[Permission::UserRead]);

        // A caller asking for a million rows gets the cap, not a table scan.
        assert_eq!(
            list_users(&db, &reader, realm_id, 1_000_000, 0)
                .await
                .unwrap()
                .len(),
            6
        );
        // A caller asking for nonsense gets at least one row rather than zero.
        assert_eq!(
            list_users(&db, &reader, realm_id, 0, -5)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn granting_a_role_from_another_realm_is_refused(db: Db) {
        let (mine, me) = a_realm_with_a_user(&db, "acme").await;
        let (theirs, _) = a_realm_with_a_user(&db, "other").await;

        let foreign_role = role::ensure(&db, theirs, "admin", None).await.unwrap();
        let me_actor = actor(mine, me, &[Permission::RoleWrite]);

        assert_eq!(
            grant_role(&db, &me_actor, me, foreign_role.id)
                .await
                .unwrap_err()
                .status(),
            404,
            "a role must not cross a tenant boundary",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn roles_can_be_granted_and_revoked_within_a_realm(db: Db) {
        let (realm_id, me) = a_realm_with_a_user(&db, "acme").await;
        let admin = actor(realm_id, me, &[Permission::RoleWrite]);

        let role = create_role(&db, &admin, realm_id, "auditor", Some("Read-only"))
            .await
            .unwrap();

        grant_role(&db, &admin, me, role.id).await.unwrap();
        assert_eq!(user::role_names(&db, me).await.unwrap(), vec!["auditor"]);

        revoke_role(&db, &admin, me, role.id).await.unwrap();
        assert!(user::role_names(&db, me).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn role_writes_need_the_role_permission_not_the_user_one(db: Db) {
        let (realm_id, me) = a_realm_with_a_user(&db, "acme").await;

        // Holding every user permission must not confer role management.
        let user_admin = actor(realm_id, me, &[Permission::UserWrite]);
        assert_eq!(
            create_role(&db, &user_admin, realm_id, "auditor", None)
                .await
                .unwrap_err()
                .status(),
            403,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn every_administrative_function_refuses_an_actor_with_no_permissions(db: Db) {
        let hasher = PasswordHasher::new();
        let (realm_id, me) = a_realm_with_a_user(&db, "acme").await;
        let nobody = actor(realm_id, me, &[]);
        let role = role::ensure(&db, realm_id, "auditor", None).await.unwrap();

        // One place to notice if a new function is added without a check.
        assert_eq!(
            list_users(&db, &nobody, realm_id, 10, 0)
                .await
                .unwrap_err()
                .status(),
            403
        );
        assert_eq!(
            count_users(&db, &nobody, realm_id)
                .await
                .unwrap_err()
                .status(),
            403
        );
        assert_eq!(
            list_roles(&db, &nobody, realm_id)
                .await
                .unwrap_err()
                .status(),
            403
        );
        assert_eq!(own_realm(&db, &nobody).await.unwrap_err().status(), 403);
        assert_eq!(
            create_role(&db, &nobody, realm_id, "x", None)
                .await
                .unwrap_err()
                .status(),
            403,
        );
        assert_eq!(
            grant_role(&db, &nobody, me, role.id)
                .await
                .unwrap_err()
                .status(),
            403
        );
        assert_eq!(
            revoke_role(&db, &nobody, me, role.id)
                .await
                .unwrap_err()
                .status(),
            403
        );
        assert_eq!(
            delete_user(&db, &nobody, me).await.unwrap_err().status(),
            403
        );
        assert_eq!(
            set_user_enabled(&db, &nobody, me, false)
                .await
                .unwrap_err()
                .status(),
            403,
        );
        assert_eq!(
            create_user(
                &db,
                &nobody,
                &hasher,
                NewUser {
                    realm_id,
                    username: "carol",
                    email: "carol@acme.example",
                    password: PASSWORD,
                    first_name: None,
                    last_name: None,
                },
            )
            .await
            .unwrap_err()
            .status(),
            403,
        );
    }
}
