//! Roles and their assignment to users.

use authenc_contract::{AppError, RealmId, Result, RoleId, UserId, model::Role};

use crate::db::Db;

/// Create a role if it does not exist, and return it either way.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn ensure(
    db: &Db,
    realm_id: RealmId,
    name: &str,
    description: Option<&str>,
) -> Result<Role> {
    let row = sqlx::query!(
        r#"
        INSERT INTO roles (realm_id, name, description)
        VALUES ($1, $2, $3)
        ON CONFLICT (realm_id, name)
            DO UPDATE SET description = COALESCE(EXCLUDED.description, roles.description)
        RETURNING id, realm_id, name, description
        "#,
        realm_id.0,
        name,
        description,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("creating role", e))?;

    Ok(Role {
        id: RoleId(row.id),
        realm_id: RealmId(row.realm_id),
        name: row.name,
        description: row.description,
    })
}

/// Grant a role to a user. Granting a role twice is not an error.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn grant(db: &Db, user_id: UserId, role_id: RoleId) -> Result<()> {
    sqlx::query!(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        user_id.0,
        role_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("granting role", e))?;

    Ok(())
}

/// Revoke a role from a user. Revoking a role they do not hold is not an error.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn revoke(db: &Db, user_id: UserId, role_id: RoleId) -> Result<()> {
    sqlx::query!(
        "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
        user_id.0,
        role_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking role", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        password::PasswordHasher,
        realm,
        user::{self, NewUser},
    };

    async fn fixture(db: &Db) -> (RealmId, UserId) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let user = user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: "alice@example.com",
                password: "correct horse battery staple",
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();
        (realm.id, user.id)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn ensure_is_idempotent(db: Db) {
        let (realm_id, _) = fixture(&db).await;

        let first = ensure(&db, realm_id, "admin", Some("Full access"))
            .await
            .unwrap();
        let second = ensure(&db, realm_id, "admin", None).await.unwrap();

        assert_eq!(first.id, second.id, "must reuse, not duplicate");
        assert_eq!(
            second.description.as_deref(),
            Some("Full access"),
            "a later call without a description must not erase the existing one",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn granting_a_role_makes_it_visible_on_the_user(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "admin", None).await.unwrap();

        assert!(user::role_names(&db, user_id).await.unwrap().is_empty());

        grant(&db, user_id, role.id).await.unwrap();
        assert_eq!(
            user::role_names(&db, user_id).await.unwrap(),
            vec!["admin".to_owned()],
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn granting_twice_is_not_an_error(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "admin", None).await.unwrap();

        grant(&db, user_id, role.id).await.unwrap();
        grant(&db, user_id, role.id).await.unwrap();

        assert_eq!(user::role_names(&db, user_id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_removes_the_role(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "admin", None).await.unwrap();

        grant(&db, user_id, role.id).await.unwrap();
        revoke(&db, user_id, role.id).await.unwrap();

        assert!(user::role_names(&db, user_id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn roles_are_scoped_to_their_realm(db: Db) {
        let (realm_id, _) = fixture(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap();

        let here = ensure(&db, realm_id, "admin", None).await.unwrap();
        let there = ensure(&db, other.id, "admin", None).await.unwrap();

        assert_ne!(
            here.id, there.id,
            "the same role name in two realms must be two roles",
        );
    }
}
