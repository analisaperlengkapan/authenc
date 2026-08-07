//! Users and their password credentials.

use authenc_contract::{AppError, RealmId, Result, UserId, model::User, validate};

use crate::{db::Db, password::PasswordHasher};

/// What a caller must supply to create a user.
#[derive(Debug, Clone)]
pub struct NewUser<'a> {
    /// Realm the user belongs to.
    pub realm_id: RealmId,
    /// Login name, unique within the realm.
    pub username: &'a str,
    /// Email address, unique within the realm.
    pub email: &'a str,
    /// Initial password. Validated against policy before hashing.
    pub password: &'a str,
    /// Given name, if known.
    pub first_name: Option<&'a str>,
    /// Family name, if known.
    pub last_name: Option<&'a str>,
}

/// A user row together with the credential needed to authenticate them.
///
/// Deliberately **not** [`User`]: this type never leaves the crate, which is
/// what stops a password hash from reaching a DTO by accident.
pub(crate) struct Credentialed {
    pub(crate) user: User,
    pub(crate) phc: Option<String>,
}

/// Create a user with a password.
///
/// # Errors
///
/// Returns a field error if the username, email, or password fails validation,
/// [`AppError::Conflict`] if the username or email is taken in that realm, or
/// an internal error if the insert fails.
pub async fn create(db: &Db, hasher: &PasswordHasher, new: NewUser<'_>) -> Result<User> {
    validate::username(new.username)?;
    validate::email(new.email)?;
    validate::password(new.password)?;

    let phc = hasher.hash(new.password)?;

    // One transaction: a user without a credential could never log in and
    // would silently occupy their username.
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("beginning transaction", e))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO users (realm_id, username, email, first_name, last_name)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, realm_id, username, email, email_verified,
                  first_name, last_name, enabled, created_at
        "#,
        new.realm_id.0,
        new.username,
        new.email,
        new.first_name,
        new.last_name,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_error) if db_error.is_unique_violation() => {
            AppError::conflict("that username or email is already taken in this realm")
        }
        _ => AppError::internal_from("creating user", e),
    })?;

    sqlx::query!(
        "INSERT INTO user_passwords (user_id, phc) VALUES ($1, $2)",
        row.id,
        phc,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("storing password", e))?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("committing transaction", e))?;

    Ok(User {
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
}

/// Find a user by id.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if there is no such user.
pub async fn by_id(db: &Db, id: UserId) -> Result<User> {
    let row = sqlx::query!(
        r#"
        SELECT id, realm_id, username, email, email_verified,
               first_name, last_name, enabled, created_at
        FROM users
        WHERE id = $1
        "#,
        id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up user by id", e))?
    .ok_or(AppError::NotFound("user"))?;

    Ok(User {
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
}

/// Find a user by username **or** email, case-insensitively, with their
/// credential.
///
/// Returns `Ok(None)` rather than an error when there is no match: the caller
/// must not be able to distinguish "no such user" from "wrong password" in what
/// it reports, and forcing it to handle the `None` case keeps that decision in
/// one place.
pub(crate) async fn credentialed_by_identifier(
    db: &Db,
    realm_id: RealmId,
    identifier: &str,
) -> Result<Option<Credentialed>> {
    let row = sqlx::query!(
        r#"
        SELECT u.id, u.realm_id, u.username, u.email, u.email_verified,
               u.first_name, u.last_name, u.enabled, u.created_at,
               p.phc
        FROM users u
        LEFT JOIN user_passwords p ON p.user_id = u.id
        WHERE u.realm_id = $1
          AND (lower(u.username) = lower($2) OR lower(u.email) = lower($2))
        "#,
        realm_id.0,
        identifier,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up user by identifier", e))?;

    Ok(row.map(|row| Credentialed {
        user: User {
            id: UserId(row.id),
            realm_id: RealmId(row.realm_id),
            username: row.username,
            email: row.email,
            email_verified: row.email_verified,
            first_name: row.first_name,
            last_name: row.last_name,
            enabled: row.enabled,
            created_at: row.created_at,
        },
        phc: row.phc,
    }))
}

/// The role names granted to a user.
///
/// Resolved from the database at the point of use rather than carried in a
/// token. The previous system minted tokens with `roles: None` and then
/// checked `roles.contains("admin")`, so no token it issued could ever satisfy
/// an admin check — every role-gated endpoint was permanently 403 while
/// everything else was permanently open.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn role_names(db: &Db, user_id: UserId) -> Result<Vec<String>> {
    let names = sqlx::query_scalar!(
        r#"
        SELECT r.name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
        ORDER BY r.name
        "#,
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("loading user roles", e))?;

    Ok(names)
}

/// Replace a user's password.
///
/// # Errors
///
/// Returns a field error if the password fails policy, or an internal error if
/// the write fails.
pub async fn set_password(
    db: &Db,
    hasher: &PasswordHasher,
    user_id: UserId,
    password: &str,
) -> Result<()> {
    validate::password(password)?;
    let phc = hasher.hash(password)?;

    sqlx::query!(
        r#"
        INSERT INTO user_passwords (user_id, phc, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (user_id) DO UPDATE SET phc = EXCLUDED.phc, updated_at = now()
        "#,
        user_id.0,
        phc,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("updating password", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm;

    const GOOD_PASSWORD: &str = "correct horse battery staple";

    async fn realm_and_user(db: &Db) -> (RealmId, User) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let user = create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: "alice@example.com",
                password: GOOD_PASSWORD,
                first_name: Some("Alice"),
                last_name: None,
            },
        )
        .await
        .unwrap();
        (realm.id, user)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_created_user_can_be_found_by_id(db: Db) {
        let (_, user) = realm_and_user(&db).await;
        let found = by_id(&db, user.id).await.unwrap();
        assert_eq!(found.username, "alice");
        assert!(found.enabled);
        assert!(!found.email_verified, "email starts unverified");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_user_can_be_found_by_username_or_email_in_any_case(db: Db) {
        let (realm_id, user) = realm_and_user(&db).await;

        for identifier in ["alice", "ALICE", "alice@example.com", "Alice@Example.COM"] {
            let found = credentialed_by_identifier(&db, realm_id, identifier)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{identifier} should match"));
            assert_eq!(found.user.id, user.id);
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_identifier_yields_none_not_an_error(db: Db) {
        let (realm_id, _) = realm_and_user(&db).await;
        let found = credentialed_by_identifier(&db, realm_id, "nobody")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn users_are_scoped_to_their_realm(db: Db) {
        let (_, _) = realm_and_user(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap();

        // The same identifier must not resolve across a realm boundary.
        let found = credentialed_by_identifier(&db, other.id, "alice")
            .await
            .unwrap();
        assert!(found.is_none(), "realms must be isolated");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_stored_credential_is_a_hash_not_the_password(db: Db) {
        let (realm_id, _) = realm_and_user(&db).await;
        let found = credentialed_by_identifier(&db, realm_id, "alice")
            .await
            .unwrap()
            .unwrap();

        let phc = found.phc.expect("a password was set");
        assert!(phc.starts_with("$argon2id$"));
        assert!(!phc.contains(GOOD_PASSWORD));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_duplicate_username_is_a_conflict(db: Db) {
        let hasher = PasswordHasher::new();
        let (realm_id, _) = realm_and_user(&db).await;

        let error = create(
            &db,
            &hasher,
            NewUser {
                realm_id,
                username: "ALICE",
                email: "other@example.com",
                password: GOOD_PASSWORD,
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.status(), 409, "case-differing username must collide");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_weak_password_is_rejected_and_no_user_is_created(db: Db) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();

        let error = create(
            &db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "bob",
                email: "bob@example.com",
                password: "short",
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.status(), 400);

        // The username must remain free — a rejected creation must not have
        // half-happened.
        let leftover = credentialed_by_identifier(&db, realm.id, "bob")
            .await
            .unwrap();
        assert!(leftover.is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn setting_a_password_replaces_the_previous_one(db: Db) {
        let hasher = PasswordHasher::new();
        let (realm_id, user) = realm_and_user(&db).await;

        let before = credentialed_by_identifier(&db, realm_id, "alice")
            .await
            .unwrap()
            .unwrap()
            .phc
            .unwrap();

        set_password(&db, &hasher, user.id, "a completely different phrase")
            .await
            .unwrap();

        let after = credentialed_by_identifier(&db, realm_id, "alice")
            .await
            .unwrap()
            .unwrap()
            .phc
            .unwrap();

        assert_ne!(before, after);
        assert!(
            hasher
                .verify("a completely different phrase", &after)
                .unwrap()
        );
        assert!(!hasher.verify(GOOD_PASSWORD, &after).unwrap());
    }
}
