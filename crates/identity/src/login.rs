//! Authenticating a user.
//!
//! This is the one place a password is checked, and the shape of the function
//! is most of the security. Three properties are load-bearing:
//!
//! 1. **A wrong password and an unknown user are indistinguishable** — same
//!    error, and the same amount of work, because skipping the hash when the
//!    user does not exist turns response time into a user-enumeration oracle.
//! 2. **Lockout is checked before the password is**, so a locked account costs
//!    an attacker a database lookup rather than an Argon2 verification.
//! 3. **Every attempt is recorded**, successful or not, because that record is
//!    both the lockout input and the answer to "was this account attacked?".

use std::net::IpAddr;

use authenc_contract::{AppError, RealmId, Result, UserId, model::User};
use time::{Duration, OffsetDateTime};

use crate::{
    db::Db,
    password::PasswordHasher,
    session::{self, Issued, Origin},
    user,
};

/// Failed attempts against one identifier before it is locked.
pub const MAX_ATTEMPTS_PER_IDENTIFIER: i64 = 5;
/// Failed attempts from one address before it is locked, across all accounts.
///
/// Higher than the per-identifier limit because a shared NAT address is a
/// normal thing, but low enough to make credential stuffing expensive.
pub const MAX_ATTEMPTS_PER_ADDRESS: i64 = 30;
/// How far back failed attempts are counted, and therefore how long a lockout
/// lasts once attempts stop.
pub const WINDOW: Duration = Duration::minutes(15);

/// What the caller supplies to authenticate someone.
#[derive(Debug, Clone, Copy)]
pub struct Attempt<'a> {
    /// Realm slug.
    pub realm: &'a str,
    /// Username or email.
    pub identifier: &'a str,
    /// Submitted password.
    pub password: &'a str,
    /// Where the request came from.
    pub origin: Origin<'a>,
}

/// A successful authentication.
#[derive(Debug)]
pub struct Authenticated {
    /// The user who authenticated.
    pub user: User,
    /// Their new session, and the token for the cookie.
    pub session: Issued,
}

/// Authenticate a user and open a session for them.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — wrong credentials, unknown user, disabled
///   user, or disabled realm. Deliberately the same error for all of them.
/// * [`AppError::RateLimited`] — too many recent failures for this identifier
///   or from this address.
/// * [`AppError::Internal`] — the database or the hasher failed.
pub async fn authenticate(
    db: &Db,
    hasher: &PasswordHasher,
    attempt: Attempt<'_>,
) -> Result<Authenticated> {
    let realm = crate::realm::by_name(db, attempt.realm)
        .await
        .map_err(|error| match error.status() {
            // Do not confirm which realms exist to an unauthenticated caller.
            404 => AppError::Unauthenticated,
            _ => error,
        })?;

    if !realm.enabled {
        return Err(AppError::Unauthenticated);
    }

    if is_locked(db, realm.id, attempt.identifier, attempt.origin.ip_address).await? {
        // Recorded so that an attacker hammering a locked account still shows
        // up in the attempt history.
        record(
            db,
            realm.id,
            attempt.identifier,
            None,
            attempt.origin,
            false,
        )
        .await?;
        return Err(AppError::RateLimited);
    }

    let found = user::credentialed_by_identifier(db, realm.id, attempt.identifier).await?;

    // Verify against a real hash whether or not the user exists, so the timing
    // of the two cases matches. `DUMMY_PHC` is a hash of a random string; it
    // can never verify.
    let (user, phc) = match &found {
        Some(credentialed) => (
            Some(&credentialed.user),
            credentialed.phc.as_deref().unwrap_or(DUMMY_PHC),
        ),
        None => (None, DUMMY_PHC),
    };

    let password_ok = hasher.verify(attempt.password, phc).unwrap_or(false);
    let enabled = user.is_some_and(|u| u.enabled);

    if !password_ok || !enabled {
        record(
            db,
            realm.id,
            attempt.identifier,
            user.map(|u| u.id),
            attempt.origin,
            false,
        )
        .await?;
        return Err(AppError::Unauthenticated);
    }

    let user = user.cloned().ok_or(AppError::Unauthenticated)?;

    // Take the opportunity to upgrade a hash made under weaker parameters.
    if hasher.needs_rehash(phc)
        && let Err(error) = user::set_password(db, hasher, user.id, attempt.password).await
    {
        // Not fatal: the user authenticated correctly, and failing the login
        // over a background upgrade would be worse than leaving the old hash.
        tracing::warn!(%error, user_id = %user.id, "failed to upgrade password hash");
    }

    record(
        db,
        realm.id,
        attempt.identifier,
        Some(user.id),
        attempt.origin,
        true,
    )
    .await?;

    let session = session::create(db, user.id, realm.id, attempt.origin).await?;

    Ok(Authenticated { user, session })
}

/// An Argon2id hash of a value no one knows, used to equalise the timing of
/// the "no such user" path with the "wrong password" path.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1\
$c29tZXNhbHRzb21lc2FsdA$Yl5rN0zCJKcCwvB5PLQVOCB6BE6cN4RQtvSHnKqLQBg";

/// Whether this identifier or address currently exceeds the failure budget.
async fn is_locked(
    db: &Db,
    realm_id: RealmId,
    identifier: &str,
    ip: Option<IpAddr>,
) -> Result<bool> {
    let since = OffsetDateTime::now_utc() - WINDOW;

    let by_identifier = sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "count!"
        FROM login_attempts
        WHERE realm_id = $1
          AND lower(identifier) = lower($2)
          AND NOT successful
          AND attempted_at > $3
        "#,
        realm_id.0,
        identifier,
        since,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting failed attempts", e))?;

    if by_identifier >= MAX_ATTEMPTS_PER_IDENTIFIER {
        return Ok(true);
    }

    let Some(ip) = ip else {
        return Ok(false);
    };

    let by_address = sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "count!"
        FROM login_attempts
        WHERE ip_address = $1::text::inet
          AND NOT successful
          AND attempted_at > $2
        "#,
        ip.to_string(),
        since,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting failed attempts by address", e))?;

    Ok(by_address >= MAX_ATTEMPTS_PER_ADDRESS)
}

/// Record an attempt.
async fn record(
    db: &Db,
    realm_id: RealmId,
    identifier: &str,
    user_id: Option<UserId>,
    origin: Origin<'_>,
    successful: bool,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO login_attempts (realm_id, identifier, user_id, ip_address, successful)
        VALUES ($1, $2, $3, $4::text::inet, $5)
        "#,
        realm_id.0,
        identifier,
        user_id.map(|id| id.0),
        origin.ip_address.map(|ip| ip.to_string()),
        successful,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording login attempt", e))?;

    Ok(())
}

/// Clear the failure history for an identifier — used after a successful
/// password reset, so a locked-out owner is not kept out by the attack that
/// prompted the reset.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn clear_failures(db: &Db, realm_id: RealmId, identifier: &str) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM login_attempts
        WHERE realm_id = $1 AND lower(identifier) = lower($2) AND NOT successful
        "#,
        realm_id.0,
        identifier,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("clearing login failures", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        realm,
        user::{self, NewUser},
    };

    const PASSWORD: &str = "correct horse battery staple";

    async fn fixture(db: &Db) -> (PasswordHasher, User) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let user = user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: "alice@example.com",
                password: PASSWORD,
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();
        (hasher, user)
    }

    fn attempt<'a>(identifier: &'a str, password: &'a str) -> Attempt<'a> {
        Attempt {
            realm: "acme",
            identifier,
            password,
            origin: Origin::default(),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn correct_credentials_open_a_session(db: Db) {
        let (hasher, user) = fixture(&db).await;

        let result = authenticate(&db, &hasher, attempt("alice", PASSWORD))
            .await
            .unwrap();

        assert_eq!(result.user.id, user.id);
        let resolved = session::lookup(&db, &result.session.token)
            .await
            .unwrap()
            .expect("the issued token must resolve");
        assert_eq!(resolved.user_id, user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_email_address_works_as_the_identifier(db: Db) {
        let (hasher, _) = fixture(&db).await;
        assert!(
            authenticate(&db, &hasher, attempt("ALICE@example.com", PASSWORD))
                .await
                .is_ok()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_wrong_password_and_an_unknown_user_are_indistinguishable(db: Db) {
        let (hasher, _) = fixture(&db).await;

        let wrong_password = authenticate(&db, &hasher, attempt("alice", "wrong password here"))
            .await
            .unwrap_err();
        let unknown_user = authenticate(&db, &hasher, attempt("nobody", PASSWORD))
            .await
            .unwrap_err();

        // Same status and same message: anything else lets a caller enumerate
        // which accounts exist.
        assert_eq!(wrong_password.status(), 401);
        assert_eq!(unknown_user.status(), 401);
        assert_eq!(wrong_password.to_string(), unknown_user.to_string());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_realm_does_not_reveal_itself(db: Db) {
        let (hasher, _) = fixture(&db).await;

        let error = authenticate(
            &db,
            &hasher,
            Attempt {
                realm: "no-such-realm",
                identifier: "alice",
                password: PASSWORD,
                origin: Origin::default(),
            },
        )
        .await
        .unwrap_err();

        // 401, not 404: a 404 would confirm which realms exist.
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_user_cannot_authenticate(db: Db) {
        let (hasher, user) = fixture(&db).await;
        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
            .bind(user.id.0)
            .execute(&db)
            .await
            .unwrap();

        let error = authenticate(&db, &hasher, attempt("alice", PASSWORD))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_realm_blocks_authentication(db: Db) {
        let (hasher, _) = fixture(&db).await;
        sqlx::query("UPDATE realms SET enabled = false")
            .execute(&db)
            .await
            .unwrap();

        let error = authenticate(&db, &hasher, attempt("alice", PASSWORD))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn repeated_failures_lock_the_account(db: Db) {
        let (hasher, _) = fixture(&db).await;

        for _ in 0..MAX_ATTEMPTS_PER_IDENTIFIER {
            let error = authenticate(&db, &hasher, attempt("alice", "wrong password here"))
                .await
                .unwrap_err();
            assert_eq!(error.status(), 401);
        }

        let error = authenticate(&db, &hasher, attempt("alice", "wrong password here"))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 429, "should be locked by now");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn lockout_holds_even_against_the_correct_password(db: Db) {
        let (hasher, _) = fixture(&db).await;

        for _ in 0..MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(&db, &hasher, attempt("alice", "wrong password here")).await;
        }

        // The whole point: an attacker who guesses correctly on attempt six
        // must still be turned away.
        let error = authenticate(&db, &hasher, attempt("alice", PASSWORD))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 429);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn lockout_is_scoped_to_the_identifier_attacked(db: Db) {
        let (hasher, _) = fixture(&db).await;
        let realm = realm::by_name(&db, "acme").await.unwrap();
        user::create(
            &db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "bob",
                email: "bob@example.com",
                password: PASSWORD,
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();

        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(&db, &hasher, attempt("alice", "wrong password here")).await;
        }

        // Attacking one account must not lock everyone else out.
        assert!(
            authenticate(&db, &hasher, attempt("bob", PASSWORD))
                .await
                .is_ok()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn failures_outside_the_window_do_not_count(db: Db) {
        let (hasher, _) = fixture(&db).await;

        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(&db, &hasher, attempt("alice", "wrong password here")).await;
        }
        assert_eq!(
            authenticate(&db, &hasher, attempt("alice", PASSWORD))
                .await
                .unwrap_err()
                .status(),
            429,
        );

        // Age the attempts past the window; the lock must lift on its own.
        sqlx::query("UPDATE login_attempts SET attempted_at = now() - interval '1 hour'")
            .execute(&db)
            .await
            .unwrap();

        assert!(
            authenticate(&db, &hasher, attempt("alice", PASSWORD))
                .await
                .is_ok(),
            "lockout must expire without an administrator",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn every_attempt_is_recorded(db: Db) {
        let (hasher, _) = fixture(&db).await;

        let _ = authenticate(&db, &hasher, attempt("alice", "wrong password here")).await;
        authenticate(&db, &hasher, attempt("alice", PASSWORD))
            .await
            .unwrap();

        let (failures, successes): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE NOT successful), \
                    count(*) FILTER (WHERE successful) FROM login_attempts",
        )
        .fetch_one(&db)
        .await
        .unwrap();

        assert_eq!(failures, 1);
        assert_eq!(successes, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn clearing_failures_lifts_a_lockout(db: Db) {
        let (hasher, _) = fixture(&db).await;
        let realm = realm::by_name(&db, "acme").await.unwrap();

        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(&db, &hasher, attempt("alice", "wrong password here")).await;
        }

        clear_failures(&db, realm.id, "alice").await.unwrap();

        assert!(
            authenticate(&db, &hasher, attempt("alice", PASSWORD))
                .await
                .is_ok(),
            "a password reset must let the rightful owner back in",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_dummy_hash_can_never_verify(db: Db) {
        // If this ever returned true, an unknown username would authenticate.
        let (hasher, _) = fixture(&db).await;
        for candidate in ["", PASSWORD, "password", "admin"] {
            assert!(
                !hasher.verify(candidate, DUMMY_PHC).unwrap(),
                "{candidate:?} verified against the dummy hash",
            );
        }
    }
}
