//! Command-line interface.
//!
//! Operational tasks live here rather than behind an HTTP endpoint. That is a
//! deliberate boundary: the previous server shipped `/api/v1/auth/test-login`
//! and `/oauth2/consent/test` in its production router — unauthenticated, and
//! hardcoding a user id — because there was nowhere else to put "set up some
//! data to try this with". There is now.

use authenc_contract::{AppError, Result, model::ROLE_ADMIN};
use authenc_identity::{
    Db, PasswordHasher, realm, role,
    user::{self, NewUser},
};
use clap::{Parser, Subcommand};

/// The Authenc server.
#[derive(Debug, Parser)]
#[command(name = "authenc", version, about)]
pub struct Cli {
    /// What to do. Defaults to running the server.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server. The default when no subcommand is given.
    Serve,

    /// Apply pending migrations and exit.
    Migrate,

    /// Create a realm and an administrator in it.
    ///
    /// Idempotent enough to be safe to re-run: an existing realm is reused, and
    /// an existing username is reported rather than overwritten.
    Seed {
        /// Realm slug to create or reuse.
        #[arg(long, default_value = "master")]
        realm: String,

        /// Administrator username.
        #[arg(long, default_value = "admin")]
        username: String,

        /// Administrator email address.
        #[arg(long)]
        email: String,

        /// Administrator password.
        ///
        /// Prefer the environment variable: a password passed as an argument
        /// is visible in the process list and in shell history.
        #[arg(long, env = "AUTHENC_SEED_PASSWORD", hide_env_values = true)]
        password: String,
    },

    /// Delete expired sessions.
    PurgeSessions,
}

/// Create a realm and an administrator inside it.
///
/// # Errors
///
/// Returns an error if validation fails or the database rejects a write.
pub async fn seed(
    db: &Db,
    hasher: &PasswordHasher,
    realm_name: &str,
    username: &str,
    email: &str,
    password: &str,
) -> Result<()> {
    let realm = match realm::by_name(db, realm_name).await {
        Ok(existing) => {
            tracing::info!(realm = realm_name, "reusing existing realm");
            existing
        }
        Err(error) if error.status() == 404 => realm::create(db, realm_name, realm_name).await?,
        Err(error) => return Err(error),
    };

    let user = user::create(
        db,
        hasher,
        NewUser {
            realm_id: realm.id,
            username,
            email,
            password,
            first_name: None,
            last_name: None,
        },
    )
    .await
    .map_err(|error| match error.status() {
        409 => AppError::conflict(format!(
            "user {username} already exists in realm {realm_name}; \
             nothing was changed"
        )),
        _ => error,
    })?;

    let admin = role::ensure(
        db,
        realm.id,
        ROLE_ADMIN,
        Some("Full administrative access within the realm"),
    )
    .await?;
    role::grant(db, user.id, admin.id).await?;

    tracing::info!(
        realm = realm_name,
        username,
        "created administrator; sign in at /login",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    #[sqlx::test(migrations = "../../migrations")]
    async fn seeding_creates_a_realm_an_admin_and_the_admin_role(db: Db) {
        let hasher = PasswordHasher::new();
        seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            PASSWORD,
        )
        .await
        .unwrap();

        // Prove it through the same path a login takes, rather than by
        // reading rows: the roles must be visible where authorisation reads
        // them.
        let authenticated = authenc_identity::login::authenticate(
            &db,
            &hasher,
            authenc_identity::login::Attempt {
                realm: "master",
                identifier: "admin",
                password: PASSWORD,
                origin: authenc_identity::session::Origin::default(),
            },
        )
        .await
        .unwrap();

        let roles = user::role_names(&db, authenticated.user.id).await.unwrap();
        assert_eq!(roles, vec![ROLE_ADMIN.to_owned()]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_seeded_admin_can_actually_log_in(db: Db) {
        // The property that matters: seeding produces working credentials, not
        // merely rows.
        let hasher = PasswordHasher::new();
        seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            PASSWORD,
        )
        .await
        .unwrap();

        let result = authenc_identity::login::authenticate(
            &db,
            &hasher,
            authenc_identity::login::Attempt {
                realm: "master",
                identifier: "admin",
                password: PASSWORD,
                origin: authenc_identity::session::Origin::default(),
            },
        )
        .await;

        assert!(result.is_ok(), "seeded admin should be able to sign in");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn seeding_twice_reports_a_conflict_rather_than_overwriting(db: Db) {
        let hasher = PasswordHasher::new();
        seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            PASSWORD,
        )
        .await
        .unwrap();

        let error = seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            "a different password entirely",
        )
        .await
        .unwrap_err();

        assert_eq!(error.status(), 409);

        // And the original password must still work — a re-run must not have
        // silently reset the administrator's credentials.
        assert!(
            authenc_identity::login::authenticate(
                &db,
                &hasher,
                authenc_identity::login::Attempt {
                    realm: "master",
                    identifier: "admin",
                    password: PASSWORD,
                    origin: authenc_identity::session::Origin::default(),
                },
            )
            .await
            .is_ok(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_weak_seed_password_is_refused(db: Db) {
        let hasher = PasswordHasher::new();
        let error = seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            "admin",
        )
        .await
        .unwrap_err();

        assert_eq!(error.status(), 400, "policy applies to the first user too");
    }
}
