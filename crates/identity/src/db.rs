//! Database pool construction, migration, and liveness.

use std::time::Duration;

use authenc_contract::{AppError, Result};
use sqlx::{
    Pool, Postgres,
    postgres::{PgConnectOptions, PgPoolOptions},
};

/// The connection pool, shared by every repository.
pub type Db = Pool<Postgres>;

/// How to reach and size the database.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// libpq-style connection URL.
    pub url: String,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
    /// Lower bound, kept warm.
    pub min_connections: u32,
    /// How long to wait for a free connection before giving up.
    pub acquire_timeout: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "postgres://postgres:postgres@localhost:5432/authenc".to_owned(),
            max_connections: 16,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

/// Open a connection pool.
///
/// Unlike the previous implementation, the configured sizing is actually
/// applied — that code built a `PoolConfig::default()` and silently discarded
/// `max_connections` — and TLS is negotiated when the server offers it rather
/// than being hard-wired to `NoTls`.
pub async fn connect(config: &DbConfig) -> Result<Db> {
    let options: PgConnectOptions = config
        .url
        .parse()
        .map_err(|e| AppError::internal_from("parsing DATABASE_URL", e))?;

    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .connect_with(options)
        .await
        .map_err(|e| AppError::internal_from("connecting to the database", e))
}

/// Apply every pending migration.
///
/// This genuinely runs the SQL. The function it replaces read a schema file
/// and logged its byte count, then reported success — and was never called
/// from anywhere in any case.
pub async fn migrate(db: &Db) -> Result<()> {
    sqlx::migrate!("../../migrations")
        .run(db)
        .await
        .map_err(|e| AppError::internal_from("running database migrations", e))?;
    tracing::info!("database migrations applied");
    Ok(())
}

/// Check that the database answers. Used by the readiness probe.
///
/// Written with the `query_scalar!` macro rather than the runtime builder so
/// that this crate genuinely exercises SQLx's compile-time checking: the query
/// is verified against the real schema at build time, and `just sqlx-prepare`
/// records the result in `.sqlx/` so CI can build with no database attached.
pub async fn ping(db: &Db) -> Result<()> {
    // The `!` suffix asserts non-null; without it PostgreSQL types a bare
    // literal as nullable and the macro returns `Option<i32>`.
    sqlx::query_scalar!(r#"SELECT 1 AS "one!""#)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::internal_from("pinging the database", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_bounded() {
        let config = DbConfig::default();
        assert!(config.max_connections >= config.min_connections);
        assert!(config.acquire_timeout > Duration::ZERO);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn migrations_apply_and_the_database_answers(db: Db) {
        ping(&db).await.expect("database should answer SELECT 1");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_schema_has_the_core_identity_tables(db: Db) {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' ORDER BY table_name",
        )
        .fetch_all(&db)
        .await
        .expect("listing tables");

        for expected in [
            "realms",
            "users",
            "user_passwords",
            "roles",
            "permissions",
            "role_permissions",
            "user_roles",
            "sessions",
            "login_attempts",
        ] {
            assert!(
                tables.iter().any(|t| t == expected),
                "missing table {expected}; got {tables:?}"
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn usernames_are_unique_per_realm_case_insensitively(db: Db) {
        let realm: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO realms (name, display_name) VALUES ('master', 'Master') RETURNING id",
        )
        .fetch_one(&db)
        .await
        .expect("creating realm");

        sqlx::query("INSERT INTO users (realm_id, username, email) VALUES ($1, 'Alice', 'a@x.io')")
            .bind(realm)
            .execute(&db)
            .await
            .expect("first insert should succeed");

        // `alice` must collide with `Alice`: treating them as distinct accounts
        // is an account-takeover vector during password reset.
        let clash = sqlx::query(
            "INSERT INTO users (realm_id, username, email) VALUES ($1, 'alice', 'b@x.io')",
        )
        .bind(realm)
        .execute(&db)
        .await;

        assert!(clash.is_err(), "case-differing username should collide");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn realm_names_must_be_slugs(db: Db) {
        for bad in ["Master", "has space", "-leading", "trailing-"] {
            let result = sqlx::query("INSERT INTO realms (name, display_name) VALUES ($1, 'x')")
                .bind(bad)
                .execute(&db)
                .await;
            assert!(result.is_err(), "{bad:?} should be rejected by the CHECK");
        }
    }
}
