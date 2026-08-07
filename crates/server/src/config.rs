//! Layered configuration.
//!
//! Sources, in increasing precedence:
//!
//! 1. the defaults in [`Config::default`]
//! 2. `config/default.toml`, then `config/{profile}.toml`, if present
//! 3. environment variables prefixed `AUTHENC_`, nested with `__`
//!    (`AUTHENC_SERVER__PORT=8080`)
//!
//! Everything is read and validated **once**, at startup, into an immutable
//! value. The previous implementation scattered forty-eight `env::var` calls
//! across five crates, read only fifteen of them into its config struct, and
//! left whole config sections unreachable from the environment entirely.

use std::{net::IpAddr, time::Duration};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A configuration value that must never appear in a log line.
///
/// `secrecy::SecretString` deliberately refuses to implement `Serialize`,
/// which figment's defaults provider requires, so this is the local
/// equivalent: it serialises (in memory, to figment) but its `Debug` output is
/// redacted and its buffer is zeroed on drop. The redaction is what stops a
/// database password travelling inside a `tracing` field or a panic message.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Read the underlying value. Every call site is a place to check.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Which environment the process believes it is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Local development: relaxed cookie flags, human-readable logs.
    #[default]
    Development,
    /// Continuous integration.
    Test,
    /// Production: every security control on, no defaults tolerated.
    Production,
}

impl Profile {
    /// Whether this profile must refuse to start on a weak configuration.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }
}

/// The whole configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which environment this is.
    pub profile: Profile,
    /// HTTP listener.
    pub server: ServerConfig,
    /// Database connection.
    pub database: DatabaseConfig,
    /// Logging and tracing.
    pub telemetry: TelemetryConfig,
    /// Security controls.
    pub security: SecurityConfig,
    /// Outbound mail.
    pub mail: MailConfig,
}

/// HTTP listener settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind. Honoured — the previous server hardcoded `0.0.0.0`
    /// and ignored the configured host entirely.
    pub host: IpAddr,
    /// Port to bind.
    pub port: u16,
    /// Public origin, used for absolute URLs and cookie scoping.
    pub public_url: String,
    /// How long a single request may take before it is cut off.
    #[serde(with = "humantime_secs")]
    pub request_timeout: Duration,
    /// Largest accepted request body, in bytes.
    pub max_body_bytes: usize,
}

/// Database settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// libpq-style connection URL.
    pub url: Secret,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
    /// Lower bound, kept warm.
    pub min_connections: u32,
    /// How long to wait for a free connection.
    #[serde(with = "humantime_secs")]
    pub acquire_timeout: Duration,
    /// Whether to apply pending migrations at startup.
    pub migrate_on_start: bool,
}

/// Logging and tracing settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `tracing-subscriber` filter directive, e.g. `info,authenc=debug`.
    pub filter: String,
    /// Emit machine-readable JSON logs instead of human-readable ones.
    pub json: bool,
}

/// How outbound mail is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MailTransport {
    /// Write the message to the log instead of sending it.
    ///
    /// Makes a fresh checkout produce a working reset link with no SMTP setup.
    /// Rejected under the production profile: a recovery flow that silently
    /// sends nothing locks users out with no error anywhere.
    #[default]
    Logging,
    /// Send over SMTP.
    Smtp,
}

/// Outbound mail settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailConfig {
    /// How to deliver.
    pub transport: MailTransport,
    /// SMTP URL, e.g. `smtp://localhost:1025` or `smtps://user:pass@host:465`.
    pub smtp_url: Secret,
    /// `From` address on outbound mail.
    pub from: String,
}

/// Security controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Origins permitted to make cross-origin requests. Empty means
    /// same-origin only.
    ///
    /// The previous server parsed this setting and then applied
    /// `CorsLayer::permissive()` — `Access-Control-Allow-Origin: *` on an IAM
    /// server — so the value never had any effect.
    pub cors_allowed_origins: Vec<String>,
    /// Whether to emit HSTS. Off in development, where there is no TLS.
    pub hsts: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: Profile::Development,
            server: ServerConfig {
                host: IpAddr::from([127, 0, 0, 1]),
                port: 3000,
                public_url: "http://localhost:3000".to_owned(),
                request_timeout: Duration::from_secs(30),
                max_body_bytes: 1024 * 1024,
            },
            database: DatabaseConfig {
                // A development-only default. `validate` rejects it under the
                // production profile rather than letting it through silently,
                // which is how the old build shipped
                // `default_jwt_secret_change_in_production`.
                url: Secret::from("postgres://postgres:postgres@localhost:5432/authenc"),
                max_connections: 16,
                min_connections: 1,
                acquire_timeout: Duration::from_secs(5),
                migrate_on_start: true,
            },
            telemetry: TelemetryConfig {
                filter: "info,authenc=debug,tower_http=debug".to_owned(),
                json: false,
            },
            security: SecurityConfig {
                cors_allowed_origins: Vec::new(),
                hsts: false,
            },
            mail: MailConfig {
                transport: MailTransport::Logging,
                // MailHog, from compose.yaml.
                smtp_url: Secret::from("smtp://localhost:1025"),
                from: "Authenc <no-reply@localhost>".to_owned(),
            },
        }
    }
}

/// Why a configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The sources could not be read or merged.
    ///
    /// Boxed because `figment::Error` is over 200 bytes, and this type is the
    /// `Err` half of every configuration call.
    #[error("reading configuration: {0}")]
    Source(#[from] Box<figment::Error>),

    /// The merged configuration is internally inconsistent or unsafe.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Load, merge, and validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a source cannot be read or the result fails
    /// [`Config::validate`].
    pub fn load() -> Result<Self, ConfigError> {
        // Read the profile first, because it selects which file to overlay and
        // how strict validation is.
        let profile: Profile = Figment::new()
            .merge(Serialized::default("profile", Profile::default()))
            .merge(Env::prefixed("AUTHENC_").only(&["profile"]))
            .extract_inner("profile")
            .unwrap_or_default();

        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file("config/default.toml"))
            .merge(Toml::file(format!("config/{}.toml", profile.as_str())))
            // `AUTHENC_SEED_PASSWORD` shares the prefix but is a CLI argument, not
            // configuration. Excluded explicitly so `deny_unknown_fields` keeps
            // catching genuine typos instead of being switched off.
            .merge(
                Env::prefixed("AUTHENC_")
                    .split("__")
                    .ignore(&["SEED_PASSWORD"]),
            )
            .extract()
            .map_err(Box::new)?;

        config.validate()?;
        Ok(config)
    }

    /// Reject configurations that are unsafe for the selected profile.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| Err(ConfigError::Invalid(message));

        if self.server.port == 0 {
            return invalid("server.port must not be 0".to_owned());
        }
        if self.database.min_connections > self.database.max_connections {
            return invalid(
                "database.min_connections must not exceed database.max_connections".to_owned(),
            );
        }
        if self.database.max_connections == 0 {
            return invalid("database.max_connections must be at least 1".to_owned());
        }

        if !self.profile.is_production() {
            return Ok(());
        }

        // Production is where silence becomes dangerous, so fail loudly.
        if self.database.url.expose().contains("postgres:postgres@") {
            return invalid(
                "database.url still uses the development postgres:postgres credentials".to_owned(),
            );
        }
        if !self.server.public_url.starts_with("https://") {
            return invalid("server.public_url must be https:// in production".to_owned());
        }
        if !self.security.hsts {
            return invalid("security.hsts must be enabled in production".to_owned());
        }
        if self
            .security
            .cors_allowed_origins
            .iter()
            .any(|origin| origin == "*")
        {
            return invalid(
                "security.cors_allowed_origins must not contain '*' in production".to_owned(),
            );
        }
        if self.mail.transport == MailTransport::Logging {
            return invalid(
                "mail.transport must be 'smtp' in production; \
                 'logging' would silently discard every password-reset mail"
                    .to_owned(),
            );
        }

        Ok(())
    }

    /// The database settings, in the shape the identity crate wants.
    #[must_use]
    pub fn db_config(&self) -> authenc_identity::DbConfig {
        authenc_identity::DbConfig {
            url: self.database.url.expose().to_owned(),
            max_connections: self.database.max_connections,
            min_connections: self.database.min_connections,
            acquire_timeout: self.database.acquire_timeout,
        }
    }
}

/// Serialise `Duration` as whole seconds, so TOML and env vars can say `30`.
mod humantime_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(value.as_secs())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production() -> Config {
        Config {
            profile: Profile::Production,
            server: ServerConfig {
                public_url: "https://id.example.com".to_owned(),
                ..Config::default().server
            },
            database: DatabaseConfig {
                url: Secret::from("postgres://app:s3cret@db.internal:5432/authenc"),
                ..Config::default().database
            },
            security: SecurityConfig {
                cors_allowed_origins: vec!["https://app.example.com".to_owned()],
                hsts: true,
            },
            mail: MailConfig {
                transport: MailTransport::Smtp,
                ..Config::default().mail
            },
            ..Config::default()
        }
    }

    #[test]
    fn the_default_configuration_is_valid_in_development() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn a_well_formed_production_configuration_is_valid() {
        assert!(production().validate().is_ok());
    }

    #[test]
    fn production_rejects_the_development_database_credentials() {
        let mut config = production();
        config.database.url = Secret::from("postgres://postgres:postgres@db:5432/authenc");
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("postgres:postgres"), "got: {error}");
    }

    #[test]
    fn production_requires_https_and_hsts() {
        let mut config = production();
        config.server.public_url = "http://id.example.com".to_owned();
        assert!(config.validate().is_err());

        let mut config = production();
        config.security.hsts = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn production_refuses_to_discard_mail() {
        let mut config = production();
        config.mail.transport = MailTransport::Logging;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("mail.transport"), "got: {error}");
    }

    #[test]
    fn production_rejects_wildcard_cors() {
        let mut config = production();
        config.security.cors_allowed_origins = vec!["*".to_owned()];
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cors_allowed_origins"), "got: {error}");
    }

    #[test]
    fn development_tolerates_what_production_rejects() {
        // The same values that fail above must not block a local run.
        let config = Config::default();
        assert!(!config.profile.is_production());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn nonsensical_pool_sizes_are_rejected() {
        let mut config = Config::default();
        config.database.min_connections = 20;
        config.database.max_connections = 5;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.database.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_database_url_is_redacted_in_debug_output() {
        // A config struct ends up in logs and panic messages; the password
        // must not travel with it.
        let rendered = format!("{:?}", Config::default());
        assert!(!rendered.contains("postgres:postgres"), "got: {rendered}");
    }
}
