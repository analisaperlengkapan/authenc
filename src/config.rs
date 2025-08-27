/// OpenID Connect configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer: String,
    /// OIDC client ID
    pub client_id: String,
    /// OIDC client secret
    pub client_secret: String,
    /// OIDC redirect URI
    pub redirect_uri: String,
}

/// SAML configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SamlConfig {
    /// SAML entity ID
    pub entity_id: String,
    /// SAML SSO URL
    pub sso_url: String,
    /// SAML certificate
    pub certificate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UiConfig {
    pub enabled: bool,
    pub theme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiDbConfig {
    pub enabled: bool,
    pub db_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretonConfig {
    pub endpoint: String,
    pub token: String,
}

use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::error::{AuthencError, Result};
use crate::middleware::rate_limit_axum::RateLimitConfig;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Server configuration
    /// Server configuration settings
    pub server: ServerConfig,

    /// Database configuration
    /// Database connection configuration
    pub database: DatabaseConfig,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Security-related configuration
    pub security: SecurityConfig,

    /// Observability configuration (logging, metrics, etc.)
    pub observability: ObservabilityConfig,

    /// Feature flags and settings
    pub features: FeatureConfig,

    /// Optional OIDC configuration
    pub oidc: Option<OidcConfig>,

    /// Optional SAML configuration
    pub saml: Option<SamlConfig>,

    /// UI configuration
    pub ui: Option<UiConfig>,

    /// Multi-database configuration (if enabled)
    pub multi_db: Option<MultiDbConfig>,

    /// Secret management configuration (if using external secret management)
    pub secreton: Option<SecretonConfig>,
}

/// Server configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind the server to
    #[serde(default = "default_host")]
    pub host: String,

    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// Number of worker threads to use (defaults to number of CPU cores)
    pub workers: Option<usize>,

    /// Keep-alive timeout in seconds
    #[serde(default = "default_keep_alive")]
    pub keep_alive: u64,

    /// Client timeout in seconds
    #[serde(default = "default_client_timeout")]
    pub client_timeout: u64,

    /// Client disconnect timeout in seconds
    #[serde(default = "default_client_disconnect_timeout")]
    pub client_disconnect_timeout: u64,

    /// Maximum number of connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Public endpoint prefix
    #[serde(default = "default_public_prefix")]
    pub public_prefix: String,

    /// Admin endpoint prefix
    #[serde(default = "default_admin_prefix")]
    pub admin_prefix: String,

    /// Internal endpoint prefix
    #[serde(default = "default_internal_prefix")]
    pub internal_prefix: String,

    /// Enable TLS
    #[serde(default)]
    pub tls_enabled: bool,

    /// Path to TLS certificate file
    pub tls_cert_path: Option<String>,

    /// Path to TLS private key file
    pub tls_key_path: Option<String>,

    /// List of allowed CORS origins
    #[serde(default = "default_cors_origins")]
    pub cors_allowed_origins: Vec<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_keep_alive() -> u64 {
    75
}

fn default_client_timeout() -> u64 {
    30
}

fn default_client_disconnect_timeout() -> u64 {
    5
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_max_connections() -> u32 {
    100
}

fn default_public_prefix() -> String {
    "/api/v1".to_string()
}

fn default_admin_prefix() -> String {
    "/admin".to_string()
}

fn default_internal_prefix() -> String {
    "/internal".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub audit_log_url: Option<String>,
    pub connection_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Secret key for JWT signing and validation
    pub jwt_secret: String,

    /// JWT token expiration time in seconds
    #[serde(default = "default_jwt_expiry")]
    pub jwt_expiry: u64,

    /// Minimum password length requirement
    #[serde(default = "default_password_min_length")]
    pub password_min_length: u8,

    /// Number of requests allowed per rate limit window
    #[serde(default = "default_rate_limit_requests")]
    pub rate_limit_requests: u32,

    /// Rate limit window in seconds
    #[serde(default = "default_rate_limit_window")]
    pub rate_limit_window: u64,

    /// Maximum number of failed login attempts before account lockout
    #[serde(default = "default_brute_force_max_attempts")]
    pub brute_force_max_attempts: u32,

    /// Brute force detection window in seconds
    #[serde(default = "default_brute_force_window")]
    pub brute_force_window_seconds: u64,

    /// Number of requests allowed per minute (global rate limit)
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_requests_per_minute: u32,

    /// Number of salt rounds for password hashing
    #[serde(default = "default_password_salt_rounds")]
    pub password_salt_rounds: u32,
}

/// Observability configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(with = "log_level_serde")]
    pub log_level: tracing::Level,

    /// Enable metrics collection
    #[serde(default = "default_true")]
    pub enable_metrics: bool,

    /// Endpoint for metrics (default: /metrics)
    #[serde(default = "default_metrics_endpoint")]
    pub metrics_endpoint: String,

    /// Enable distributed tracing
    #[serde(default = "default_true")]
    pub enable_tracing: bool,

    /// Enable structured logging (JSON format)
    #[serde(default = "default_true")]
    pub structured_logging: bool,

    /// Optional path to log file (if not set, logs to stderr)
    pub log_file: Option<String>,

    /// Port for metrics server
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

/// Feature flags and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Enable user registration
    #[serde(default = "default_true")]
    pub enable_registration: bool,

    /// Enable password reset functionality
    #[serde(default = "default_true")]
    pub enable_password_reset: bool,

    /// Require email verification for new accounts
    #[serde(default = "default_false")]
    pub enable_email_verification: bool,

    /// Enable multi-factor authentication
    #[serde(default = "default_false")]
    pub enable_multi_factor_auth: bool,

    /// Enable API documentation (OpenAPI/Swagger)
    #[serde(default = "default_true")]
    pub enable_api_docs: bool,

    /// Enable metrics endpoint
    #[serde(default = "default_true")]
    pub enable_metrics: bool,

    /// Enable health check endpoints
    #[serde(default = "default_true")]
    pub enable_health_checks: bool,

    /// Enable rate limiting
    #[serde(default = "default_true")]
    pub enable_rate_limiting: bool,

    /// Enable response caching
    #[serde(default = "default_true")]
    pub enable_caching: bool,

    /// Enable response compression
    #[serde(default = "default_true")]
    pub enable_compression: bool,

    /// Enable CORS
    #[serde(default = "default_true")]
    pub enable_cors: bool,
}

impl AppConfig {
    /// Load configuration from environment variables with sensible defaults
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        // Server configuration
        if let Ok(host) = env::var("HOST") {
            config.server.host = host;
        }

        if let Ok(port) = env::var("PORT") {
            config.server.port = port
                .parse()
                .map_err(|_| AuthencError::validation("Invalid PORT"))?;
        }

        if let Ok(workers) = env::var("WORKERS") {
            config.server.workers = Some(
                workers
                    .parse()
                    .map_err(|_| AuthencError::validation("Invalid WORKERS"))?,
            );
        }

        // TLS configuration
        if let Ok(tls_enabled) = env::var("TLS_ENABLED") {
            config.server.tls_enabled = tls_enabled.parse().unwrap_or(false);
        }

        if let Ok(cert_path) = env::var("TLS_CERT_PATH") {
            config.server.tls_cert_path = Some(cert_path);
        }

        if let Ok(key_path) = env::var("TLS_KEY_PATH") {
            config.server.tls_key_path = Some(key_path);
        }

        // Database configuration
        if let Ok(db_url) = env::var("DATABASE_URL") {
            // Parse database URL if provided
            // Format: postgres://username:password@host:port/database
            if let Ok(url) = url::Url::parse(&db_url) {
                if let Some(host) = url.host_str() {
                    config.database.host = host.to_string();
                }
                if let Some(port) = url.port() {
                    config.database.port = port;
                }
                if !url.username().is_empty() {
                    config.database.username = url.username().to_string();
                }
                if let Some(password) = url.password() {
                    config.database.password = password.to_string();
                }
                if let Some(mut segments) = url.path_segments() {
                    if let Some(db) = segments.next() {
                        config.database.database = db.trim_start_matches('/').to_string();
                    }
                }
            }
        }

        // Security configuration
        if let Ok(secret) = env::var("JWT_SECRET") {
            config.security.jwt_secret = secret;
        }

        if let Ok(allow_origins) = env::var("CORS_ALLOWED_ORIGINS") {
            config.server.cors_allowed_origins = allow_origins
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }

        // Observability configuration
        if let Ok(log_level) = env::var("LOG_LEVEL") {
            if let Ok(level) = log_level.parse::<Level>() {
                config.observability.log_level = level;
            }
        }

        // Feature flags
        if let Ok(features) = env::var("ENABLED_FEATURES") {
            for feature in features.split(',') {
                match feature.trim() {
                    "api_docs" => config.features.enable_api_docs = true,
                    "metrics" => config.features.enable_metrics = true,
                    "health_checks" => config.features.enable_health_checks = true,
                    _ => {}
                }
            }
        }

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(AuthencError::validation("Server port cannot be 0"));
        }

        // Validate TLS configuration if enabled
        if self.server.tls_enabled {
            if self.server.tls_cert_path.is_none() || self.server.tls_key_path.is_none() {
                return Err(AuthencError::validation(
                    "TLS certificate and key paths are required when TLS is enabled",
                ));
            }

            // Check if certificate and key files exist
            if let (Some(cert_path), Some(key_path)) =
                (&self.server.tls_cert_path, &self.server.tls_key_path)
            {
                if !PathBuf::from(cert_path).exists() {
                    return Err(AuthencError::validation("TLS certificate file not found"));
                }
                if !PathBuf::from(key_path).exists() {
                    return Err(AuthencError::validation("TLS key file not found"));
                }
            }
        }

        // Validate database configuration
        if self.database.host.is_empty() {
            return Err(AuthencError::validation("Database host cannot be empty"));
        }

        if self.database.database.is_empty() {
            return Err(AuthencError::validation("Database name cannot be empty"));
        }

        // Validate security configuration
        if self.security.jwt_secret.is_empty() {
            return Err(AuthencError::validation("JWT secret cannot be empty"));
        }

        if self.security.password_min_length < 8 {
            return Err(AuthencError::validation(
                "Password minimum length must be at least 8 characters",
            ));
        }

        Ok(())
    }

    /// Get the server socket address
    pub fn server_addr(&self) -> SocketAddr {
        format!("{}:{}", self.server.host, self.server.port)
            .parse()
            .expect("Invalid server address")
    }

    /// Get the database connection string
    pub fn database_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.database.username,
            self.database.password,
            self.database.host,
            self.database.port,
            self.database.database
        )
    }

    /// Get the keep-alive duration
    pub fn keep_alive(&self) -> Duration {
        Duration::from_secs(self.server.keep_alive)
    }

    /// Get the client timeout duration
    pub fn client_timeout(&self) -> Duration {
        Duration::from_secs(self.server.client_timeout)
    }

    /// Get the client disconnect timeout duration
    pub fn client_disconnect_timeout(&self) -> Duration {
        Duration::from_secs(self.server.client_disconnect_timeout)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
                workers: None,
                keep_alive: default_keep_alive(),
                client_timeout: default_client_timeout(),
                client_disconnect_timeout: default_client_disconnect_timeout(),
                max_connections: default_max_connections(),
                public_prefix: default_public_prefix(),
                admin_prefix: default_admin_prefix(),
                internal_prefix: default_internal_prefix(),
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
                cors_allowed_origins: default_cors_origins(),
            },
            database: DatabaseConfig {
                host: "localhost".to_string(),
                port: 5432,
                username: "postgres".to_string(),
                password: "postgres".to_string(),
                database: "authenc".to_string(),
                max_connections: 10,
                connection_timeout: 30,
                audit_log_url: None,
                connection_timeout_seconds: 30,
            },
            security: SecurityConfig {
                jwt_secret: env::var("JWT_SECRET")
                    .unwrap_or_else(|_| "default_jwt_secret_change_in_production".to_string()),
                jwt_expiry: default_jwt_expiry(),
                password_min_length: default_password_min_length(),
                rate_limit_requests: default_rate_limit_requests(),
                rate_limit_window: default_rate_limit_window(),
                brute_force_max_attempts: default_brute_force_max_attempts(),
                brute_force_window_seconds: default_brute_force_window(),
                rate_limit_requests_per_minute: default_rate_limit_per_minute(),
                password_salt_rounds: default_password_salt_rounds(),
            },
            observability: ObservabilityConfig {
                log_level: default_log_level(),
                enable_metrics: true,
                metrics_endpoint: default_metrics_endpoint(),
                enable_tracing: true,
                structured_logging: true,
                log_file: None,
                metrics_port: default_metrics_port(),
            },
            features: FeatureConfig {
                enable_registration: true,
                enable_password_reset: true,
                enable_email_verification: false,
                enable_multi_factor_auth: false,
                enable_api_docs: true,
                enable_metrics: true,
                enable_health_checks: true,
                enable_rate_limiting: true,
                enable_caching: true,
                enable_compression: true,
                enable_cors: true,
            },
            rate_limit: RateLimitConfig::default(),
            oidc: None,
            saml: None,
            ui: None,
            multi_db: None,
            secreton: None,
        }
    }
}

// Default value helpers
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}

fn default_log_level() -> Level {
    Level::INFO
}
fn default_metrics_endpoint() -> String {
    "/metrics".to_string()
}
fn default_metrics_port() -> u16 {
    9090
}

fn default_jwt_expiry() -> u64 {
    3600
} // 1 hour
fn default_password_min_length() -> u8 {
    8
}
fn default_rate_limit_requests() -> u32 {
    100
}
fn default_rate_limit_window() -> u64 {
    60
} // 1 minute
fn default_brute_force_max_attempts() -> u32 {
    5
}
fn default_brute_force_window() -> u64 {
    300
} // 5 minutes
fn default_rate_limit_per_minute() -> u32 {
    60
}
fn default_password_salt_rounds() -> u32 {
    10
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.host, "localhost");
        assert_eq!(config.database.port, 5432);
    }

    #[test]
    #[serial]
    fn test_from_env() {
        temp_env::with_vars(
            vec![
                ("HOST", Some("127.0.0.1")),
                ("PORT", Some("4000")),
                ("JWT_SECRET", Some("test_secret")),
            ],
            || {
                let config = AppConfig::from_env().unwrap();
                assert_eq!(config.server.host, "127.0.0.1");
                assert_eq!(config.server.port, 4000);
                assert_eq!(config.security.jwt_secret, "test_secret");
            },
        );
    }

    #[test]
    #[serial]
    fn test_validation() {
        let mut config = AppConfig::default();

        // Test valid config
        assert!(config.validate().is_ok());

        // Test invalid port
        config.server.port = 0;
        assert!(config.validate().is_err());
        config.server.port = 3000;

        // Test empty database host
        let old_host = config.database.host.clone();
        config.database.host = String::new();
        assert!(config.validate().is_err());
        config.database.host = old_host;

        // Test empty JWT secret
        let old_secret = config.security.jwt_secret.clone();
        config.security.jwt_secret = String::new();
        assert!(config.validate().is_err());
        config.security.jwt_secret = old_secret;
    }
}

/// Serde module for log level serialization
mod log_level_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tracing::Level;

    pub fn serialize<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let level_str = match *level {
            Level::TRACE => "trace",
            Level::DEBUG => "debug",
            Level::INFO => "info",
            Level::WARN => "warn",
            Level::ERROR => "error",
        };
        level_str.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: Deserializer<'de>,
    {
        let level_str = String::deserialize(deserializer)?;
        match level_str.to_lowercase().as_str() {
            "trace" => Ok(Level::TRACE),
            "debug" => Ok(Level::DEBUG),
            "info" => Ok(Level::INFO),
            "warn" => Ok(Level::WARN),
            "error" => Ok(Level::ERROR),
            _ => Err(serde::de::Error::custom(format!(
                "Invalid log level: {}",
                level_str
            ))),
        }
    }
}
