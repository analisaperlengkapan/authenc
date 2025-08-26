
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SamlConfig {
    pub entity_id: String,
    pub sso_url: String,
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

use crate::error::{AuthencError, Result};
use serde::{Deserialize, Serialize};
use std::env;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub observability: ObservabilityConfig,
    pub features: FeatureConfig,
    // OIDC/SAML/DB/UI stub configs
    pub oidc: Option<OidcConfig>,
    pub saml: Option<SamlConfig>,
    pub ui: Option<UiConfig>,
    pub multi_db: Option<MultiDbConfig>,
    pub secreton: Option<SecretonConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
    pub max_connections: usize,
    // TLS/mTLS
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub tls_enable: bool,
    pub mtls_enable: bool,
    pub tls_truststore_file: Option<String>,
    pub tls_truststore_password: Option<String>,
        // Endpoint separation
        pub public_prefix: String,
        pub admin_prefix: String,
        pub internal_prefix: String,
    }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub audit_log_url: Option<String>,
    pub connection_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub jwt_expiry: u64,
    pub password_min_length: usize,
    pub rate_limit_requests: u32,
    pub rate_limit_window: u64,
    pub brute_force_max_attempts: u32,
    pub brute_force_window_seconds: u64,
    pub rate_limit_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub enable_metrics: bool,
    pub metrics_endpoint: String,
    pub enable_tracing: bool,
    pub metrics_enabled: bool,
    pub structured_logging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    pub enable_totp: bool,
    pub enable_federation: bool,
    pub enable_audit_logging: bool,
    pub enable_rate_limiting: bool,
        // Feature flags
        pub enable_oidc: bool,
        pub enable_saml: bool,
        pub enable_ui: bool,
        pub enable_multi_db: bool,
    }

impl AppConfig {
    /// Load configuration from environment variables with sensible defaults
    pub fn from_env() -> Result<Self> {
        let features = FeatureConfig {
            enable_totp: env::var("ENABLE_TOTP").unwrap_or_else(|_| "true".to_string()).parse().unwrap_or(true),
            enable_federation: env::var("ENABLE_FEDERATION").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            enable_audit_logging: env::var("ENABLE_AUDIT_LOGGING").unwrap_or_else(|_| "true".to_string()).parse().unwrap_or(true),
            enable_rate_limiting: env::var("ENABLE_RATE_LIMITING").unwrap_or_else(|_| "true".to_string()).parse().unwrap_or(true),
            enable_oidc: env::var("ENABLE_OIDC").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            enable_saml: env::var("ENABLE_SAML").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            enable_ui: env::var("ENABLE_UI").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            enable_multi_db: env::var("ENABLE_MULTI_DB").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        };
        Ok(Self {
            server: ServerConfig {
                host: env::var("AUTHENC_HOST").or_else(|_| env::var("AUTHENCE_HOST")).unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("AUTHENC_PORT").or_else(|_| env::var("AUTHENCE_PORT")).unwrap_or_else(|_| "8080".to_string()).parse()?,
                workers: env::var("AUTHENC_WORKERS").or_else(|_| env::var("AUTHENCE_WORKERS")).ok().and_then(|w| w.parse().ok()),
                max_connections: env::var("AUTHENC_MAX_CONNECTIONS").or_else(|_| env::var("AUTHENCE_MAX_CONNECTIONS")).unwrap_or_else(|_| "1000".to_string()).parse()?,
                tls_cert_file: env::var("TLS_CERT_FILE").ok(),
                tls_key_file: env::var("TLS_KEY_FILE").ok(),
                tls_enable: env::var("TLS_ENABLE").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
                mtls_enable: env::var("MTLS_ENABLE").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
                tls_truststore_file: env::var("TLS_TRUSTSTORE_FILE").ok(),
                tls_truststore_password: env::var("TLS_TRUSTSTORE_PASSWORD").ok(),
                public_prefix: env::var("PUBLIC_PREFIX").unwrap_or_else(|_| "/api/public".to_string()),
                admin_prefix: env::var("ADMIN_PREFIX").unwrap_or_else(|_| "/api/admin".to_string()),
                internal_prefix: env::var("INTERNAL_PREFIX").unwrap_or_else(|_| "/api/internal".to_string()),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/authenc".to_string()),
                max_connections: env::var("DATABASE_MAX_CONNECTIONS").unwrap_or_else(|_| "10".to_string()).parse().unwrap_or(10),
                connection_timeout: env::var("DATABASE_CONNECTION_TIMEOUT").unwrap_or_else(|_| "30".to_string()).parse().unwrap_or(30),
                audit_log_url: env::var("AUDIT_LOG_URL").ok(),
                connection_timeout_seconds: env::var("DATABASE_CONNECTION_TIMEOUT_SECONDS").unwrap_or_else(|_| "30".to_string()).parse().unwrap_or(30),
            },
            security: SecurityConfig {
                jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret".to_string()),
                jwt_expiry: env::var("JWT_EXPIRY").unwrap_or_else(|_| "3600".to_string()).parse().unwrap_or(3600),
                password_min_length: env::var("PASSWORD_MIN_LENGTH").unwrap_or_else(|_| "8".to_string()).parse().unwrap_or(8),
                rate_limit_requests: env::var("RATE_LIMIT_REQUESTS").unwrap_or_else(|_| "100".to_string()).parse().unwrap_or(100),
                rate_limit_window: env::var("RATE_LIMIT_WINDOW").unwrap_or_else(|_| "60".to_string()).parse().unwrap_or(60),
                brute_force_max_attempts: env::var("BRUTE_FORCE_MAX_ATTEMPTS").unwrap_or_else(|_| "5".to_string()).parse().unwrap_or(5),
                brute_force_window_seconds: env::var("BRUTE_FORCE_WINDOW_SECONDS").unwrap_or_else(|_| "300".to_string()).parse().unwrap_or(300),
                rate_limit_requests_per_minute: env::var("RATE_LIMIT_REQUESTS_PER_MINUTE").unwrap_or_else(|_| "60".to_string()).parse().unwrap_or(60),
            },
            observability: ObservabilityConfig {
                log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
                enable_metrics: env::var("ENABLE_METRICS").unwrap_or_else(|_| "true".to_string()).parse().unwrap_or(true),
                metrics_endpoint: env::var("METRICS_ENDPOINT").unwrap_or_else(|_| "/metrics".to_string()),
                enable_tracing: env::var("ENABLE_TRACING").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
                metrics_enabled: env::var("METRICS_ENABLED").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
                structured_logging: env::var("STRUCTURED_LOGGING").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
            },
            features: features.clone(),
            oidc: if features.enable_oidc {
                Some(OidcConfig {
                    issuer: env::var("OIDC_ISSUER").unwrap_or_default(),
                    client_id: env::var("OIDC_CLIENT_ID").unwrap_or_default(),
                    client_secret: env::var("OIDC_CLIENT_SECRET").unwrap_or_default(),
                    redirect_uri: env::var("OIDC_REDIRECT_URI").unwrap_or_default(),
                })
            } else { None },
            saml: if features.enable_saml {
                Some(SamlConfig {
                    entity_id: env::var("SAML_ENTITY_ID").unwrap_or_default(),
                    sso_url: env::var("SAML_SSO_URL").unwrap_or_default(),
                    certificate: env::var("SAML_CERTIFICATE").unwrap_or_default(),
                })
            } else { None },
            ui: if features.enable_ui {
                Some(UiConfig {
                    enabled: true,
                    theme: env::var("UI_THEME").ok(),
                })
            } else { None },
            multi_db: if features.enable_multi_db {
                Some(MultiDbConfig {
                    enabled: true,
                    db_urls: env::var("MULTI_DB_URLS").map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
                })
            } else { None },
            secreton: None,
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.security.jwt_secret == "your-secret-key-change-in-production" {
            log::warn!("⚠️  Using default JWT secret key. Change this in production!");
        }

        if self.security.password_min_length < 8 {
            return Err(AuthencError::ConfigurationError { 
                message: "Password minimum length must be at least 8 characters".to_string() 
            });
        }

        if self.server.port == 0 {
            return Err(AuthencError::ConfigurationError { 
                message: "Server port cannot be 0".to_string() 
            });
        }

        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::from_env().unwrap_or_else(|_| AppConfig {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                workers: None,
                max_connections: 1000,
                tls_cert_file: None,
                tls_key_file: None,
                tls_enable: false,
                mtls_enable: false,
                tls_truststore_file: None,
                tls_truststore_password: None,
                public_prefix: "/api/public".to_string(),
                admin_prefix: "/api/admin".to_string(),
                internal_prefix: "/api/internal".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://postgres:postgres@localhost:5432/authenc".to_string(),
                max_connections: 10,
                connection_timeout: 30,
                audit_log_url: None,
                connection_timeout_seconds: 30,
            },
            security: SecurityConfig {
                jwt_secret: "default-secret-change-me".to_string(),
                jwt_expiry: 3600,
                password_min_length: 8,
                rate_limit_requests: 100,
                rate_limit_window: 60,
                brute_force_max_attempts: 5,
                brute_force_window_seconds: 300,
                rate_limit_requests_per_minute: 60,
            },
            observability: ObservabilityConfig {
                log_level: "info".to_string(),
                enable_metrics: true,
                metrics_endpoint: "/metrics".to_string(),
                enable_tracing: true,
                metrics_enabled: true,
                structured_logging: true,
            },
            features: FeatureConfig {
                enable_totp: true,
                enable_federation: true,
                enable_audit_logging: true,
                enable_rate_limiting: true,
                enable_oidc: false,
                enable_saml: false,
                enable_ui: false,
                enable_multi_db: false,
            },
            oidc: None,
            saml: None,
            ui: None,
            multi_db: None,
            secreton: None,
        })
    }
}
