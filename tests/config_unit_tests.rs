use authenc::config::*;
use serial_test::serial;
use temp_env;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_config_default() {
        let config = OidcConfig::default();
        assert_eq!(config.issuer, "");
        assert_eq!(config.client_id, "");
        assert_eq!(config.client_secret, "");
        assert_eq!(config.redirect_uri, "");
    }

    #[test]
    fn test_saml_config_default() {
        let config = SamlConfig::default();
        assert_eq!(config.entity_id, "");
        assert_eq!(config.sso_url, "");
        assert_eq!(config.certificate, "");
    }

    #[test]
    fn test_ui_config_default() {
        let config = UiConfig::default();
        assert!(!config.enabled);
        assert!(config.theme.is_none());
    }

    #[test]
    fn test_multi_db_config_default() {
        let config = MultiDbConfig::default();
        assert!(!config.enabled);
        assert!(config.db_urls.is_empty());
    }

    #[test]
    fn test_secreton_config_creation() {
        let config = SecretonConfig {
            endpoint: "https://secreton.example.com".to_string(),
            token: "secret-token".to_string(),
        };
        assert_eq!(config.endpoint, "https://secreton.example.com");
        assert_eq!(config.token, "secret-token");
    }

    #[test]
    fn test_kafka_config_default() {
        let config = KafkaConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.brokers, "");
        assert_eq!(config.audit_topic, "");
        assert_eq!(config.user_events_topic, "");
        assert_eq!(config.admin_events_topic, "");
        assert!(config.client_id.is_none());
        assert!(config.message_timeout_ms.is_none());
        assert!(config.compression.is_none());
    }

    #[test]
    fn test_events_config_default() {
        let config = EventsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.user_event_retention_days, 90);
        assert_eq!(config.admin_event_retention_days, 365);
        assert_eq!(config.max_cleanup_batch_size, 10000);
        assert_eq!(config.cleanup_interval_hours, 24);
        assert!(!config.archive_before_delete);
        assert!(config.archive_directory.is_none());
    }

    #[test]
    fn test_server_config_creation() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: Some(8),
            keep_alive: 60,
            client_timeout: 20,
            client_disconnect_timeout: 2,
            max_connections: 200,
            public_prefix: "/api".to_string(),
            admin_prefix: "/management".to_string(),
            internal_prefix: "/system".to_string(),
            tls_enabled: true,
            tls_cert_path: Some("/path/to/cert.pem".to_string()),
            tls_key_path: Some("/path/to/key.pem".to_string()),
            cors_allowed_origins: vec!["https://example.com".to_string()],
            base_url: "https://auth.example.com".to_string(),
        };
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.workers, Some(8));
        assert_eq!(config.keep_alive, 60);
        assert_eq!(config.client_timeout, 20);
        assert_eq!(config.client_disconnect_timeout, 2);
        assert_eq!(config.max_connections, 200);
        assert_eq!(config.public_prefix, "/api");
        assert_eq!(config.admin_prefix, "/management");
        assert_eq!(config.internal_prefix, "/system");
        assert!(config.tls_enabled);
        assert_eq!(config.tls_cert_path, Some("/path/to/cert.pem".to_string()));
        assert_eq!(config.tls_key_path, Some("/path/to/key.pem".to_string()));
        assert_eq!(
            config.cors_allowed_origins,
            vec!["https://example.com".to_string()]
        );
    }

    #[test]
    fn test_database_config_creation() {
        let config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "password".to_string(),
            database: "authenc".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            audit_log_url: Some("postgres://audit:pass@localhost:5432/audit".to_string()),
            connection_timeout_seconds: 30,
        };
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.username, "postgres");
        assert_eq!(config.password, "password");
        assert_eq!(config.database, "authenc");
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.connection_timeout, 30);
        assert_eq!(
            config.audit_log_url,
            Some("postgres://audit:pass@localhost:5432/audit".to_string())
        );
        assert_eq!(config.connection_timeout_seconds, 30);
    }

    #[test]
    fn test_basic_security_config_default() {
        let config = BasicSecurityConfig::default();
        assert_eq!(config.jwt_secret, "default_jwt_secret_change_in_production");
        assert_eq!(config.jwt_expiry, 3600);
        assert_eq!(config.password_min_length, 8);
        assert_eq!(config.rate_limit_requests, 100);
        assert_eq!(config.rate_limit_window, 60);
        assert_eq!(config.brute_force_max_attempts, 5);
        assert_eq!(config.brute_force_window_seconds, 300);
        assert_eq!(config.rate_limit_requests_per_minute, 60);
        assert_eq!(config.password_salt_rounds, 10);
    }

    #[test]
    fn test_observability_config_creation() {
        let config = ObservabilityConfig {
            log_level: tracing::Level::DEBUG,
            enable_metrics: false,
            metrics_endpoint: "/custom-metrics".to_string(),
            enable_tracing: false,
            structured_logging: false,
            log_file: Some("/var/log/app.log".to_string()),
            metrics_port: 8080,
            db_check_active_connections: 10,
        };
        assert_eq!(config.log_level, tracing::Level::DEBUG);
        assert!(!config.enable_metrics);
        assert_eq!(config.metrics_endpoint, "/custom-metrics");
        assert!(!config.enable_tracing);
        assert!(!config.structured_logging);
        assert_eq!(config.log_file, Some("/var/log/app.log".to_string()));
        assert_eq!(config.metrics_port, 8080);
    }

    #[test]
    fn test_feature_config_creation() {
        let config = FeatureConfig {
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
            enable_input_validation: true,
        };
        assert!(config.enable_registration);
        assert!(config.enable_password_reset);
        assert!(!config.enable_email_verification);
        assert!(!config.enable_multi_factor_auth);
        assert!(config.enable_api_docs);
        assert!(config.enable_metrics);
        assert!(config.enable_health_checks);
        assert!(config.enable_rate_limiting);
        assert!(config.enable_caching);
        assert!(config.enable_compression);
        assert!(config.enable_cors);
        assert!(config.enable_input_validation);
    }

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.host, "localhost");
        assert_eq!(config.database.port, 5432);
        assert_eq!(config.database.username, "postgres");
        assert_eq!(config.database.password, "postgres");
        assert_eq!(config.database.database, "authenc");
        assert_eq!(
            config.security.jwt_secret,
            "default_jwt_secret_change_in_production"
        );
        assert_eq!(config.observability.log_level, tracing::Level::INFO);
        assert!(config.features.enable_registration);
        assert!(config.events.user_event_retention_days == 90);
    }

    #[test]
    fn test_app_config_server_addr() {
        let config = AppConfig::default();
        let addr = config.server_addr();
        assert_eq!(addr.to_string(), "0.0.0.0:3000");
    }

    #[test]
    fn test_app_config_database_url() {
        let config = AppConfig::default();
        let url = config.database_url();
        assert_eq!(url, "postgres://postgres:postgres@localhost:5432/authenc");
    }

    #[test]
    fn test_app_config_timeouts() {
        let config = AppConfig::default();
        assert_eq!(config.keep_alive().as_secs(), 75);
        assert_eq!(config.client_timeout().as_secs(), 30);
        assert_eq!(config.client_disconnect_timeout().as_secs(), 5);
    }

    #[test]
    fn test_app_config_validation_valid() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_app_config_validation_invalid_port() {
        let mut config = AppConfig::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_config_validation_empty_db_host() {
        let mut config = AppConfig::default();
        config.database.host = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_config_validation_empty_db_name() {
        let mut config = AppConfig::default();
        config.database.database = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_config_validation_empty_jwt_secret() {
        let mut config = AppConfig::default();
        config.security.jwt_secret = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_config_validation_short_password() {
        let mut config = AppConfig::default();
        config.security.password_min_length = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_config_validation_tls_missing_files() {
        let mut config = AppConfig::default();
        config.server.tls_enabled = true;
        // Missing cert and key paths
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_config_validation_invalid_base_url() {
        let mut config = AppConfig::default();
        config.server.base_url = "not-a-valid-url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    #[serial]
    fn test_app_config_from_env_basic() {
        temp_env::with_vars(
            vec![
                ("HOST", Some("127.0.0.1")),
                ("PORT", Some("4000")),
                ("WORKERS", Some("4")),
                ("JWT_SECRET", Some("test_secret")),
                (
                    "CORS_ALLOWED_ORIGINS",
                    Some("https://example.com,https://app.example.com"),
                ),
                ("LOG_LEVEL", Some("debug")),
            ],
            || {
                let config = AppConfig::from_env().unwrap();
                assert_eq!(config.server.host, "127.0.0.1");
                assert_eq!(config.server.port, 4000);
                assert_eq!(config.server.workers, Some(4));
                assert_eq!(config.security.jwt_secret, "test_secret");
                assert_eq!(
                    config.server.cors_allowed_origins,
                    vec![
                        "https://example.com".to_string(),
                        "https://app.example.com".to_string()
                    ]
                );
                assert_eq!(config.observability.log_level, tracing::Level::DEBUG);
            },
        );
    }

    #[test]
    #[serial]
    fn test_app_config_from_env_database_url() {
        temp_env::with_vars(
            vec![(
                "DATABASE_URL",
                Some("postgres://user:pass@db.example.com:5433/myapp"),
            )],
            || {
                let config = AppConfig::from_env().unwrap();
                assert_eq!(config.database.host, "db.example.com");
                assert_eq!(config.database.port, 5433);
                assert_eq!(config.database.username, "user");
                assert_eq!(config.database.password, "pass");
                assert_eq!(config.database.database, "myapp");
            },
        );
    }

    #[test]
    #[serial]
    fn test_app_config_from_env_features() {
        temp_env::with_vars(
            vec![("ENABLED_FEATURES", Some("api_docs,metrics,health_checks"))],
            || {
                let config = AppConfig::from_env().unwrap();
                assert!(config.features.enable_api_docs);
                assert!(config.features.enable_metrics);
                assert!(config.features.enable_health_checks);
            },
        );
    }

    #[test]
    fn test_security_middleware_config_secure_defaults() {
        let config = SecurityMiddlewareConfig::secure_defaults();
        assert!(config.headers.enabled);
        assert_eq!(config.headers.hsts_max_age, 31536000);
        assert!(config.headers.hsts_include_subdomains);
        assert!(config.headers.hsts_preload);
        assert!(config.csrf.enabled);
    }

    #[test]
    fn test_security_middleware_config_development_defaults() {
        let config = SecurityMiddlewareConfig::development_defaults();
        assert!(config.headers.enabled);
        assert_eq!(config.headers.hsts_max_age, 0);
        assert!(!config.headers.hsts_include_subdomains);
        assert!(!config.headers.hsts_preload);
        assert!(!config.csrf.enabled);
    }

    #[test]
    fn test_security_headers_config_secure() {
        let config = SecurityHeadersConfig::secure();
        assert!(config.enabled);
        assert_eq!(config.hsts_max_age, 31536000);
        assert!(config.hsts_include_subdomains);
        assert!(config.hsts_preload);
        assert!(config.csp_directives.len() > 0);
        assert!(
            config
                .csp_directives
                .contains(&"default-src 'self'".to_string())
        );
    }

    #[test]
    fn test_security_headers_config_development() {
        let config = SecurityHeadersConfig::development();
        assert!(config.enabled);
        assert_eq!(config.hsts_max_age, 0);
        assert!(!config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert!(
            config
                .csp_directives
                .contains(&"default-src 'self' 'unsafe-inline' 'unsafe-eval'".to_string())
        );
    }

    #[test]
    fn test_observability_config_serialization() {
        let config = ObservabilityConfig {
            log_level: tracing::Level::DEBUG,
            enable_metrics: true,
            metrics_endpoint: "/metrics".to_string(),
            enable_tracing: true,
            structured_logging: true,
            log_file: Some("/var/log/app.log".to_string()),
            metrics_port: 9090,
            db_check_active_connections: 5,
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: ObservabilityConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.log_level, tracing::Level::DEBUG);
        assert!(deserialized.enable_metrics);
        assert_eq!(deserialized.metrics_endpoint, "/metrics");
        assert!(deserialized.enable_tracing);
        assert!(deserialized.structured_logging);
        assert_eq!(deserialized.log_file, Some("/var/log/app.log".to_string()));
        assert_eq!(deserialized.metrics_port, 9090);
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&serialized).unwrap();

        // Test a few key fields
        assert_eq!(deserialized.server.host, config.server.host);
        assert_eq!(deserialized.server.port, config.server.port);
        assert_eq!(deserialized.database.host, config.database.host);
        assert_eq!(deserialized.security.jwt_secret, config.security.jwt_secret);
    }

    #[test]
    fn test_events_config_serialization() {
        let config = EventsConfig {
            enabled: true,
            user_event_retention_days: 120,
            admin_event_retention_days: 500,
            max_cleanup_batch_size: 5000,
            cleanup_interval_hours: 12,
            archive_before_delete: true,
            archive_directory: Some("/var/log/archive".to_string()),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: EventsConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.enabled, true);
        assert_eq!(deserialized.user_event_retention_days, 120);
        assert_eq!(deserialized.admin_event_retention_days, 500);
        assert_eq!(deserialized.max_cleanup_batch_size, 5000);
        assert_eq!(deserialized.cleanup_interval_hours, 12);
        assert!(deserialized.archive_before_delete);
        assert_eq!(
            deserialized.archive_directory,
            Some("/var/log/archive".to_string())
        );
    }
}
