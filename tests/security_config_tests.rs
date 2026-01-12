#[cfg(test)]
mod tests {
    use authenc::config::AppConfig;
    use temp_env;

    #[test]
    fn test_jwt_secret_validation_production() {
        temp_env::with_vars(
            vec![
                ("APP_ENV", Some("production")),
                ("JWT_SECRET", Some("default_jwt_secret_change_in_production")),
            ],
            || {
                let config = AppConfig::from_env();
                assert!(config.is_err(), "Should fail validation in production with default secret");

                if let Err(e) = config {
                    assert!(e.to_string().contains("Security Risk"));
                }
            },
        );
    }

    #[test]
    fn test_jwt_secret_validation_development() {
        temp_env::with_vars(
            vec![
                ("APP_ENV", Some("development")),
                ("JWT_SECRET", Some("default_jwt_secret_change_in_production")),
            ],
            || {
                let config = AppConfig::from_env();
                assert!(config.is_ok(), "Should pass validation in development with default secret (but warn)");
            },
        );
    }

    #[test]
    fn test_jwt_secret_validation_custom_secret() {
        temp_env::with_vars(
            vec![
                ("APP_ENV", Some("production")),
                ("JWT_SECRET", Some("my-super-secret-production-key-12345")),
            ],
            || {
                let config = AppConfig::from_env();
                assert!(config.is_ok(), "Should pass validation with custom secret");
            },
        );
    }
}
