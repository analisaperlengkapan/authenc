#[cfg(test)]
mod tests {
    use authenc::spi::admin_console::*;
    use authenc::spi::{ProviderConfig, ProviderFactory, Spi};

    #[test]
    fn test_admin_console_spi() {
        let spi = AdminConsoleSpi;
        assert_eq!(spi.get_name(), "admin-console");
        assert!(!spi.is_internal());
        assert_eq!(
            spi.get_provider_class(),
            "io.authenc.adminconsole.AdminConsoleProvider"
        );
        assert_eq!(
            spi.get_provider_factory_class(),
            "io.authenc.adminconsole.AdminConsoleProviderFactory"
        );
    }

    #[test]
    fn test_admin_console_config_default() {
        let config = AdminConsoleConfig::default();
        assert!(config.enabled);
        assert_eq!(config.base_url, "/admin");
        assert_eq!(config.theme, "authenc");
        assert_eq!(config.locale, "en");
        assert!(config.features.contains(&"users".to_string()));
    }

    #[test]
    fn test_default_admin_console_provider() {
        let config = AdminConsoleConfig::default();
        let provider = DefaultAdminConsoleProvider::new(config);

        assert!(provider.is_enabled());
        assert_eq!(provider.get_base_url(), "/admin");
        assert_eq!(provider.get_theme(), "authenc");
        assert_eq!(provider.get_locale(), "en");
        assert!(
            provider
                .get_supported_features()
                .contains(&AdminConsoleFeature::Users)
        );
    }

    #[tokio::test]
    async fn test_default_admin_console_provider_factory() {
        let factory = DefaultAdminConsoleProviderFactory::new();
        let config = ProviderConfig::default();

        let result = factory.create(&config);
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert!(provider.is_enabled());
    }
}
