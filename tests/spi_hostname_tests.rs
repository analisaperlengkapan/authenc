#[cfg(test)]
mod tests {
    use authenc::spi::hostname::*;
    use authenc::spi::{Provider, ProviderConfig, ProviderFactory, Spi};
    use std::any::Any;

    #[test]
    fn test_hostname_spi() {
        let spi = HostnameSpi::new();
        assert_eq!(spi.get_name(), "hostname");
        assert!(!spi.is_internal());
        assert_eq!(
            spi.get_provider_class(),
            "org.keycloak.protocol.hostname.HostnameProvider"
        );
        assert_eq!(
            spi.get_provider_factory_class(),
            "org.keycloak.protocol.hostname.HostnameProviderFactory"
        );
    }

    #[test]
    fn test_hostname_config_default() {
        let config = HostnameConfig::default();
        assert!(config.hostname.is_none());
        assert!(!config.use_request_hostname);
        assert!(config.frontend_url.is_none());
        assert!(!config.hostname_required);
        assert!(config.admin_url.is_none());
    }

    #[test]
    fn test_hostname_config_creation() {
        let config = HostnameConfig {
            hostname: Some("example.com".to_string()),
            use_request_hostname: true,
            frontend_url: Some("https://example.com".to_string()),
            hostname_required: true,
            admin_url: Some("https://admin.example.com".to_string()),
        };

        assert_eq!(config.hostname, Some("example.com".to_string()));
        assert!(config.use_request_hostname);
        assert_eq!(config.frontend_url, Some("https://example.com".to_string()));
        assert!(config.hostname_required);
        assert_eq!(
            config.admin_url,
            Some("https://admin.example.com".to_string())
        );
    }

    #[test]
    fn test_hostname_resolution_creation() {
        let resolution = HostnameResolution {
            hostname: "example.com".to_string(),
            frontend_url: Some("https://example.com".to_string()),
            admin_url: Some("https://admin.example.com".to_string()),
            fixed: true,
        };

        assert_eq!(resolution.hostname, "example.com");
        assert_eq!(
            resolution.frontend_url,
            Some("https://example.com".to_string())
        );
        assert_eq!(
            resolution.admin_url,
            Some("https://admin.example.com".to_string())
        );
        assert!(resolution.fixed);
    }

    #[test]
    fn test_extract_hostname_from_uri() {
        // Test various URI formats
        assert_eq!(
            extract_hostname_from_uri("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_hostname_from_uri("http://example.com:8080/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_hostname_from_uri("https://sub.example.com"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            extract_hostname_from_uri("http://localhost:3000"),
            Some("localhost".to_string())
        );
        assert_eq!(extract_hostname_from_uri("invalid-uri"), None);
        assert_eq!(extract_hostname_from_uri(""), None);
    }

    #[test]
    fn test_default_hostname_provider() {
        let provider = DefaultHostnameProvider::new();
        // Provider should be created successfully
        assert!(true); // This is just a basic instantiation test
    }

    #[test]
    fn test_default_hostname_provider_with_config() {
        let config = HostnameConfig {
            hostname: Some("test.com".to_string()),
            use_request_hostname: false,
            frontend_url: Some("https://test.com".to_string()),
            hostname_required: true,
            admin_url: Some("https://admin.test.com".to_string()),
        };

        let provider = DefaultHostnameProvider::with_config(config);
        // Provider should be created successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_default_hostname_provider_hostname() {
        let provider = DefaultHostnameProvider::new();

        let hostname = provider
            .get_hostname("https://example.com/path")
            .await
            .unwrap();
        assert!(hostname.is_none()); // Default provider returns None

        let config = HostnameConfig {
            hostname: Some("configured.com".to_string()),
            ..Default::default()
        };
        let provider_with_config = DefaultHostnameProvider::with_config(config);

        let hostname = provider_with_config
            .get_hostname("https://example.com/path")
            .await
            .unwrap();
        assert_eq!(hostname, Some("configured.com".to_string()));
    }

    #[tokio::test]
    async fn test_default_hostname_provider_frontend_url() {
        let provider = DefaultHostnameProvider::new();

        let frontend_url = provider
            .get_frontend_url("https://example.com/path")
            .await
            .unwrap();
        assert!(frontend_url.is_none()); // Default provider returns None

        let config = HostnameConfig {
            frontend_url: Some("https://frontend.com".to_string()),
            ..Default::default()
        };
        let provider_with_config = DefaultHostnameProvider::with_config(config);

        let frontend_url = provider_with_config
            .get_frontend_url("https://example.com/path")
            .await
            .unwrap();
        assert_eq!(frontend_url, Some("https://frontend.com".to_string()));
    }

    #[tokio::test]
    async fn test_default_hostname_provider_admin_url() {
        let provider = DefaultHostnameProvider::new();

        let admin_url = provider
            .get_admin_url("https://example.com/path")
            .await
            .unwrap();
        assert!(admin_url.is_none()); // Default provider returns None

        let config = HostnameConfig {
            admin_url: Some("https://admin.com".to_string()),
            ..Default::default()
        };
        let provider_with_config = DefaultHostnameProvider::with_config(config);

        let admin_url = provider_with_config
            .get_admin_url("https://example.com/path")
            .await
            .unwrap();
        assert_eq!(admin_url, Some("https://admin.com".to_string()));
    }

    #[tokio::test]
    async fn test_default_hostname_provider_is_hostname_required() {
        let provider = DefaultHostnameProvider::new();

        let required = provider.is_hostname_required().await.unwrap();
        assert!(!required); // Default is false

        let config = HostnameConfig {
            hostname_required: true,
            ..Default::default()
        };
        let provider_with_config = DefaultHostnameProvider::with_config(config);

        let required = provider_with_config.is_hostname_required().await.unwrap();
        assert!(required);
    }

    #[tokio::test]
    async fn test_default_hostname_provider_resolve_hostname_fixed() {
        let config = HostnameConfig {
            hostname: Some("fixed.com".to_string()),
            frontend_url: Some("https://fixed.com".to_string()),
            admin_url: Some("https://admin.fixed.com".to_string()),
            use_request_hostname: false,
            hostname_required: false,
        };

        let provider = DefaultHostnameProvider::with_config(config);
        let resolution = provider
            .resolve_hostname("https://example.com/path")
            .await
            .unwrap();

        assert_eq!(resolution.hostname, "fixed.com");
        assert_eq!(
            resolution.frontend_url,
            Some("https://fixed.com".to_string())
        );
        assert_eq!(
            resolution.admin_url,
            Some("https://admin.fixed.com".to_string())
        );
        assert!(resolution.fixed);
    }

    #[tokio::test]
    async fn test_default_hostname_provider_resolve_hostname_dynamic() {
        let config = HostnameConfig {
            hostname: Some("fallback.com".to_string()),
            use_request_hostname: true,
            hostname_required: false,
            ..Default::default()
        };

        let provider = DefaultHostnameProvider::with_config(config);
        let resolution = provider
            .resolve_hostname("https://dynamic.com/path")
            .await
            .unwrap();

        assert_eq!(resolution.hostname, "dynamic.com"); // Should extract from request
        assert!(!resolution.fixed);
    }

    #[tokio::test]
    async fn test_default_hostname_provider_resolve_hostname_fallback() {
        let config = HostnameConfig {
            hostname: Some("fallback.com".to_string()),
            use_request_hostname: true,
            hostname_required: false,
            ..Default::default()
        };

        let provider = DefaultHostnameProvider::with_config(config);
        let resolution = provider.resolve_hostname("invalid-uri").await.unwrap();

        assert_eq!(resolution.hostname, "fallback.com"); // Should fallback to configured hostname
        assert!(!resolution.fixed);
    }

    #[tokio::test]
    async fn test_default_hostname_provider_resolve_hostname_default() {
        let provider = DefaultHostnameProvider::new();
        let resolution = provider.resolve_hostname("invalid-uri").await.unwrap();

        assert_eq!(resolution.hostname, "localhost"); // Should default to localhost
        assert!(resolution.fixed);
    }

    #[test]
    fn test_provider_factory() {
        let factory = DefaultHostnameProviderFactory::new();
        assert_eq!(ProviderFactory::get_id(&factory), "default-hostname");
    }

    #[tokio::test]
    async fn test_provider_factory_creation() {
        let factory = DefaultHostnameProviderFactory::new();
        let config = authenc::spi::ProviderConfig::default();

        let provider = ProviderFactory::create(&factory, &config).unwrap();
        // Provider should be created successfully
        assert!(true);
    }

    #[test]
    fn test_provider_as_any() {
        let provider = DefaultHostnameProvider::new();
        let any_ref = provider.as_any();
        assert!(any_ref.is::<DefaultHostnameProvider>());
    }
}
