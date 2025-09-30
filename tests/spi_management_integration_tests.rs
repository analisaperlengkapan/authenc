use authenc::config::{AppConfig, SpiConfig, SpiProviderConfig};
use serde_json::json;

// Unit tests for SPI management configuration logic
// These tests verify that the SPI configuration structures work correctly
// and that the configuration-driven provider management functions as expected.

#[cfg(test)]
mod spi_management_config_tests {
    use super::*;

    #[test]
    fn test_spi_config_creation() {
        let mut config = AppConfig::default();

        // Configure SPI providers
        config.spi = SpiConfig {
            organization: vec![SpiProviderConfig {
                id: "org-default".to_string(),
                enabled: true,
                priority: 0,
                config: json!({
                    "max_organizations": 100,
                    "default_organization": "default"
                }),
            }],
            rich_authorization: vec![SpiProviderConfig {
                id: "authz-default".to_string(),
                enabled: true,
                priority: 0,
                config: json!({
                    "enable_policies": true,
                    "cache_size": 1000
                }),
            }],
            migration: vec![SpiProviderConfig {
                id: "migration-default".to_string(),
                enabled: true,
                priority: 0,
                config: json!({
                    "auto_migrate": true,
                    "migration_table": "schema_migrations"
                }),
            }],
            hostname: vec![SpiProviderConfig {
                id: "hostname-default".to_string(),
                enabled: true,
                priority: 0,
                config: json!({
                    "hostname": "auth.example.com",
                    "frontend_url": "https://auth.example.com",
                    "admin_url": "https://auth.example.com/admin"
                }),
            }],
        };

        // Verify configuration is set correctly
        assert_eq!(config.spi.organization.len(), 1);
        assert_eq!(config.spi.organization[0].id, "org-default");
        assert!(config.spi.organization[0].enabled);
        assert_eq!(config.spi.organization[0].priority, 0);

        assert_eq!(config.spi.rich_authorization.len(), 1);
        assert_eq!(config.spi.rich_authorization[0].id, "authz-default");
        assert!(config.spi.rich_authorization[0].enabled);

        assert_eq!(config.spi.migration.len(), 1);
        assert_eq!(config.spi.migration[0].id, "migration-default");
        assert!(config.spi.migration[0].enabled);

        assert_eq!(config.spi.hostname.len(), 1);
        assert_eq!(config.spi.hostname[0].id, "hostname-default");
        assert!(config.spi.hostname[0].enabled);
    }

    #[test]
    fn test_spi_provider_config_validation() {
        // Test valid hostname configuration
        let hostname_config = SpiProviderConfig {
            id: "hostname-test".to_string(),
            enabled: true,
            priority: 1,
            config: json!({
                "hostname": "test.example.com",
                "frontend_url": "https://test.example.com",
                "admin_url": "https://test.example.com/admin"
            }),
        };

        assert_eq!(hostname_config.id, "hostname-test");
        assert!(hostname_config.enabled);
        assert_eq!(hostname_config.priority, 1);
        assert_eq!(hostname_config.config["hostname"], "test.example.com");
        assert_eq!(
            hostname_config.config["frontend_url"],
            "https://test.example.com"
        );
        assert_eq!(
            hostname_config.config["admin_url"],
            "https://test.example.com/admin"
        );

        // Test organization configuration
        let org_config = SpiProviderConfig {
            id: "org-test".to_string(),
            enabled: false,
            priority: 2,
            config: json!({
                "max_organizations": 50,
                "default_organization": "test-org"
            }),
        };

        assert_eq!(org_config.id, "org-test");
        assert!(!org_config.enabled);
        assert_eq!(org_config.priority, 2);
        assert_eq!(org_config.config["max_organizations"], 50);
        assert_eq!(org_config.config["default_organization"], "test-org");
    }

    #[test]
    fn test_spi_config_serialization() {
        let config = SpiConfig {
            organization: vec![SpiProviderConfig {
                id: "org-1".to_string(),
                enabled: true,
                priority: 0,
                config: json!({"key": "value"}),
            }],
            rich_authorization: vec![],
            migration: vec![],
            hostname: vec![SpiProviderConfig {
                id: "host-1".to_string(),
                enabled: true,
                priority: 1,
                config: json!({"hostname": "example.com"}),
            }],
        };

        // Test that the config can be serialized to JSON
        let json_str = serde_json::to_string(&config).unwrap();
        assert!(json_str.contains("org-1"));
        assert!(json_str.contains("host-1"));
        assert!(json_str.contains("example.com"));

        // Test that it can be deserialized back
        let deserialized: SpiConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.organization.len(), 1);
        assert_eq!(deserialized.hostname.len(), 1);
        assert_eq!(deserialized.organization[0].id, "org-1");
        assert_eq!(deserialized.hostname[0].id, "host-1");
    }

    #[test]
    fn test_provider_config_update_logic() {
        // Test the logic for updating provider configurations
        let mut provider = SpiProviderConfig {
            id: "test-provider".to_string(),
            enabled: true,
            priority: 0,
            config: json!({"old_key": "old_value"}),
        };

        // Simulate updating the configuration
        let new_config = json!({"new_key": "new_value", "old_key": "updated_value"});
        provider.config = new_config.clone();

        assert_eq!(provider.config["new_key"], "new_value");
        assert_eq!(provider.config["old_key"], "updated_value");
    }

    #[test]
    fn test_provider_status_update_logic() {
        // Test the logic for updating provider status
        let mut provider = SpiProviderConfig {
            id: "test-provider".to_string(),
            enabled: true,
            priority: 0,
            config: json!({}),
        };

        // Disable the provider
        provider.enabled = false;
        assert!(!provider.enabled);

        // Re-enable the provider
        provider.enabled = true;
        assert!(provider.enabled);
    }

    #[test]
    fn test_provider_priority_ordering() {
        let providers = vec![
            SpiProviderConfig {
                id: "low-priority".to_string(),
                enabled: true,
                priority: 10,
                config: json!({}),
            },
            SpiProviderConfig {
                id: "high-priority".to_string(),
                enabled: true,
                priority: 1,
                config: json!({}),
            },
            SpiProviderConfig {
                id: "medium-priority".to_string(),
                enabled: true,
                priority: 5,
                config: json!({}),
            },
        ];

        // Sort by priority (lower number = higher priority)
        let mut sorted = providers.clone();
        sorted.sort_by_key(|p| p.priority);

        assert_eq!(sorted[0].id, "high-priority");
        assert_eq!(sorted[1].id, "medium-priority");
        assert_eq!(sorted[2].id, "low-priority");
    }

    #[test]
    fn test_empty_spi_config() {
        let config = SpiConfig::default();

        assert!(config.organization.is_empty());
        assert!(config.rich_authorization.is_empty());
        assert!(config.migration.is_empty());
        assert!(config.hostname.is_empty());
    }

    #[test]
    fn test_multiple_providers_same_spi() {
        let config = SpiConfig {
            organization: vec![
                SpiProviderConfig {
                    id: "org-primary".to_string(),
                    enabled: true,
                    priority: 0,
                    config: json!({"primary": true}),
                },
                SpiProviderConfig {
                    id: "org-secondary".to_string(),
                    enabled: false,
                    priority: 1,
                    config: json!({"primary": false}),
                },
            ],
            rich_authorization: vec![],
            migration: vec![],
            hostname: vec![],
        };

        assert_eq!(config.organization.len(), 2);
        assert_eq!(config.organization[0].id, "org-primary");
        assert_eq!(config.organization[1].id, "org-secondary");
        assert!(config.organization[0].enabled);
        assert!(!config.organization[1].enabled);
    }
}
