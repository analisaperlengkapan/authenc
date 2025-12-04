#[cfg(test)]
mod tests {
    use authenc::spi::migration::*;
    use authenc::spi::{Provider, ProviderConfig, ProviderFactory, Spi};
    use chrono::Utc;

    #[test]
    fn test_migration_spi() {
        let spi = MigrationSpi::new();
        assert_eq!(spi.get_name(), "migration");
        assert!(!spi.is_internal());
        assert_eq!(
            spi.get_provider_class(),
            "io.authenc.migration.MigrationProvider"
        );
        assert_eq!(
            spi.get_provider_factory_class(),
            "io.authenc.migration.MigrationProviderFactory"
        );
    }

    #[test]
    fn test_migration_model_creation() {
        let migration = MigrationModel {
            id: "test-migration-001".to_string(),
            version: "1.0.0".to_string(),
            description: "Test migration".to_string(),
            script: "CREATE TABLE test (id INTEGER PRIMARY KEY);".to_string(),
            checksum: "abc123".to_string(),
            migration_type: MigrationType::SQL,
            executed_at: Some(Utc::now()),
            success: true,
            execution_time: Some(150),
        };

        assert_eq!(migration.id, "test-migration-001");
        assert_eq!(migration.version, "1.0.0");
        assert_eq!(migration.migration_type, MigrationType::SQL);
        assert!(migration.success);
        assert_eq!(migration.execution_time, Some(150));
    }

    #[test]
    fn test_migration_type_default() {
        let migration_type = MigrationType::default();
        assert!(matches!(migration_type, MigrationType::SQL));
    }

    #[test]
    fn test_migration_status_creation() {
        let status = MigrationStatus {
            current_version: "1.0.0".to_string(),
            target_version: "2.0.0".to_string(),
            pending_migrations: vec![],
            completed_migrations: vec![],
            is_up_to_date: false,
        };

        assert_eq!(status.current_version, "1.0.0");
        assert_eq!(status.target_version, "2.0.0");
        assert!(!status.is_up_to_date);
        assert!(status.pending_migrations.is_empty());
        assert!(status.completed_migrations.is_empty());
    }

    #[test]
    fn test_default_migration_provider() {
        let provider = DefaultMigrationProvider::new();
        // Provider should be created successfully
        assert!(true); // This is just a basic instantiation test
    }

    #[tokio::test]
    async fn test_default_migration_provider_status() {
        let provider = DefaultMigrationProvider::new();

        let status = provider.get_status().await.unwrap();

        // Default provider returns basic status
        assert_eq!(status.current_version, "0.0.0");
        assert_eq!(status.target_version, "0.0.0");
        assert!(status.is_up_to_date);
        assert!(status.pending_migrations.is_empty());
        assert!(status.completed_migrations.is_empty());
    }

    #[tokio::test]
    async fn test_default_migration_provider_migrate() {
        let provider = DefaultMigrationProvider::new();

        // These operations should succeed without doing anything
        provider.migrate().await.unwrap();
        provider.migrate_to_version("1.0.0").await.unwrap();
        provider.rollback_to_version("0.5.0").await.unwrap();
    }

    #[tokio::test]
    async fn test_default_migration_provider_get_migrations() {
        let provider = DefaultMigrationProvider::new();

        let migrations = provider.get_migrations().await.unwrap();
        assert!(migrations.is_empty());

        let pending = provider.get_migrations_by_status(false).await.unwrap();
        assert!(pending.is_empty());

        let completed = provider.get_migrations_by_status(true).await.unwrap();
        assert!(completed.is_empty());
    }

    #[tokio::test]
    async fn test_default_migration_provider_validate_checksums() {
        let provider = DefaultMigrationProvider::new();

        let is_valid = provider.validate_checksums().await.unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_provider_factory() {
        let factory = DefaultMigrationProviderFactory::new();
        assert_eq!(ProviderFactory::get_id(&factory), "default-migration");
    }

    #[tokio::test]
    async fn test_provider_factory_creation() {
        let factory = DefaultMigrationProviderFactory::new();
        let config = authenc::spi::ProviderConfig::default();

        let provider = ProviderFactory::create(&factory, &config).unwrap();
        // Provider should be created successfully
        assert!(true);
    }
}
