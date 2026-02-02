use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::any::Any;

use authenc_api::error::Result;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, SpiError};

/// Migration SPI for database schema management and data migration
/// This SPI enables database migrations and schema updates
pub struct MigrationSpi;

impl Default for MigrationSpi {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrationSpi {
    /// Create a new migration SPI instance
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl crate::spi::Spi for MigrationSpi {
    fn get_name(&self) -> &'static str {
        "migration"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.migration.MigrationProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.migration.MigrationProviderFactory"
    }
}

/// Migration model representing a database migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationModel {
    /// Unique identifier for the migration
    pub id: String,
    /// Version of the migration
    pub version: String,
    /// Description of what the migration does
    pub description: String,
    /// Script or SQL to execute for the migration
    pub script: String,
    /// Checksum of the migration script for integrity
    pub checksum: String,
    /// Type of migration (SQL, JAVA, etc.)
    pub migration_type: MigrationType,
    /// When the migration was executed
    pub executed_at: Option<DateTime<Utc>>,
    /// Success status of the migration
    pub success: bool,
    /// Execution time in milliseconds
    pub execution_time: Option<i64>,
}

/// Migration types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MigrationType {
    /// SQL migration
    #[default]
    SQL,
    /// Custom migration with custom type
    Custom(String),
}

/// Migration status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStatus {
    /// Current database version
    pub current_version: String,
    /// Target version for migration
    pub target_version: String,
    /// List of pending migrations
    pub pending_migrations: Vec<MigrationModel>,
    /// List of completed migrations
    pub completed_migrations: Vec<MigrationModel>,
    /// Whether the database is up to date
    pub is_up_to_date: bool,
}

/// Provider interface for Migration operations
#[async_trait]
pub trait MigrationProvider: Provider + Send + Sync {
    /// Get the current migration status
    async fn get_status(&self) -> Result<MigrationStatus>;

    /// Execute pending migrations
    async fn migrate(&self) -> Result<()>;

    /// Execute a specific migration
    async fn migrate_to_version(&self, version: &str) -> Result<()>;

    /// Rollback to a specific version
    async fn rollback_to_version(&self, version: &str) -> Result<()>;

    /// Get all available migrations
    async fn get_migrations(&self) -> Result<Vec<MigrationModel>>;

    /// Get migrations by status
    async fn get_migrations_by_status(&self, executed: bool) -> Result<Vec<MigrationModel>>;

    /// Validate migration checksums
    async fn validate_checksums(&self) -> Result<bool>;
}

/// Default implementation of MigrationProvider
pub struct DefaultMigrationProvider;

impl Default for DefaultMigrationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultMigrationProvider {
    /// Create a new default migration provider
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl MigrationProvider for DefaultMigrationProvider {
    async fn get_status(&self) -> Result<MigrationStatus> {
        // Default implementation returns empty status
        Ok(MigrationStatus {
            current_version: "0.0.0".to_string(),
            target_version: "0.0.0".to_string(),
            pending_migrations: vec![],
            completed_migrations: vec![],
            is_up_to_date: true,
        })
    }

    async fn migrate(&self) -> Result<()> {
        // Default implementation does nothing
        Ok(())
    }

    async fn migrate_to_version(&self, _version: &str) -> Result<()> {
        // Default implementation does nothing
        Ok(())
    }

    async fn rollback_to_version(&self, _version: &str) -> Result<()> {
        // Default implementation does nothing
        Ok(())
    }

    async fn get_migrations(&self) -> Result<Vec<MigrationModel>> {
        // Default implementation returns empty list
        Ok(vec![])
    }

    async fn get_migrations_by_status(&self, _executed: bool) -> Result<Vec<MigrationModel>> {
        // Default implementation returns empty list
        Ok(vec![])
    }

    async fn validate_checksums(&self) -> Result<bool> {
        // Default implementation returns true
        Ok(true)
    }
}

impl Provider for DefaultMigrationProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Factory for creating MigrationProvider instances
pub struct DefaultMigrationProviderFactory;

impl Default for DefaultMigrationProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultMigrationProviderFactory {
    /// Create a new default migration provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<DefaultMigrationProvider> for DefaultMigrationProviderFactory {
    fn get_id(&self) -> &'static str {
        "default-migration"
    }

    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<DefaultMigrationProvider>, SpiError> {
        let provider = DefaultMigrationProvider::new();
        Ok(Box::new(provider))
    }
}
