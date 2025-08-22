use anyhow::Result;
use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;

use crate::config::DatabaseConfig;

/// Database connection pool manager
pub struct Database {
    pool: Pool,
}

impl Database {
    /// Create new database connection pool
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let cfg = Config {
            user: Some("postgres".to_string()),
            password: Some("postgres".to_string()),
            host: Some("localhost".to_string()),
            port: Some(5432),
            dbname: Some("authenc".to_string()),
            pool: Some(deadpool_postgres::PoolConfig {
                max_size: config.max_connections as usize,
                timeouts: deadpool_postgres::Timeouts::wait_millis(config.connection_timeout * 1000),
            }),
            ..Default::default()
        };

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;
        
        // Test connection
        let _conn = pool.get().await?;
        log::info!("✅ Database connection established");

        Ok(Self { pool })
    }

    /// Get database connection from pool
    pub async fn get_connection(&self) -> Result<deadpool_postgres::Client> {
        Ok(self.pool.get().await?)
    }

    /// Check if database is healthy
    pub async fn health_check(&self) -> Result<()> {
        let client = self.get_connection().await?;
        let _rows = client.query("SELECT 1", &[]).await?;
        Ok(())
    }
}

/// Database module exports
pub mod migrations;
pub mod queries;
