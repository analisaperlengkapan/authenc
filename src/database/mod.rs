use deadpool_postgres::{Pool, Runtime};
use tokio_postgres::NoTls;
use tracing::{error, info};

use crate::{
    config::DatabaseConfig,
    error::{AuthencError, Result},
};

/// Mock status for testing
#[cfg(test)]
#[derive(Clone, Debug)]
pub enum MockStatus {
    /// Database is healthy
    Healthy,
    /// Database is unhealthy with specific error message
    Unhealthy(String),
}

/// Database connection pool manager
#[derive(Clone)] // Derive Clone for easy sharing across handlers
pub struct Database {
    pool: Pool,
    /// Prepared statement cache for improved performance
    prepared_cache: PreparedStatementCache,
    /// Mock status for testing
    #[cfg(test)]
    mock_status: Option<MockStatus>,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Database");
        d.field("pool", &"Pool")
            .field(
                "prepared_cache",
                &format!("{} cached statements", self.prepared_cache.len()),
            );

        #[cfg(test)]
        d.field("mock_status", &self.mock_status);

        d.finish()
    }
}

impl Database {
    /// Create new database connection pool
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let cfg = deadpool_postgres::Config {
            host: Some(config.host.clone()),
            port: Some(config.port),
            user: Some(config.username.clone()),
            password: Some(config.password.clone()),
            dbname: Some(config.database.clone()),
            pool: Some(deadpool_postgres::PoolConfig::default()),
            ..Default::default()
        };

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).map_err(|e| {
            error!("Failed to create database pool: {}", e);
            AuthencError::database("Failed to create database pool")
        })?;

        // Test connection
        match pool.get().await {
            Ok(_) => {
                info!(
                    "✅ Database connection established to {}:{}/{}",
                    config.host, config.port, config.database
                );
                Ok(Self {
                    pool,
                    prepared_cache: PreparedStatementCache::new(1000),
                    #[cfg(test)]
                    mock_status: None,
                })
            }
            Err(e) => {
                error!("Failed to connect to database: {}", e);
                Err(AuthencError::database("Failed to connect to database"))
            }
        }
    }

    /// Get a database connection from the pool
    pub async fn get_connection(&self) -> Result<deadpool_postgres::Client> {
        self.pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {}", e);
            AuthencError::database("Failed to get database connection")
        })
    }

    /// Get the database connection pool
    pub fn get_pool(&self) -> deadpool_postgres::Pool {
        self.pool.clone()
    }

    /// Execute a read-only query and return results
    pub async fn query<T>(
        &self,
        statement: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<T>>
    where
        T: Send + 'static + TryFrom<tokio_postgres::Row>,
        <T as TryFrom<tokio_postgres::Row>>::Error: std::fmt::Debug,
    {
        let client = self.get_connection().await?;
        let rows = client.query(statement, params).await.map_err(|e| {
            error!("Query failed: {}\nStatement: {}", e, statement);
            AuthencError::database(format!("Database query failed: {}", e))
        })?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(row.try_into().map_err(|e| {
                error!("Failed to convert row: {:?}", e);
                AuthencError::database("Failed to convert database row")
            })?);
        }

        Ok(results)
    }

    /// Execute a read-only query and return raw rows
    pub async fn query_raw(
        &self,
        statement: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<tokio_postgres::Row>> {
        let client = self.get_connection().await?;
        client.query(statement, params).await.map_err(|e| {
            error!("Query failed: {}\nStatement: {}", e, statement);
            AuthencError::database(format!("Database query failed: {}", e))
        })
    }

    /// Execute a query that returns a single row
    pub async fn query_one<T>(
        &self,
        statement: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<T>
    where
        T: Send + 'static + TryFrom<tokio_postgres::Row>,
        <T as TryFrom<tokio_postgres::Row>>::Error: std::fmt::Debug,
    {
        let client = self.get_connection().await?;
        let row = client.query_one(statement, params).await.map_err(|e| {
            error!("Query one failed: {}\nStatement: {}", e, statement);
            AuthencError::database(format!("Database query failed: {}", e))
        })?;

        row.try_into().map_err(|e| {
            error!("Failed to convert row: {:?}", e);
            AuthencError::database("Failed to convert database row")
        })
    }

    /// Execute a query that returns an optional single row
    pub async fn query_opt(
        &self,
        statement: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Option<tokio_postgres::Row>> {
        let client = self.get_connection().await?;
        client.query_opt(statement, params).await.map_err(|e| {
            error!("Query opt failed: {}\nStatement: {}", e, statement);
            AuthencError::database(format!("Database query failed: {}", e))
        })
    }

    /// Execute a statement that doesn't return any rows
    pub async fn execute(
        &self,
        statement: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<u64> {
        let client = self.get_connection().await?;
        client.execute(statement, params).await.map_err(|e| {
            error!("Execute failed: {}\nStatement: {}", e, statement);
            AuthencError::database(format!("Database execute failed: {}", e))
        })
    }

    /// Execute multiple queries within a single connection
    /// Note: For true transactions, use the database client directly
    pub async fn execute_batch<F, Fut, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&deadpool_postgres::Client) -> Fut,
        Fut: std::future::Future<Output = Result<R>>,
        R: Send,
    {
        let client = self.get_connection().await?;
        f(&client).await
    }

    /// Check if database is healthy
    pub async fn health_check(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(status) = &self.mock_status {
            return match status {
                MockStatus::Healthy => Ok(()),
                MockStatus::Unhealthy(msg) => Err(AuthencError::database(msg)),
            };
        }

        match self.get_connection().await {
            Ok(conn) => conn.query("SELECT 1", &[]).await.map(|_| ()).map_err(|e| {
                error!("Database health check failed: {}", e);
                AuthencError::database("Database health check failed")
            }),
            Err(e) => {
                error!("Database connection failed: {}", e);
                Err(e)
            }
        }
    }

    /// Set mock status for testing
    #[cfg(test)]
    pub fn with_mock_status(mut self, status: MockStatus) -> Self {
        self.mock_status = Some(status);
        self
    }
}

// Mock database for testing
impl Database {
    /// Create a mock database for testing
    pub async fn mock() -> Self {
        use deadpool_postgres::{Manager, Pool};
        use std::env;
        use tokio_postgres::NoTls;

        // Use test database if specified, otherwise use mock
        if let Ok(_database_url) = env::var("TEST_DATABASE_URL") {
            // Use real test database if URL is provided
            let config = DatabaseConfig {
                host: "localhost".to_string(),
                port: 5432,
                username: "postgres".to_string(),
                password: "postgres".to_string(),
                database: "test_authenc".to_string(),
                max_connections: 5,
                connection_timeout: 5,
                audit_log_url: None,
                connection_timeout_seconds: 5,
            };

            if let Ok(db) = Database::new(&config).await {
                return db;
            }
        }

        // Fall back to mock implementation
        let mut config = tokio_postgres::Config::new();
        config
            .user("test")
            .password("test")
            .host("localhost")
            .port(5432)
            .dbname("test");

        let manager = Manager::new(config, NoTls);
        let pool = Pool::builder(manager)
            .max_size(1)
            .build()
            .expect("Failed to create mock database pool");

        Self {
            pool,
            prepared_cache: PreparedStatementCache::new(1),
            #[cfg(test)]
            mock_status: None,
        }
    }

    /// Execute work within a transaction
    ///
    /// The provided closure receives the client and can perform multiple operations.
    /// The transaction is automatically committed if the closure succeeds, or rolled back on error.
    pub async fn with_transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: for<'a> FnOnce(
            &'a deadpool_postgres::Client,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<R>> + Send + 'a>,
        >,
        R: Send,
    {
        let client = self.get_connection().await?;

        // Begin transaction
        client.execute("BEGIN", &[]).await.map_err(|e| {
            error!("Failed to begin transaction: {}", e);
            AuthencError::database(format!("Failed to begin transaction: {}", e))
        })?;

        match f(&client).await {
            Ok(result) => {
                client.execute("COMMIT", &[]).await.map_err(|e| {
                    error!("Failed to commit transaction: {}", e);
                    AuthencError::database(format!("Failed to commit transaction: {}", e))
                })?;
                Ok(result)
            }
            Err(e) => {
                let _ = client.execute("ROLLBACK", &[]).await;
                Err(e)
            }
        }
    }

    /// Get the prepared statement cache
    pub fn prepared_cache(&self) -> &PreparedStatementCache {
        &self.prepared_cache
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        self.prepared_cache.stats()
    }

    /// Execute batch operations
    ///
    /// The provided closure receives a BatchOperations builder for bulk inserts, updates, deletes.
    pub async fn with_batch_operations<F, R>(&self, f: F) -> Result<R>
    where
        F: for<'a> FnOnce(
            BatchOperations<'a>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<R>> + Send + 'a>,
        >,
        R: Send,
    {
        let client = self.get_connection().await?;
        let batch_ops = BatchOperations::new(&client);
        f(batch_ops).await
    }

    /// Clear prepared statement cache (useful for schema changes)
    pub fn clear_prepared_cache(&self) {
        self.prepared_cache.clear();
    }
}

/// Database migration utilities and schema management
///
/// This module contains database migration scripts and utilities for managing
/// schema changes, version control, and database upgrades. Migrations ensure
/// that the database schema remains consistent across different deployments
/// and versions of the authentication platform.
pub mod migrations;

/// Database operation utilities and transaction management
///
/// This module provides high-level database operations and transaction management
/// utilities for common database tasks. It includes connection pooling, query
/// execution, and error handling for database operations.
pub mod operations;
/// Database module exports
pub mod queries;

/// Transaction management with enterprise transaction semantics
pub mod transaction;

/// Prepared statement caching for improved performance
pub mod prepared_cache;

/// Batch operations for efficient bulk database operations
pub mod batch;

/// Advanced connection pool configuration
pub mod pool_config;

// Re-export commonly used types
pub use batch::{BatchInsertable, BatchOperations, BatchUpdateable};
pub use pool_config::{PoolConfigBuilder, PoolHealth};
pub use prepared_cache::{CacheStats, PreparedStatementCache};
pub use transaction::{DatabaseTransaction, IsolationLevel, TransactionManager};
