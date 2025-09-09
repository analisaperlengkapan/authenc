use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;
use tracing::{error, info};

use crate::{
    config::DatabaseConfig,
    error::{AuthencError, Result},
};

/// Database connection pool manager
#[derive(Clone)] // Derive Clone for easy sharing across handlers
pub struct Database {
    pool: Pool,
}

impl Database {
    /// Create new database connection pool
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let cfg = Config {
            user: Some(config.username.clone()),
            password: Some(config.password.clone()),
            host: Some(config.host.clone()),
            port: Some(config.port),
            dbname: Some(config.database.clone()),
            pool: Some(deadpool_postgres::PoolConfig {
                max_size: config.max_connections as usize,
                timeouts: deadpool_postgres::Timeouts::wait_millis(
                    config.connection_timeout * 1000,
                ),
                ..Default::default()
            }),
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
                Ok(Self { pool })
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
            AuthencError::database("Database query failed")
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
            AuthencError::database("Database query failed")
        })?;

        row.try_into().map_err(|e| {
            error!("Failed to convert row: {:?}", e);
            AuthencError::database("Failed to convert database row")
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
            AuthencError::database("Database execute failed")
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

        Self { pool }
    }
}

pub mod migrations;
pub mod operations;
/// Database module exports
pub mod queries;
