//! Prepared statement caching for improved performance
//!
//! Caches prepared statements to avoid re-parsing SQL on every execution.
//! Following PostgreSQL best practices for prepared statement lifecycle.

use crate::error::{AuthencError, Result};
use dashmap::DashMap;
use std::sync::Arc;
use tokio_postgres::{Client, Statement};
use tracing::{debug, error, warn};

/// Prepared statement cache
///
/// Thread-safe cache for prepared statements using DashMap for concurrent access.
/// Automatically prepares statements on first use and reuses them for subsequent calls.
#[derive(Clone)]
pub struct PreparedStatementCache {
    /// Map from SQL query to prepared statement
    cache: Arc<DashMap<String, Arc<Statement>>>,
    /// Maximum number of cached statements
    max_size: usize,
}

impl Default for PreparedStatementCache {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl PreparedStatementCache {
    /// Create a new prepared statement cache with specified maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            max_size,
        }
    }

    /// Get or prepare a statement
    ///
    /// If the statement is already cached, returns the cached version.
    /// Otherwise, prepares it and adds to cache.
    pub async fn get_or_prepare(&self, client: &Client, sql: &str) -> Result<Arc<Statement>> {
        // Check cache first
        if let Some(stmt) = self.cache.get(sql) {
            debug!(
                "Using cached prepared statement for: {}",
                Self::truncate_sql(sql)
            );
            return Ok(stmt.value().clone());
        }

        // Not in cache - prepare it
        self.prepare_and_cache(client, sql).await
    }

    /// Prepare a statement and add to cache
    async fn prepare_and_cache(&self, client: &Client, sql: &str) -> Result<Arc<Statement>> {
        // Check size limit
        if self.cache.len() >= self.max_size {
            warn!(
                "Prepared statement cache is full ({} entries), clearing oldest entries",
                self.max_size
            );
            // Simple eviction: clear 10% of cache
            let to_remove = self.max_size / 10;
            let keys: Vec<String> = self
                .cache
                .iter()
                .take(to_remove)
                .map(|e| e.key().clone())
                .collect();
            for key in keys {
                self.cache.remove(&key);
            }
        }

        // Prepare the statement
        let statement = client.prepare(sql).await.map_err(|e| {
            error!("Failed to prepare statement: {}", e);
            AuthencError::database(format!("Failed to prepare statement: {}", e))
        })?;

        let stmt_arc = Arc::new(statement);
        self.cache.insert(sql.to_string(), stmt_arc.clone());

        debug!("Prepared and cached statement: {}", Self::truncate_sql(sql));
        Ok(stmt_arc)
    }

    /// Clear all cached prepared statements
    pub fn clear(&self) {
        self.cache.clear();
        debug!("Cleared all prepared statements from cache");
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.cache.len(),
            max_size: self.max_size,
        }
    }

    /// Truncate SQL for logging (avoid logging sensitive data)
    fn truncate_sql(sql: &str) -> String {
        let max_len = 100;
        if sql.len() > max_len {
            format!("{}...", &sql[..max_len])
        } else {
            sql.to_string()
        }
    }

    /// Remove a specific statement from cache
    pub fn invalidate(&self, sql: &str) {
        if self.cache.remove(sql).is_some() {
            debug!("Invalidated cached statement: {}", Self::truncate_sql(sql));
        }
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of cached statements
    pub size: usize,
    /// Maximum cache size
    pub max_size: usize,
}

impl CacheStats {
    /// Calculate cache utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.max_size == 0 {
            0.0
        } else {
            (self.size as f64 / self.max_size as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = PreparedStatementCache::new(100);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let cache = PreparedStatementCache::new(100);
        let stats = cache.stats();
        assert_eq!(stats.size, 0);
        assert_eq!(stats.max_size, 100);
        assert_eq!(stats.utilization(), 0.0);
    }

    #[test]
    fn test_sql_truncation() {
        let long_sql = "SELECT * FROM users WHERE ".to_string() + &"x".repeat(200);
        let truncated = PreparedStatementCache::truncate_sql(&long_sql);
        assert!(truncated.len() <= 103); // 100 + "..."
    }

    #[test]
    fn test_cache_clear() {
        let cache = PreparedStatementCache::new(100);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
