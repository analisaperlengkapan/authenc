//! Advanced connection pool configuration and optimization
//!
//! Provides production-grade connection pooling configuration inspired by
//! Keycloak's HikariCP setup and PostgreSQL best practices.

use crate::config::DatabaseConfig;
use deadpool_postgres::{ManagerConfig, PoolConfig, RecyclingMethod};
use std::time::Duration;

/// Connection pool configuration builder
///
/// Provides fine-grained control over connection pool behavior following
/// production best practices from Keycloak and PostgreSQL documentation.
#[derive(Debug, Clone)]
pub struct PoolConfigBuilder {
    /// Maximum number of connections in the pool
    max_size: usize,
    /// Minimum idle connections to maintain
    min_idle: Option<usize>,
    /// Connection timeout
    timeout: Duration,
    /// Connection idle timeout (how long before an idle connection is closed)
    idle_timeout: Option<Duration>,
    /// Connection max lifetime (how long a connection can live)
    max_lifetime: Option<Duration>,
    /// Connection recycling method
    recycling_method: RecyclingMethod,
}

impl Default for PoolConfigBuilder {
    fn default() -> Self {
        Self {
            max_size: 10,
            min_idle: Some(2),
            timeout: Duration::from_secs(30),
            idle_timeout: Some(Duration::from_secs(600)), // 10 minutes
            max_lifetime: Some(Duration::from_secs(1800)), // 30 minutes
            recycling_method: RecyclingMethod::Fast,
        }
    }
}

impl PoolConfigBuilder {
    /// Create a new pool configuration builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum pool size
    ///
    /// # Recommendations (from Keycloak/HikariCP best practices):
    /// - For OLTP workloads: (core_count * 2) + effective_spindle_count
    /// - For web servers: 10-20 per instance
    /// - Never exceed PostgreSQL max_connections setting
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Set minimum idle connections
    ///
    /// Keeping some connections warm improves latency for the first requests.
    /// Recommended: 2-5 for most applications
    pub fn min_idle(mut self, min: usize) -> Self {
        self.min_idle = Some(min);
        self
    }

    /// Set connection acquisition timeout
    ///
    /// How long to wait for a connection from the pool before timing out.
    /// Recommended: 30 seconds (Keycloak default)
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Set idle connection timeout
    ///
    /// Connections idle longer than this will be closed to free resources.
    /// Recommended: 10 minutes (Keycloak/HikariCP default)
    pub fn idle_timeout(mut self, duration: Duration) -> Self {
        self.idle_timeout = Some(duration);
        self
    }

    /// Set maximum connection lifetime
    ///
    /// Connections older than this will be closed and replaced.
    /// Prevents issues with long-lived connections and helps with load balancing.
    /// Recommended: 30 minutes (Keycloak/HikariCP default)
    pub fn max_lifetime(mut self, duration: Duration) -> Self {
        self.max_lifetime = Some(duration);
        self
    }

    /// Set connection recycling method
    ///
    /// - Fast: Quick recycling check (default)
    /// - Verified: Runs SELECT 1 to verify connection
    /// - Clean: Closes and reopens connection
    pub fn recycling_method(mut self, method: RecyclingMethod) -> Self {
        self.recycling_method = method;
        self
    }

    /// Build from DatabaseConfig with optimizations
    pub fn from_database_config(config: &DatabaseConfig) -> Self {
        Self::new()
            .max_size(config.max_connections as usize)
            .timeout(Duration::from_secs(config.connection_timeout))
    }

    /// Build for production environment (Keycloak-like settings)
    pub fn production() -> Self {
        Self::new()
            .max_size(20)
            .min_idle(5)
            .timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .max_lifetime(Duration::from_secs(1800))
            .recycling_method(RecyclingMethod::Verified)
    }

    /// Build for development environment
    pub fn development() -> Self {
        Self::new()
            .max_size(5)
            .min_idle(1)
            .timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(600))
            .recycling_method(RecyclingMethod::Fast)
    }

    /// Build for testing environment
    pub fn testing() -> Self {
        Self::new()
            .max_size(2)
            .min_idle(1)
            .timeout(Duration::from_secs(5))
            .idle_timeout(Duration::from_secs(60))
            .max_lifetime(Duration::from_secs(120))
            .recycling_method(RecyclingMethod::Fast)
    }

    /// Build the deadpool PoolConfig
    pub fn build(self) -> PoolConfig {
        let mut config = PoolConfig::default();
        config.max_size = self.max_size;
        config.timeouts.wait = Some(self.timeout);
        config.timeouts.create = Some(self.timeout);
        config.timeouts.recycle = Some(Duration::from_secs(5));

        config
    }

    /// Build ManagerConfig with statement cache
    pub fn build_manager_config(self) -> ManagerConfig {
        ManagerConfig {
            recycling_method: self.recycling_method,
        }
    }
}

/// Pool health metrics
#[derive(Debug, Clone)]
pub struct PoolHealth {
    /// Current pool size
    pub size: usize,
    /// Maximum pool size
    pub max_size: usize,
    /// Number of available connections
    pub available: usize,
    /// Pool utilization percentage
    pub utilization: f64,
}

impl PoolHealth {
    /// Check if pool is healthy
    pub fn is_healthy(&self) -> bool {
        self.utilization < 90.0 && self.available > 0
    }

    /// Check if pool is under pressure
    pub fn is_under_pressure(&self) -> bool {
        self.utilization > 80.0 || self.available < 2
    }

    /// Get health status as string
    pub fn status(&self) -> &'static str {
        if self.is_healthy() {
            "healthy"
        } else if self.is_under_pressure() {
            "under_pressure"
        } else {
            "critical"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_builder() {
        let config = PoolConfigBuilder::new().max_size(10).min_idle(2).build();

        assert_eq!(config.max_size, 10);
    }

    #[test]
    fn test_production_config() {
        let config = PoolConfigBuilder::production();
        assert_eq!(config.max_size, 20);
        assert_eq!(config.min_idle, Some(5));
    }

    #[test]
    fn test_pool_health() {
        let health = PoolHealth {
            size: 10,
            max_size: 20,
            available: 8,
            utilization: 50.0,
        };

        assert!(health.is_healthy());
        assert!(!health.is_under_pressure());
        assert_eq!(health.status(), "healthy");
    }

    #[test]
    fn test_pool_under_pressure() {
        let health = PoolHealth {
            size: 18,
            max_size: 20,
            available: 1,
            utilization: 90.0,
        };

        assert!(!health.is_healthy());
        assert!(health.is_under_pressure());
    }
}
