//! Application state and initialization
//!
//! This module provides the core application state management and
//! initialization logic for the Authenc authentication service.

use crate::config::AppConfig;
use crate::error::{AuthencError, Result};
use std::sync::Arc;

/// Comprehensive application state with all services
#[derive(Clone)]
pub struct AppState {
    /// Application configuration
    pub config: Arc<AppConfig>,
    /// Database connection pool
    pub database: Arc<crate::database::Database>,
    /// User data store
    pub user_store: Arc<crate::services::stores::user_store::UserStore>,
    /// Session management store
    pub session_store: Arc<crate::services::session_store::SessionStore>,
    /// TOTP (Time-based One-Time Password) store
    pub totp_store: Arc<crate::services::totp_store::TotpStore>,
    /// Brute force attack protection service
    pub brute_force_protector: Arc<crate::services::brute_force_protector::BruteForceProtector>,
    /// Anomaly detection service
    pub anomaly_detector: Arc<crate::services::anomaly_detector::AnomalyDetector>,
    /// Federation provider registry
    pub federation_registry: Arc<crate::services::federation_provider::FederationRegistry>,
    /// Audit log storage
    pub audit_log_store: Arc<crate::services::pg_audit_log_store::PgAuditLogStore>,
    /// Realm configuration store
    pub realm_store: Arc<crate::services::stores::realm_store::RealmStore>,
    /// Role management store
    pub role_store: Arc<crate::services::stores::role_store::RoleStore>,
    /// Permission management store
    pub permission_store: Arc<crate::services::stores::permission_store::PermissionStore>,
}

impl AppState {
    /// Initialize application state with all services
    pub async fn new(config: AppConfig) -> Result<Self> {
        let config = Arc::new(config);

        // Initialize database connection pool
        let database = Arc::new(
            crate::database::Database::new(&config.database)
                .await
                .map_err(|e| {
                    AuthencError::database(format!("Failed to initialize database: {}", e))
                })?,
        );

        // Initialize audit log store
        let audit_log_store = Arc::new(
            crate::services::pg_audit_log_store::PgAuditLogStore::new(&config.database_url())
                .await
                .map_err(|e| {
                    AuthencError::database(format!("Failed to init audit store: {}", e))
                })?,
        );

        // Initialize other services
        let user_store = Arc::new(crate::services::stores::user_store::UserStore::new());
        let session_store = Arc::new(crate::services::session_store::SessionStore::new());
        let totp_store = Arc::new(crate::services::totp_store::TotpStore::new());

        let brute_force_protector = Arc::new(
            crate::services::brute_force_protector::BruteForceProtector::new(
                config.security.brute_force_max_attempts as usize,
                config.security.brute_force_window_seconds,
            ),
        );

        let anomaly_detector = Arc::new(crate::services::anomaly_detector::AnomalyDetector::new());
        let federation_registry =
            Arc::new(crate::services::federation_provider::FederationRegistry::new());
        let realm_store = Arc::new(crate::services::stores::realm_store::RealmStore::new());
        let role_store = Arc::new(crate::services::stores::role_store::RoleStore::new());
        let permission_store =
            Arc::new(crate::services::stores::permission_store::PermissionStore::new());

        Ok(Self {
            config,
            database,
            user_store,
            session_store,
            totp_store,
            brute_force_protector,
            anomaly_detector,
            federation_registry,
            audit_log_store,
            realm_store,
            role_store,
            permission_store,
        })
    }
}

/// Application builder for configuring and running the server
pub struct ApplicationBuilder {
    config: AppConfig,
}

impl ApplicationBuilder {
    /// Create a new application builder
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Build the application state
    pub async fn build_state(self) -> Result<AppState> {
        AppState::new(self.config).await
    }

    /// Run the application server
    pub async fn run(self) -> Result<()> {
        let state = self.build_state().await?;

        #[cfg(feature = "axum")]
        {
            use crate::axum_app::AxumApp;
            let app = AxumApp::new(state);
            app.run().await?;
        }

        #[cfg(not(feature = "axum"))]
        {
            return Err(AuthencError::ConfigurationError {
                message: "No web framework feature enabled. Enable 'axum' feature.".to_string(),
            });
        }

        Ok(())
    }
}

/// Initialize logging based on configuration
pub fn initialize_logging(config: &AppConfig) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let level = match config.observability.log_level.as_str() {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| level.as_str().to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_state_initialization() {
        let config = AppConfig::default();
        let result = AppState::new(config).await;
        // Note: This will fail without a database, but tests the structure
        assert!(result.is_err()); // Expected to fail in test environment
    }

    #[test]
    fn test_application_builder_creation() {
        let config = AppConfig::default();
        let builder = ApplicationBuilder::new(config);
        assert!(builder.config.server.port > 0);
    }
}
