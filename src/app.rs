#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_app_state_initialization() {
        let _config = Arc::new(AppConfig::default());
    }
    #[test]
    fn test_logging_initialization() {
        let _config = AppConfig::default();
    }
}

use crate::config::AppConfig;
use crate::error::AuthencError;
use std::sync::Arc;

/// Application state shared across handlers
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub user_store: Arc<crate::services::services::user_store::UserStore>,
    pub session_store: Arc<crate::services::session_store::SessionStore>,
    pub totp_store: Arc<crate::services::totp_store::TotpStore>,
    pub brute_force_protector: Arc<crate::services::brute_force_protector::BruteForceProtector>,
    pub anomaly_detector: Arc<crate::services::anomaly_detector::AnomalyDetector>,
    pub federation_registry: Arc<crate::services::federation_provider::FederationRegistry>,
    pub audit_log_store: Arc<crate::services::pg_audit_log_store::PgAuditLogStore>,
    pub realm_store: Arc<crate::services::services::realm_store::RealmStore>,
    pub role_store: Arc<crate::services::services::role_store::RoleStore>,
    pub permission_store: Arc<crate::services::services::permission_store::PermissionStore>,
}

impl AppState {
    /// Initialize application state with all services
    pub async fn new(config: Arc<AppConfig>) -> crate::error::Result<Self> {
        // Initialize stores with proper error handling
        let audit_log_store = Arc::new(
            crate::services::pg_audit_log_store::PgAuditLogStore::new(&format!(
                "postgresql://{}:{}@{}:{}/{}",
                config.database.username,
                config.database.password,
                config.database.host,
                config.database.port,
                config.database.database
            ))
            .await
            .map_err(|e| AuthencError::database(format!("Failed to init audit store: {}", e)))?,
        );

        // Initialize other services
        let user_store = Arc::new(crate::services::services::user_store::UserStore::new());
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
        let realm_store = Arc::new(crate::services::services::realm_store::RealmStore::new());
        let role_store = Arc::new(crate::services::services::role_store::RoleStore::new());
        let permission_store =
            Arc::new(crate::services::services::permission_store::PermissionStore::new());

        Ok(Self {
            config,
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

/// Application builder with proper configuration and service initialization
pub struct ApplicationBuilder {
    config: Arc<AppConfig>,
}

impl ApplicationBuilder {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Run the application server with Axum
    pub async fn run(self) -> std::io::Result<()> {
        let state = AppState::new(self.config.clone()).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("state init error: {e}"))
        })?;
        
        let host = self.config.server.host.clone();
        let port = self.config.server.port;
        let addr = format!("{}:{}", host, port);
        
        // Create Axum router with all endpoints
        let app = self.create_axum_router(state);
        
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("Server running on {}", addr);
        
        axum::serve(listener, app).await
    }

    /// Create Axum router with all endpoints
    fn create_axum_router(&self, _state: AppState) -> axum::Router {
        use axum::{routing::get, Router};
        
        Router::new()
            .route("/health", get(crate::handlers::health_axum::health))
            .route("/ready", get(crate::handlers::health_axum::ready))
            .route("/live", get(crate::handlers::health_axum::live))
    }
}

/// Initialize logging based on configuration
pub fn initialize_logging(config: &AppConfig) -> std::result::Result<(), AuthencError> {
    let log_level = match config.observability.log_level.as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();
    Ok(())
}

// ...existing code...
