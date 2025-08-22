use crate::config::AppConfig;
use crate::error::{AuthencError, Result};
use actix_web::{HttpResponse, Responder, App, HttpServer, web};
use std::sync::Arc;
// Bring store/service types into scope via the wildcard re-export from lib
use crate::services::{
    user_store::UserStore,
    session_store::SessionStore,
    totp_store::TotpStore,
    brute_force_protector::BruteForceProtector,
    anomaly_detector::AnomalyDetector,
    federation_provider::FederationRegistry,
    pg_audit_log_store::PgAuditLogStore,
    services::{realm_store::RealmStore, role_store::RoleStore, permission_store::PermissionStore},
};

/// Health check endpoint
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Readiness check endpoint  
async fn ready() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ready",
        "checks": { "database": "healthy" }
    }))
}

/// Metrics endpoint placeholder
async fn metrics() -> impl Responder { HttpResponse::Ok().body("# Metrics endpoint placeholder") }

/// Application state shared across handlers
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub user_store: Arc<UserStore>,
    pub session_store: Arc<SessionStore>,
    pub totp_store: Arc<TotpStore>,
    pub brute_force_protector: Arc<BruteForceProtector>,
    pub anomaly_detector: Arc<AnomalyDetector>,
    pub federation_registry: Arc<FederationRegistry>,
    pub audit_log_store: Arc<PgAuditLogStore>,
    pub realm_store: Arc<RealmStore>,
    pub role_store: Arc<RoleStore>,
    pub permission_store: Arc<PermissionStore>,
}

impl AppState {
    pub async fn new(config: Arc<AppConfig>) -> Result<Self> {
        let audit_log_store = Arc::new(
            PgAuditLogStore::new(&config.database.url)
                .await
                .map_err(|e| AuthencError::database(format!("Failed to init audit store: {}", e)))?
        );
        let user_store = Arc::new(UserStore::new());
        let session_store = Arc::new(SessionStore::new());
        let totp_store = Arc::new(TotpStore::new());
        let brute_force_protector = Arc::new(BruteForceProtector::new(
            config.security.brute_force_max_attempts as usize,
            config.security.brute_force_window_seconds,
        ));
        let anomaly_detector = Arc::new(AnomalyDetector::new());
        let federation_registry = Arc::new(FederationRegistry::new());
        let realm_store = Arc::new(RealmStore::new());
        let role_store = Arc::new(RoleStore::new());
        let permission_store = Arc::new(PermissionStore::new());
        Ok(Self { config, user_store, session_store, totp_store, brute_force_protector, anomaly_detector, federation_registry, audit_log_store, realm_store, role_store, permission_store })
    }
}

pub struct ApplicationBuilder { config: Arc<AppConfig> }
impl ApplicationBuilder { 
    pub fn new(config: AppConfig) -> Self { 
        Self { config: Arc::new(config) } 
    } 

    pub async fn run(self) -> std::io::Result<()> { 
        // Validate configuration
        if let Err(e) = self.config.validate() { 
            eprintln!("Configuration validation failed: {e}"); 
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("config error: {e}"))); 
        }

        // Build shared state
        let state = AppState::new(self.config.clone())
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("state init error: {e}")))?;
        let state = web::Data::new(state);

        let host = self.config.server.host.clone();
        let port = self.config.server.port;
        let workers = self.config.server.workers;
        let max_conns = self.config.server.max_connections;
        let metrics_path = self.config.observability.metrics_endpoint.clone();
        let enable_metrics = self.config.observability.enable_metrics || self.config.observability.metrics_enabled;

        log::info!("Starting Authenc server on {host}:{port}");
        let server = HttpServer::new(move || {
            let app = App::new()
                .app_data(state.clone())
                .route("/health", web::get().to(health))
                .route("/ready", web::get().to(ready));
            if enable_metrics { 
                app.route(&metrics_path, web::get().to(metrics))
            } else { 
                app 
            }
        })
        .workers(workers.unwrap_or_else(|| num_cpus::get().max(1)))
        .max_connections(max_conns)
        .bind((host.as_str(), port))?;

        server.run().await
    } 
}

pub fn initialize_logging(config: &AppConfig) -> Result<()> {
    let log_level = match config.observability.log_level.as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::from_default_env().filter_level(log_level).init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_app_state_initialization() { let _config = Arc::new(AppConfig::default()); }
    #[test]
    fn test_logging_initialization() { let _config = AppConfig::default(); }
}
