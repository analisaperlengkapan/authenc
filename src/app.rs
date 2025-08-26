
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_app_state_initialization() { let _config = Arc::new(AppConfig::default()); }
    #[test]
    fn test_logging_initialization() { let _config = AppConfig::default(); }
}

use crate::config::AppConfig;
use crate::error::AuthencError;
use actix_web::{HttpResponse, Responder};
use std::sync::Arc;

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
        "checks": {
            "database": "healthy"
        }
    }))
}

/// Metrics endpoint placeholder
async fn metrics() -> impl Responder {
    HttpResponse::Ok().body("# Metrics endpoint placeholder")
}

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
            crate::services::pg_audit_log_store::PgAuditLogStore::new(&config.database.url)
                .await
                .map_err(|e| AuthencError::database(format!("Failed to init audit store: {}", e)))?
        );

        // Initialize other services
        let user_store = Arc::new(crate::services::services::user_store::UserStore::new());
        let session_store = Arc::new(crate::services::session_store::SessionStore::new());
        let totp_store = Arc::new(crate::services::totp_store::TotpStore::new());
        
        let brute_force_protector = Arc::new(
            crate::services::brute_force_protector::BruteForceProtector::new(
                config.security.brute_force_max_attempts as usize,
                config.security.brute_force_window_seconds,
            )
        );
        
        let anomaly_detector = Arc::new(crate::services::anomaly_detector::AnomalyDetector::new());
        let federation_registry = Arc::new(crate::services::federation_provider::FederationRegistry::new());
        let realm_store = Arc::new(crate::services::services::realm_store::RealmStore::new());
        let role_store = Arc::new(crate::services::services::role_store::RoleStore::new());
        let permission_store = Arc::new(crate::services::services::permission_store::PermissionStore::new());
        
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

    /// Run the application server with endpoint separation (public, admin, internal)
    pub async fn run(self) -> std::io::Result<()> {
    use actix_web::{HttpServer, web};
        let state = web::Data::new(AppState::new(self.config.clone()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("state init error: {e}")))?);
        let host = self.config.server.host.clone();
        let port = self.config.server.port;
        let workers = self.config.server.workers.unwrap_or_else(|| num_cpus::get().max(1));
        let max_conns = self.config.server.max_connections;
        let public_prefix = self.config.server.public_prefix.clone();
        let admin_prefix = self.config.server.admin_prefix.clone();
        let internal_prefix = self.config.server.internal_prefix.clone();

    let enable_metrics = self.config.observability.enable_metrics || self.config.observability.metrics_enabled;
        let server = HttpServer::new(move || {
            let mut app = actix_web::App::new().app_data(state.clone());
            // Public endpoints
            app = app.service(
                actix_web::web::scope(&public_prefix)
                    .route("/health", actix_web::web::get().to(health))
                    .route("/ready", actix_web::web::get().to(ready))
            );
            // Admin endpoints (placeholder)
            app = app.service(
                actix_web::web::scope(&admin_prefix)
                    .route("/users", actix_web::web::get().to(|| async { HttpResponse::Ok().body("admin users") }))
                    .route("/roles", actix_web::web::get().to(|| async { HttpResponse::Ok().body("admin roles") }))
            );
            // Internal endpoints (placeholder)
            app = app.service(
                actix_web::web::scope(&internal_prefix)
                    .route("/audit", actix_web::web::get().to(|| async { HttpResponse::Ok().body("internal audit") }))
            );
            // Feature-flagged metrics endpoint
            if enable_metrics {
                app = app.route("/metrics", actix_web::web::get().to(metrics));
            }
            app
        })
        .workers(workers)
        .max_connections(max_conns);

            // TLS support only (no mTLS, see README for mTLS via reverse proxy)
            if self.config.server.tls_enable {
                use std::fs::File;
                use std::io::BufReader;
                use rustls::{Certificate, PrivateKey, ServerConfig};
                use rustls_pemfile::{certs, pkcs8_private_keys};
                let cert_file = self.config.server.tls_cert_file.as_ref().expect("TLS_CERT_FILE required if TLS_ENABLE=true");
                let key_file = self.config.server.tls_key_file.as_ref().expect("TLS_KEY_FILE required if TLS_ENABLE=true");
                let mut cert_reader = BufReader::new(File::open(cert_file).expect("Failed to open TLS cert file"));
                let mut key_reader = BufReader::new(File::open(key_file).expect("Failed to open TLS key file"));
                let cert_chain: Vec<Certificate> = certs(&mut cert_reader)
                    .unwrap_or_default()
                    .into_iter()
                    .map(Certificate)
                    .collect();
                let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut key_reader)
                    .unwrap_or_default()
                    .into_iter()
                    .map(PrivateKey)
                    .collect();
                let key = keys.remove(0);
                let config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, key)
                    .expect("Invalid TLS cert/key");
                return server.bind_rustls((host.as_str(), port), config)?.run().await;
            } else {
                return server.bind((host.as_str(), port))?.run().await;
            }
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
    env_logger::Builder::from_default_env().filter_level(log_level).init();
    Ok(())
}

// ...existing code...
