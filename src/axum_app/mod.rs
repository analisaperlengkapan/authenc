use axum::Router;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info};

use crate::{
    database::Database, error::Result, handlers::create_router,
    middleware::rate_limit_axum::RateLimitConfig, AppConfig,
};

/// Represents the Axum web application
pub struct AxumApp {
    config: Arc<AppConfig>,
    router: Router,
}

impl AxumApp {
    /// Create a new Axum application with the given configuration
    pub fn new(config: AppConfig) -> Self {
        let config = Arc::new(config);

        // Initialize database
        let db = {
            let db_config = config.database.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async move { Database::new(&db_config).await })
            })
            .expect("Failed to initialize database")
        };
        let db = Arc::new(db);

        // Configure rate limiting
        let _rate_limit_config = RateLimitConfig {
            requests_per_minute: 60,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
            ],
            enabled: true,
        };

        // Build the router with middleware and routes
        let router = create_router(db.clone())
            // Add middleware layers
            .layer(TraceLayer::new_for_http())
            .layer(CorsLayer::permissive())
            .layer(CompressionLayer::new());

        Self { config, router }
    }

    /// Run the Axum server
    pub async fn run(self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.server.port));
        info!("🌐 Server starting on {}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        info!("🌐 Server listening on {}", addr);

        axum::serve(
            listener,
            self.router
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| {
            error!("Server error: {}", e);
            crate::error::AuthencError::internal(format!("Server error: {}", e))
        })?;

        Ok(())
    }
}

/// Health check endpoint
/// Handle graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("🛑 Shutting down gracefully...");
}
