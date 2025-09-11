//! Axum web framework integration
//!
//! This module provides the Axum-specific implementation for running
//! the Authenc authentication service as an HTTP server.

use axum::Router;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info};

use crate::{
    app::AppState,
    error::Result,
    handlers::create_router,
    middleware::rate_limit_axum::{RateLimitConfig, RateLimitLayer, RateLimiterState},
    middleware::{
        input_validation_axum::{input_validation_middleware, InputValidationConfig},
        security_headers_axum::security_headers_middleware,
    },
};

/// Axum web application wrapper
pub struct AxumApp {
    state: Arc<AppState>,
    router: Router,
}

impl AxumApp {
    /// Create a new Axum application with the given state
    pub fn new(state: AppState) -> Self {
        let state = Arc::new(state);

        // Configure rate limiting
        let rate_limit_config = RateLimitConfig {
            requests_per_minute: state.config.security.rate_limit_requests_per_minute as u64,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
                "/metrics".to_string(),
                "/.well-known/".to_string(), // OIDC discovery endpoints
            ],
            enabled: state.config.features.enable_rate_limiting,
        };

        // Configure input validation
        let input_validation_config = Arc::new(InputValidationConfig {
            enabled: state.config.features.enable_input_validation,
            max_query_param_length: 2048,
            max_header_length: 4096,
            block_suspicious_patterns: true,
        });

        // Build the router with middleware and routes
        let router = create_router(state.clone())
            // Add rate limiting first (early rejection)
            .layer(RateLimitLayer::new(RateLimiterState::new(
                rate_limit_config,
            )))
            // Add security middleware layers (order matters!)
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(input_validation_config.clone(), req, next)
            }))
            // Add utility middleware layers
            .layer(TraceLayer::new_for_http())
            .layer(CorsLayer::permissive())
            .layer(CompressionLayer::new());

        Self { state, router }
    }

    /// Run the Axum server
    pub async fn run(self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.state.config.server.port));
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
