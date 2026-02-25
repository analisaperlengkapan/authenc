//! Axum web framework integration
//!
//! This module provides the Axum-specific implementation for running
//! the Authenc authentication service as an HTTP server.

use axum::{Router, extract::State};
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info};

use crate::{
    app::AppState,
    error::Result,
    handlers::create_router,
    middleware::rate_limit::{RateLimitConfig, RateLimitLayer, RateLimiterState},
    middleware::{
        csrf::{CsrfConfig, CsrfState, csrf_protection_middleware},
        validation::{InputValidationConfig, input_validation_middleware},
        security_headers::security_headers_middleware,
        timeout::timeout_middleware,
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
            progressive_delays: true,
            base_delay_ms: 1000,
            max_delay_ms: 10000,
        };

        // Configure input validation
        let input_validation_config = InputValidationConfig {
            enabled: state.config.features.enable_input_validation,
            max_query_param_length: 2048,
            max_header_length: 4096,
            max_request_body_size: 1024 * 1024, // 1MB
            block_suspicious_patterns: true,
            validate_content_type: true,
            allowed_content_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "text/plain".to_string(),
            ],
        };

        // Configure CSRF protection
        let csrf_config = CsrfConfig {
            enabled: true, // Enable CSRF protection by default
            header_name: "X-CSRF-Token".to_string(),
            cookie_name: "csrf_token".to_string(),
            token_length: 32,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
                "/metrics".to_string(),
                "/.well-known/".to_string(), // OIDC discovery endpoints
                "/api/v1/csrf/token".to_string(), // CSRF token endpoint
                "/auth/forgot-password".to_string(),
                "/auth/reset-password".to_string(),
            ],
        };
        let csrf_state = Arc::new(CsrfState::new(csrf_config));

        // Build the router with middleware and routes
        let router = create_router(state.clone())
            // Add rate limiting first (early rejection)
            .layer(RateLimitLayer::new(RateLimiterState::new(
                rate_limit_config,
            )))
            // Add security middleware layers (order matters!)
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .layer(axum::middleware::from_fn(move |req, next| {
                let csrf_state = csrf_state.clone();
                async move { csrf_protection_middleware(State(csrf_state), req, next).await }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(Arc::new(input_validation_config.clone()), req, next)
            }))
            // Add request logging and timeout protection
            .layer(axum::middleware::from_fn(timeout_middleware))
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
