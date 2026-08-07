//! The Authenc server binary.
//!
//! Deliberately thin: load configuration, wire the application together, bind
//! a listener, and shut down cleanly. Everything it composes lives in the
//! library half of this crate, which is what the integration tests exercise.

use std::sync::Arc;

use authenc_server::{AppState, Config, http, telemetry};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::load()?;
    telemetry::init(&config.telemetry)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        profile = ?config.profile,
        "starting authenc",
    );

    let db = authenc_identity::connect(&config.db_config()).await?;
    if config.database.migrate_on_start {
        authenc_identity::migrate(&db).await?;
    }

    let state = AppState {
        config: Arc::new(config),
        db,
        hasher: authenc_identity::PasswordHasher::new(),
        leptos_options: http::leptos_options()?,
    };

    let address = http::bind_address(&state.config);
    let router = http::router(state);

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolve when the process is asked to stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for ctrl-c");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received ctrl-c, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
