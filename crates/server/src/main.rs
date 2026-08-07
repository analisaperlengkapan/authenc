//! The Authenc server binary.
//!
//! Deliberately thin: parse the command, load configuration, wire the
//! application together, and either run it or perform a one-off task.
//! Everything it composes lives in the library half of this crate, which is
//! what the integration tests exercise.

use std::sync::Arc;

use authenc_server::{
    AppState, Config,
    cli::{Cli, Command},
    http, telemetry,
};
use clap::Parser;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let config = Config::load()?;
    telemetry::init(&config.telemetry)?;

    let db = authenc_identity::connect(&config.db_config()).await?;
    let hasher = authenc_identity::PasswordHasher::new();

    match cli.command.unwrap_or(Command::Serve) {
        Command::Migrate => {
            authenc_identity::migrate(&db).await?;
        }

        Command::Seed {
            realm,
            username,
            email,
            password,
        } => {
            authenc_identity::migrate(&db).await?;
            authenc_server::cli::seed(&db, &hasher, &realm, &username, &email, &password).await?;
        }

        Command::PurgeSessions => {
            let removed = authenc_identity::session::purge_expired(&db).await?;
            tracing::info!(removed, "purged expired sessions");
        }

        Command::Serve => {
            serve(config, db, hasher).await?;
        }
    }

    Ok(())
}

/// Run the HTTP server until it is asked to stop.
async fn serve(
    config: Config,
    db: authenc_identity::Db,
    hasher: authenc_identity::PasswordHasher,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        profile = ?config.profile,
        "starting authenc",
    );

    if config.database.migrate_on_start {
        authenc_identity::migrate(&db).await?;
    }

    let state = AppState {
        config: Arc::new(config),
        db,
        hasher,
        leptos_options: http::leptos_options()?,
    };

    let address = http::bind_address(&state.config);
    let router = http::router(state);

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "listening");

    // `into_make_service_with_connect_info` is what puts the peer address in
    // the request extensions. Without it, every login would be recorded with
    // no address and the per-address lockout could never fire.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
