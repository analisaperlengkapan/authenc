use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use authenc::{axum_app::AxumApp, AppConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🚀 Starting Authenc Identity and Access Management System (by Cipherce)");
    tracing::info!("📖 Version: {}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = AppConfig::from_env()?;

    // Create and run the Axum application
    let app = AxumApp::new(config);
    app.run().await?;

    Ok(())
}
