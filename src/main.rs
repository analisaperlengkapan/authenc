use anyhow::Result;
use authenc::{app::ApplicationBuilder, config::AppConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = AppConfig::from_env()?;

    // Initialize logging
    authenc::app::initialize_logging(&config)?;

    tracing::info!("🚀 Starting Authenc Identity and Access Management System (by Cipherce)");
    tracing::info!("📖 Version: {}", env!("CARGO_PKG_VERSION"));

    // Create and run the application
    let app = ApplicationBuilder::new(config);
    app.run().await?;

    Ok(())
}
