//! Authenc Enterprise Identity Management Platform
//!
//! A secure, scalable identity management platform built with Rust,
//! featuring OAuth2/OIDC, SAML federation, WebAuthn, and advanced cryptography.

use anyhow::Result;
use authenc_server::app::ApplicationBuilder;
use authenc_core::config::AppConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = AppConfig::from_env()?;

    // Initialize logging
    authenc_server::app::initialize_logging(&config)?;

    tracing::info!("🚀 Starting Authenc Identity and Access Management System (by Cipherce)");
    tracing::info!("📖 Version: {}", env!("CARGO_PKG_VERSION"));

    // Create and run the application
    let app = ApplicationBuilder::new(config);
    app.run().await?;

    Ok(())
}
