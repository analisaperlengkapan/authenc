use anyhow::Result;
use std::env;

use authenc::AppConfig;
use authenc::ApplicationBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Starting Authenc Identity and Access Management System (by Cipherce)");
    println!("📖 Version: {}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = AppConfig::from_env()?;
    
    // Create and run application
    let app_builder = ApplicationBuilder::new(config);
    // TODO: enable when ApplicationBuilder::run implemented
    let _ = app_builder; // silence unused
    // app_builder.run().await?;
    
    Ok(())
}
