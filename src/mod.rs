// Core modules
pub mod config;
pub mod error;
pub mod app;

// Feature modules
pub mod database;
pub mod middleware;
pub mod handlers;
pub mod services;
pub mod models;
pub mod utils;

// NOTE: The binary entrypoint `src/main.rs` is NOT included in the library module tree.
// Removing `pub mod main;` prevents circular/self crate import issues when the bin
// wants to reference the library as `authenc::...`.

// Re-export commonly used items
pub use config::AppConfig;
pub use error::{AuthencError, Result};
