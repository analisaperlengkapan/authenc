// Utility modules
pub mod crypto;
pub mod jwt;
pub mod i18n;
pub mod plugin;

// Authentication utilities
pub mod auth_context;

// Legacy modules (to be refactored)
pub mod core;
pub mod integration;

// Re-exports for convenience
pub use auth_context::*;
pub use i18n::*;
