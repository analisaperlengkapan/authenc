pub mod config;
pub mod events;
pub mod protocol;
pub mod spi;
pub mod utils;
pub mod traits;

// Re-exports
pub use authenc_api::error;
pub use authenc_api::error::{AuthencError, Result};
pub use config::AppConfig;
