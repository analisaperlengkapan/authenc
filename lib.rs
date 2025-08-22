pub mod src;

// Re-export selected modules (not everything) to form the public API surface.
pub use src::config; // needed for crate::config path inside internal modules
pub use src::error;  // needed for crate::error path
pub use src::database; // for crate::database references
pub use src::config::AppConfig;
pub use src::error::{AuthencError, Result};
pub use src::app::{self, ApplicationBuilder};
pub use src::services;
pub use src::handlers;
pub use src::middleware;
pub use src::models;
pub use src::utils;

