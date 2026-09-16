//! Logging and tracing setup.

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::TelemetryConfig;

/// Install the global subscriber.
///
/// `RUST_LOG` still wins when set, so an operator can raise the level on a
/// running deployment without editing configuration.
///
/// # Errors
///
/// Returns an error if the configured filter directive is not parseable.
pub fn init(config: &TelemetryConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&config.filter))?;

    let registry = tracing_subscriber::registry().with(filter);

    if config.json {
        registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true),
            )
            .try_init()?;
    } else {
        registry.with(fmt::layer().compact()).try_init()?;
    }

    Ok(())
}
