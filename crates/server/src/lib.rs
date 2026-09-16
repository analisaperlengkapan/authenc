//! The Authenc server, as a library.
//!
//! `main.rs` is a thin wrapper over this: configuration, wiring, and the
//! listener. Keeping the application itself in a library is what lets the
//! integration tests in `tests/` drive the assembled router — middleware stack
//! and all — rather than calling handlers in isolation and hoping the stack
//! around them behaves.

pub mod api;
pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod federation;
pub mod health;
pub mod http;
pub mod oidc;
pub mod state;
pub mod telemetry;

pub use config::Config;
pub use state::AppState;
