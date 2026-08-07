//! The contract between the browser and the server.
//!
//! Everything in this crate compiles to **both** `wasm32-unknown-unknown` and
//! the native target, because both sides of the wire need it: the Leptos views
//! and the Axum handlers agree on these types by construction rather than by
//! a hand-written OpenAPI client that can fall out of date.
//!
//! # What belongs here
//!
//! * [`error`] — the one error type and the one status-code mapping
//! * [`id`] — typed identifiers, so a `RealmId` cannot be passed as a `UserId`
//! * [`validate`] — validation rules run identically on both sides
//! * [`model`] — the entities and DTOs that cross the wire
//!
//! # What must never be added
//!
//! `axum`, `sqlx`, `tokio`, or `leptos`. Any of them either breaks the wasm
//! build or drags server-only code into the browser bundle. CI enforces this
//! with `cargo tree`; see `.github/workflows/ci.yml`.

pub mod error;
pub mod id;
pub mod model;
pub mod validate;

pub use error::{AppError, Problem, Result};
pub use id::{PermissionId, RealmId, RoleId, SessionId, UserId};
