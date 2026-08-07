//! Application state.
//!
//! Four fields, all of them used. The previous `AppState` had forty-four,
//! built by a single 683-line async constructor, and several of its stores
//! were process-local `HashMap`s that nothing ever populated — which is why
//! every route under `/realms/{realm}/roles` returned 404 unconditionally.
//!
//! New dependencies get added here as the slices that need them land, not in
//! advance.

use std::sync::Arc;

use authenc_identity::{Db, PasswordHasher};
use axum::extract::FromRef;
use leptos::prelude::LeptosOptions;

use crate::config::Config;

/// Everything a handler or server function may reach for.
#[derive(Clone)]
pub struct AppState {
    /// Immutable, already-validated configuration.
    pub config: Arc<Config>,
    /// Database pool.
    pub db: Db,
    /// Password hasher, carrying the current Argon2 parameters.
    pub hasher: PasswordHasher,
    /// Leptos build settings; required by `leptos_axum`.
    pub leptos_options: LeptosOptions,
}

// `leptos_routes` needs to pull `LeptosOptions` out of whatever state the
// router carries.
impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}

impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for Arc<Config> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}
