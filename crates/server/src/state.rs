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

use authenc_identity::{Db, PasswordHasher, mail::Mailer};
use authenc_web::server_ctx::PublicUrls;
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
    /// How outbound mail is delivered.
    pub mailer: Arc<dyn Mailer>,
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

/// Build the public link bases from the configured origin.
#[must_use]
pub fn public_urls(config: &Config) -> PublicUrls {
    let base = config.server.public_url.trim_end_matches('/');
    PublicUrls {
        reset: format!("{base}/reset-password"),
        verify: format!("{base}/verify-email"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_urls_are_absolute_and_free_of_double_slashes() {
        let mut config = Config::default();
        config.server.public_url = "https://id.example.com/".to_owned();

        let urls = public_urls(&config);
        assert_eq!(urls.reset, "https://id.example.com/reset-password");
        assert_eq!(urls.verify, "https://id.example.com/verify-email");
    }
}
