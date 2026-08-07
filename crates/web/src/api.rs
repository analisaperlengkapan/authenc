//! Server functions.
//!
//! A `#[server]` function is one function that the browser calls and the server
//! runs. There is no DTO written twice, no hand-maintained fetch wrapper, and
//! no route string to get wrong — the argument and return types *are* the
//! contract, checked by the compiler on both sides.
//!
//! The previous console needed 60 lines of `authenticated_request` plumbing to
//! do this by hand, and that wrapper silently rejected `PATCH`, so renaming a
//! passkey failed without ever reaching the network.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// What the server reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    /// Version from `CARGO_PKG_VERSION` of the server binary.
    pub version: String,
    /// Whether the database answered.
    pub database_ready: bool,
}

/// Ask the server how it is doing.
///
/// Deliberately the first server function in the tree: it exercises the whole
/// path — browser call, wire format, server execution, database access, typed
/// response — so that if hydration or the server-function plumbing is broken,
/// the home page says so instead of failing silently.
#[server(name = GetServerStatus, prefix = "/api/sfn", endpoint = "status")]
pub async fn server_status() -> Result<ServerStatus, ServerFnError> {
    use authenc_identity::Db;

    let db = expect_context::<Db>();
    let database_ready = authenc_identity::ping(&db).await.is_ok();

    Ok(ServerStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        database_ready,
    })
}

/// Render a server-function failure as something a person can read.
///
/// A single place to do this, so no page invents its own error string. Stage 2
/// gives this the RFC 9457 problem document that the server already produces;
/// until the auth slice lands there is nothing richer than the transport error
/// to show, and pretending otherwise would just be a nicer-looking lie.
#[must_use]
pub fn describe(error: &ServerFnError) -> String {
    error.to_string()
}
