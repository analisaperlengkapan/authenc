//! Liveness and readiness probes.
//!
//! The two answer different questions and must not be conflated: liveness says
//! "this process is not wedged, do not restart me", readiness says "I can serve
//! traffic right now". A database outage should take an instance out of the
//! load balancer, not into a restart loop.

use authenc_contract::AppError;
use axum::{Json, extract::State};
use serde::Serialize;

use crate::{error::ApiError, state::AppState};

/// Body of a successful probe response.
#[derive(Debug, Serialize)]
pub struct Health {
    /// Always `"ok"`; a failure is reported as an RFC 9457 problem instead.
    pub status: &'static str,
    /// Server version.
    pub version: &'static str,
}

/// Liveness: deliberately touches no dependency.
pub async fn live() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Readiness: 200 when this instance can serve traffic, 503 when it cannot.
///
/// # Errors
///
/// Returns [`AppError::Unavailable`] — HTTP 503 — when the database does not
/// answer, so an orchestrator stops routing to this instance rather than
/// restarting it.
pub async fn ready(State(state): State<AppState>) -> Result<Json<Health>, ApiError> {
    authenc_identity::ping(&state.db).await.map_err(|error| {
        tracing::warn!(%error, "readiness probe failed");
        ApiError(AppError::Unavailable("database"))
    })?;

    Ok(Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    }))
}
