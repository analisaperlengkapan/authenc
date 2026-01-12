use axum::{
    Json, Router,
    extract::{State, Path},
    routing::{get, post, put},
    http::StatusCode,
};
use std::sync::Arc;
use serde::Serialize;
use crate::app::AppState;
use crate::services::fips::{
    FipsSecurityProfileProvider, FipsSecurityProvider, SecurityProfile, FipsLevel, FipsComplianceCheck
};
use crate::error::AuthencError;

/// Get current FIPS status
async fn get_fips_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FipsStatusResponse>, AuthencError> {
    let provider = &state.fips_provider;

    let is_enabled = provider.is_fips_mode().await?;
    let level = provider.get_fips_level().await?;
    let current_profile = provider.get_current_profile().await?;

    Ok(Json(FipsStatusResponse {
        enabled: is_enabled,
        level,
        current_profile: current_profile.name,
    }))
}

/// Enable FIPS mode
async fn enable_fips_mode(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, AuthencError> {
    state.fips_provider.enable_fips_mode().await;
    Ok(StatusCode::OK)
}

/// Disable FIPS mode
async fn disable_fips_mode(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, AuthencError> {
    state.fips_provider.disable_fips_mode().await;
    Ok(StatusCode::OK)
}

/// Get available security profiles
async fn get_security_profiles(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SecurityProfile>>, AuthencError> {
    let profiles = state.fips_provider.get_security_profiles().await?;
    Ok(Json(profiles))
}

/// Set security profile
async fn set_security_profile(
    State(state): State<Arc<AppState>>,
    Path(profile_name): Path<String>,
) -> Result<StatusCode, AuthencError> {
    state.fips_provider.set_security_profile(&profile_name).await?;
    Ok(StatusCode::OK)
}

/// Perform compliance check
async fn perform_compliance_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<FipsComplianceCheck>>, AuthencError> {
    let checks = state.fips_provider.perform_compliance_check().await?;
    Ok(Json(checks))
}

#[derive(Serialize)]
struct FipsStatusResponse {
    enabled: bool,
    level: FipsLevel,
    current_profile: String,
}

pub fn create_fips_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(get_fips_status))
        .route("/enable", post(enable_fips_mode))
        .route("/disable", post(disable_fips_mode))
        .route("/profiles", get(get_security_profiles))
        .route("/profiles/:profile_name", put(set_security_profile))
        .route("/check", get(perform_compliance_check))
}
