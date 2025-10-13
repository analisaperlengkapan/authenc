//! Authenticator Management API Endpoints
//!
//! REST API for custom authenticator configuration and flow management

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    app::AppState,
    database::operations::authenticators as auth_ops,
    error::{AuthencError, Result},
};

/// Register authenticator request
#[derive(Debug, Deserialize)]
pub struct RegisterAuthenticatorRequest {
    pub name: String,
    pub alias: String,
    pub authenticator_type: String, // "username-password", "otp", "conditional", etc.
    pub config: JsonValue,
    pub priority: Option<i32>,
}

/// Update authenticator request
#[derive(Debug, Deserialize)]
pub struct UpdateAuthenticatorRequest {
    pub config: Option<JsonValue>,
    pub enabled: Option<bool>,
}

/// Create execution request
#[derive(Debug, Deserialize)]
pub struct CreateExecutionRequest {
    pub flow_id: Uuid,
    pub authenticator_id: Option<Uuid>,
    pub requirement: String, // "REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL"
    pub priority: i32,
    pub parent_flow_id: Option<Uuid>,
}

/// Update execution request
#[derive(Debug, Deserialize)]
pub struct UpdateExecutionRequest {
    pub requirement: String,
}

/// Query parameters for authenticator listing
#[derive(Debug, Deserialize)]
pub struct AuthenticatorQueryParams {
    pub enabled_only: Option<bool>,
}

/// Query parameters for statistics
#[derive(Debug, Deserialize)]
pub struct StatisticsQueryParams {
    pub from_date: Option<String>,
    pub to_date: Option<String>,
}

/// Register a new authenticator
pub async fn register_authenticator(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Json(req): Json<RegisterAuthenticatorRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let authenticator_id = auth_ops::register_authenticator(
        db,
        realm_id,
        req.name,
        req.alias,
        req.authenticator_type,
        req.config,
        req.priority.unwrap_or(100),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": authenticator_id,
            "message": "Authenticator registered successfully"
        })),
    ))
}

/// List authenticators for a realm
pub async fn list_authenticators(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Query(params): Query<AuthenticatorQueryParams>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let authenticators =
        auth_ops::get_realm_authenticators(db, realm_id, params.enabled_only.unwrap_or(false))
            .await?;

    Ok(Json(json!({
        "authenticators": authenticators,
        "total": authenticators.len(),
    })))
}

/// Update authenticator configuration
pub async fn update_authenticator(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, authenticator_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateAuthenticatorRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    if let Some(config) = req.config {
        auth_ops::update_authenticator_config(db, authenticator_id, config).await?;
    }

    if let Some(enabled) = req.enabled {
        auth_ops::set_authenticator_enabled(db, authenticator_id, enabled).await?;
    }

    Ok(Json(json!({
        "id": authenticator_id,
        "message": "Authenticator updated successfully"
    })))
}

/// Delete authenticator
pub async fn delete_authenticator(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, authenticator_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    auth_ops::delete_authenticator(db, authenticator_id).await?;

    Ok(Json(json!({
        "message": "Authenticator deleted successfully"
    })))
}

/// Create an execution for a flow
pub async fn create_execution(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Json(req): Json<CreateExecutionRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    // Validate requirement
    let valid_requirements = ["REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL"];
    if !valid_requirements.contains(&req.requirement.as_str()) {
        return Err(AuthencError::validation(format!(
            "Invalid requirement. Must be one of: {:?}",
            valid_requirements
        )));
    }

    let execution_id = auth_ops::create_execution(
        db,
        realm_id,
        req.flow_id,
        req.authenticator_id,
        req.requirement,
        req.priority,
        req.parent_flow_id,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": execution_id,
            "message": "Execution created successfully"
        })),
    ))
}

/// List executions for a flow
pub async fn list_flow_executions(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, flow_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let executions = auth_ops::get_flow_executions(db, flow_id).await?;

    Ok(Json(json!({
        "executions": executions,
        "total": executions.len(),
    })))
}

/// Update execution requirement
pub async fn update_execution(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, execution_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateExecutionRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let valid_requirements = ["REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL"];
    if !valid_requirements.contains(&req.requirement.as_str()) {
        return Err(AuthencError::validation(format!(
            "Invalid requirement. Must be one of: {:?}",
            valid_requirements
        )));
    }

    auth_ops::update_execution_requirement(db, execution_id, req.requirement).await?;

    Ok(Json(json!({
        "id": execution_id,
        "message": "Execution updated successfully"
    })))
}

/// Get execution statistics
pub async fn get_execution_statistics(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Query(params): Query<StatisticsQueryParams>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let from_date = if let Some(ref date_str) = params.from_date {
        Some(
            chrono::DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| AuthencError::validation(format!("Invalid from_date: {}", e)))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let to_date = if let Some(ref date_str) = params.to_date {
        Some(
            chrono::DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| AuthencError::validation(format!("Invalid to_date: {}", e)))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let stats = auth_ops::get_execution_statistics(db, realm_id, from_date, to_date).await?;

    Ok(Json(stats))
}

/// Create router for authenticator API endpoints
pub fn create_authenticator_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/:realm/authenticators",
            post(register_authenticator).get(list_authenticators),
        )
        .route(
            "/:realm/authenticators/:authenticator_id",
            put(update_authenticator).delete(delete_authenticator),
        )
        .route(
            "/:realm/authentication-flows/:flow_id/executions",
            post(create_execution).get(list_flow_executions),
        )
        .route(
            "/:realm/authentication-flows/:flow_id/executions/:execution_id",
            put(update_execution),
        )
        .route(
            "/:realm/execution-statistics",
            get(get_execution_statistics),
        )
}
