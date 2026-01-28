use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    app::AppState,
    error::AuthencError,
    services::auth_flow::{
        AuthenticationExecutionModel, AuthenticationFlowModel, AuthenticationFlowType,
    },
    services::stores::auth_flow_store::AuthFlowStoreTrait,
};

/// Create authentication flow routes
pub fn create_auth_flow_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/flows", get(list_flows).post(create_flow))
        .route(
            "/flows/{flow_id}",
            get(get_flow).put(update_flow).delete(delete_flow),
        )
        .route("/flows/{flow_id}/executions", post(create_execution))
}

/// Query parameters for listing flows
#[derive(Deserialize)]
pub struct ListFlowsQuery {
    /// Optional realm ID to filter flows
    pub realm_id: Option<String>,
}

/// List authentication flows
pub async fn list_flows(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListFlowsQuery>,
) -> Result<Json<Vec<AuthenticationFlowResponse>>, AuthencError> {
    let realm_id = if let Some(realm_id_str) = query.realm_id {
        Some(
            Uuid::parse_str(&realm_id_str)
                .map_err(|_| AuthencError::validation("Invalid realm ID"))?,
        )
    } else {
        None
    };

    let flows = state.auth_flow_store.list_flows(realm_id).await?;

    let responses = flows
        .into_iter()
        .map(AuthenticationFlowResponse::from)
        .collect();

    Ok(Json(responses))
}

/// Create a new authentication flow
pub async fn create_flow(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateFlowRequest>,
) -> Result<Json<AuthenticationFlowResponse>, AuthencError> {
    let flow_type = match request.flow_type.as_str() {
        "browser" => AuthenticationFlowType::Browser,
        "direct_grant" => AuthenticationFlowType::DirectGrant,
        "client_authentication" => AuthenticationFlowType::ClientAuthentication,
        "registration" => AuthenticationFlowType::Registration,
        "reset_credentials" => AuthenticationFlowType::ResetCredentials,
        "docker" => AuthenticationFlowType::Docker,
        custom => AuthenticationFlowType::Custom(custom.to_string()),
    };

    let flow = AuthenticationFlowModel {
        id: Uuid::new_v4(),
        alias: request.alias,
        description: request.description,
        flow_type,
        realm_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(), // Default test realm
        enabled: request.enabled.unwrap_or(true),
        priority: request.priority.unwrap_or(0),
    };

    let created_flow = state.auth_flow_store.create_flow(&flow).await?;

    Ok(Json(AuthenticationFlowResponse::from(created_flow)))
}

/// Get authentication flow by ID
pub async fn get_flow(
    State(state): State<Arc<AppState>>,
    Path(flow_id): Path<String>,
) -> Result<Json<AuthenticationFlowResponse>, AuthencError> {
    let flow_id =
        Uuid::parse_str(&flow_id).map_err(|_| AuthencError::validation("Invalid flow ID"))?;

    let flow = state
        .auth_flow_store
        .get_flow(flow_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Authentication flow not found"))?;

    Ok(Json(AuthenticationFlowResponse::from(flow)))
}

/// Update authentication flow
pub async fn update_flow(
    State(state): State<Arc<AppState>>,
    Path(flow_id): Path<String>,
    Json(request): Json<UpdateFlowRequest>,
) -> Result<Json<AuthenticationFlowResponse>, AuthencError> {
    let flow_id =
        Uuid::parse_str(&flow_id).map_err(|_| AuthencError::validation("Invalid flow ID"))?;

    // Get existing flow
    let mut existing_flow = state
        .auth_flow_store
        .get_flow(flow_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Authentication flow not found"))?;

    // Update fields
    if let Some(alias) = request.alias {
        existing_flow.alias = alias;
    }
    if let Some(description) = request.description {
        existing_flow.description = description;
    }
    if let Some(enabled) = request.enabled {
        existing_flow.enabled = enabled;
    }
    if let Some(priority) = request.priority {
        existing_flow.priority = priority;
    }

    let updated_flow = state
        .auth_flow_store
        .update_flow(flow_id, &existing_flow)
        .await?;

    Ok(Json(AuthenticationFlowResponse::from(updated_flow)))
}

/// Delete authentication flow
pub async fn delete_flow(
    State(state): State<Arc<AppState>>,
    Path(flow_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    let flow_id =
        Uuid::parse_str(&flow_id).map_err(|_| AuthencError::validation("Invalid flow ID"))?;

    state.auth_flow_store.delete_flow(flow_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Create authentication execution
pub async fn create_execution(
    State(state): State<Arc<AppState>>,
    Path(flow_id): Path<String>,
    Json(request): Json<CreateExecutionRequest>,
) -> Result<Json<AuthenticationExecutionResponse>, AuthencError> {
    let flow_id =
        Uuid::parse_str(&flow_id).map_err(|_| AuthencError::validation("Invalid flow ID"))?;

    let execution = AuthenticationExecutionModel {
        id: Uuid::new_v4(),
        flow_id,
        alias: request.alias,
        description: request.description,
        execution_type: request.execution_type,
        enabled: request.enabled.unwrap_or(true),
        priority: request.priority.unwrap_or(0),
        configuration: request.configuration.unwrap_or_default(),
        requirements: request.requirements.unwrap_or_default(),
    };

    let created_execution = state.auth_flow_store.create_execution(&execution).await?;

    Ok(Json(AuthenticationExecutionResponse::from(
        created_execution,
    )))
}

// Request/Response structures

/// Request to create a new authentication flow
#[derive(Deserialize)]
pub struct CreateFlowRequest {
    /// Unique alias for the authentication flow
    pub alias: String,
    /// Description of the authentication flow
    pub description: String,
    /// Type of authentication flow
    pub flow_type: String,
    /// Whether the flow is enabled
    pub enabled: Option<bool>,
    /// Priority order for execution
    pub priority: Option<i32>,
}

/// Request to update an existing authentication flow
#[derive(Deserialize)]
pub struct UpdateFlowRequest {
    /// Updated alias for the authentication flow
    pub alias: Option<String>,
    /// Updated description of the authentication flow
    pub description: Option<String>,
    /// Updated enabled status
    pub enabled: Option<bool>,
    /// Updated priority order
    pub priority: Option<i32>,
}

/// Request to create a new authentication execution
#[derive(Deserialize)]
pub struct CreateExecutionRequest {
    /// Unique alias for the execution
    pub alias: String,
    /// Description of the execution
    pub description: String,
    /// Type of execution
    pub execution_type: String,
    /// Whether the execution is enabled
    pub enabled: Option<bool>,
    /// Priority order for execution
    pub priority: Option<i32>,
    /// Configuration parameters
    pub configuration: Option<std::collections::HashMap<String, String>>,
    /// Required execution dependencies
    pub requirements: Option<Vec<String>>,
}

/// Response containing authentication flow information
#[derive(Serialize)]
pub struct AuthenticationFlowResponse {
    /// Unique identifier of the authentication flow
    pub id: String,
    /// Unique alias of the authentication flow
    pub alias: String,
    /// Description of the authentication flow
    pub description: String,
    /// Type of authentication flow
    pub flow_type: String,
    /// Whether the flow is enabled
    pub enabled: bool,
    /// Priority order for execution
    pub priority: i32,
}

impl From<AuthenticationFlowModel> for AuthenticationFlowResponse {
    fn from(flow: AuthenticationFlowModel) -> Self {
        Self {
            id: flow.id.to_string(),
            alias: flow.alias,
            description: flow.description,
            flow_type: match flow.flow_type {
                AuthenticationFlowType::Browser => "browser".to_string(),
                AuthenticationFlowType::DirectGrant => "direct_grant".to_string(),
                AuthenticationFlowType::ClientAuthentication => "client_authentication".to_string(),
                AuthenticationFlowType::Registration => "registration".to_string(),
                AuthenticationFlowType::ResetCredentials => "reset_credentials".to_string(),
                AuthenticationFlowType::Docker => "docker".to_string(),
                AuthenticationFlowType::Custom(s) => s,
            },
            enabled: flow.enabled,
            priority: flow.priority,
        }
    }
}

/// Response containing authentication execution information
#[derive(Serialize)]
pub struct AuthenticationExecutionResponse {
    /// Unique identifier of the execution
    pub id: String,
    /// Unique alias of the execution
    pub alias: String,
    /// Description of the execution
    pub description: String,
    /// Type of authentication execution
    pub execution_type: String,
    /// Whether the execution is enabled
    pub enabled: bool,
    /// Priority order for execution
    pub priority: i32,
    /// Configuration parameters
    pub configuration: std::collections::HashMap<String, String>,
    /// Required execution dependencies
    pub requirements: Vec<String>,
}

impl From<AuthenticationExecutionModel> for AuthenticationExecutionResponse {
    fn from(execution: AuthenticationExecutionModel) -> Self {
        Self {
            id: execution.id.to_string(),
            alias: execution.alias,
            description: execution.description,
            execution_type: execution.execution_type,
            enabled: execution.enabled,
            priority: execution.priority,
            configuration: execution.configuration,
            requirements: execution.requirements,
        }
    }
}
