//! Protocol Mapper API Endpoints
//!
//! REST API for OIDC/SAML protocol mapper management

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    app::AppState,
    database::operations::protocol_mappers as mapper_ops,
    error::{AuthencError, Result},
};

/// Create protocol mapper request
#[derive(Debug, Deserialize)]
pub struct CreateMapperRequest {
    /// Name of the protocol mapper
    pub name: String,
    /// Protocol type (oidc or saml)
    pub protocol: String,
    /// Type of mapper (user-attribute, role-list, etc.)
    pub mapper_type: String,
    /// Configuration parameters for the mapper
    pub config: JsonValue,
}

/// Update protocol mapper request
#[derive(Debug, Deserialize)]
pub struct UpdateMapperRequest {
    /// Updated configuration parameters
    pub config: Option<JsonValue>,
    /// Updated enabled status
    pub enabled: Option<bool>,
}

/// Query parameters for mapper listing
#[derive(Debug, Deserialize)]
pub struct MapperQueryParams {
    /// Filter by protocol type
    pub protocol: Option<String>,
}

/// Create a client-level protocol mapper
pub async fn create_client_mapper(
    State(state): State<Arc<AppState>>,
    Path((realm_id, client_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<CreateMapperRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    // Validate protocol
    if req.protocol != "oidc" && req.protocol != "saml" {
        return Err(AuthencError::validation(
            "Protocol must be 'oidc' or 'saml'",
        ));
    }

    let mapper_id = mapper_ops::create_protocol_mapper(
        db,
        Some(client_id),
        realm_id,
        req.name,
        req.protocol,
        req.mapper_type,
        req.config,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": mapper_id,
            "message": "Protocol mapper created successfully"
        })),
    ))
}

/// List client protocol mappers
pub async fn list_client_mappers(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, client_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<MapperQueryParams>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let mappers = mapper_ops::get_client_mappers(db, client_id, params.protocol).await?;

    Ok(Json(json!({
        "mappers": mappers,
        "total": mappers.len(),
    })))
}

/// Get a specific mapper by ID
pub async fn get_mapper(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, _client_id, mapper_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let mapper = mapper_ops::get_mapper_by_id(db, mapper_id).await?;

    match mapper {
        Some(m) => Ok(Json(m)),
        None => Err(AuthencError::resource_not_found(
            "Protocol mapper not found",
        )),
    }
}

/// Update protocol mapper
pub async fn update_mapper(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, _client_id, mapper_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(req): Json<UpdateMapperRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    if let Some(config) = req.config {
        mapper_ops::update_mapper_config(db, mapper_id, config).await?;
    }

    if let Some(enabled) = req.enabled {
        mapper_ops::set_mapper_enabled(db, mapper_id, enabled).await?;
    }

    Ok(Json(json!({
        "id": mapper_id,
        "message": "Protocol mapper updated successfully"
    })))
}

/// Delete protocol mapper
pub async fn delete_mapper(
    State(state): State<Arc<AppState>>,
    Path((_realm_id, _client_id, mapper_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    mapper_ops::delete_mapper(db, mapper_id).await?;

    Ok(Json(json!({
        "message": "Protocol mapper deleted successfully"
    })))
}

/// Create a realm-level protocol mapper
pub async fn create_realm_mapper(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Json(req): Json<CreateMapperRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    if req.protocol != "oidc" && req.protocol != "saml" {
        return Err(AuthencError::validation(
            "Protocol must be 'oidc' or 'saml'",
        ));
    }

    let mapper_id = mapper_ops::create_protocol_mapper(
        db,
        None, // realm-level mapper
        realm_id,
        req.name,
        req.protocol,
        req.mapper_type,
        req.config,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": mapper_id,
            "message": "Realm protocol mapper created successfully"
        })),
    ))
}

/// List realm protocol mappers
pub async fn list_realm_mappers(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Query(params): Query<MapperQueryParams>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let mappers = mapper_ops::get_realm_mappers(db, realm_id, params.protocol).await?;

    Ok(Json(json!({
        "mappers": mappers,
        "total": mappers.len(),
    })))
}

/// Get mapper statistics for a realm
pub async fn get_mapper_statistics(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let stats = mapper_ops::get_mapper_statistics(db, realm_id).await?;

    Ok(Json(stats))
}

/// Create router for protocol mapper API endpoints
pub fn create_protocol_mapper_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/:realm/clients/:client_id/mappers",
            post(create_client_mapper).get(list_client_mappers),
        )
        .route(
            "/:realm/clients/:client_id/mappers/:mapper_id",
            get(get_mapper).put(update_mapper).delete(delete_mapper),
        )
        .route(
            "/:realm/mappers",
            post(create_realm_mapper).get(list_realm_mappers),
        )
        .route("/:realm/mapper-statistics", get(get_mapper_statistics))
}
