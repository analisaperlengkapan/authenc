use crate::models::realm::{CreateRealmRequest, UpdateRealmRequest, RealmResponse};
use crate::services::realm::{RealmService, RealmManager};
use crate::app::AppState;
use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ListRealmsQuery {
    pub enabled_only: Option<bool>,
}

/// Create realm management routes
pub fn create_realm_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/realms", get(list_realms))
        .route("/realms/{identifier}", get(get_realm))
        .route("/realms", post(create_realm))
        .route("/realms/{identifier}", put(update_realm))
        .route("/realms/{identifier}", delete(delete_realm))
        .route("/realms/{identifier}/status", put(set_realm_status))
}

/// List all realms
pub async fn list_realms(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListRealmsQuery>,
) -> Result<Json<Vec<RealmResponse>>, StatusCode> {
    let realms = state.realm_service.list_realms()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let filtered_realms = if query.enabled_only.unwrap_or(false) {
        realms.into_iter().filter(|r| r.enabled).collect()
    } else {
        realms
    };

    Ok(Json(filtered_realms))
}

/// Get a specific realm by name or ID
pub async fn get_realm(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
) -> Result<Json<RealmResponse>, StatusCode> {
    let realm = if let Ok(uuid) = Uuid::parse_str(&identifier) {
        state.realm_service.get_realm_by_id(&uuid)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        state.realm_service.get_realm_by_name(&identifier)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    match realm {
        Some(realm) => Ok(Json(realm)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Create a new realm
pub async fn create_realm(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateRealmRequest>,
) -> Result<Json<RealmResponse>, StatusCode> {
    match state.realm_service.create_realm(request.clone()).await {
        Ok(realm) => {
            // Fire admin event for realm creation
            let auth_details = crate::models::events::AuthDetails {
                user_id: "system".to_string(), // System operation for realm creation
                username: Some("system".to_string()),
                ip_address: None,
                user_agent: None,
            };

            let admin_event = crate::services::events::AdminEventBuilder::new(
                realm.id.to_string(),
                auth_details,
                crate::models::events::ResourceType::Realm,
                crate::models::events::OperationType::Create,
                format!("/realms/{}", realm.id),
            )
            .representation(serde_json::to_string(&realm).unwrap_or_default())
            .build();

            if let Err(e) = state.event_manager.write().await.fire_admin_event(admin_event, true).await {
                tracing::error!("Failed to fire realm creation admin event: {}", e);
            }

            Ok(Json(realm))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Update an existing realm
pub async fn update_realm(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
    Json(request): Json<UpdateRealmRequest>,
) -> Result<Json<RealmResponse>, StatusCode> {
    let realm_id = if let Ok(uuid) = Uuid::parse_str(&identifier) {
        uuid
    } else {
        // Get realm by name to find ID
        let realm = state.realm_service.get_realm_by_name(&identifier)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;
        realm.id
    };

    match state.realm_service.update_realm(&realm_id, request).await {
        Ok(realm) => {
            // Fire admin event for realm update
            let auth_details = crate::models::events::AuthDetails {
                user_id: "system".to_string(),
                username: Some("system".to_string()),
                ip_address: None,
                user_agent: None,
            };

            let admin_event = crate::services::events::AdminEventBuilder::new(
                realm.id.to_string(),
                auth_details,
                crate::models::events::ResourceType::Realm,
                crate::models::events::OperationType::Update,
                format!("/realms/{}", realm.id),
            )
            .build();

            if let Err(e) = state.event_manager.write().await.fire_admin_event(admin_event, false).await {
                tracing::error!("Failed to fire realm update admin event: {}", e);
            }

            Ok(Json(realm))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Delete a realm
pub async fn delete_realm(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let realm_id = if let Ok(uuid) = Uuid::parse_str(&identifier) {
        uuid
    } else {
        // Get realm by name to find ID
        let realm = state.realm_service.get_realm_by_name(&identifier)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;
        realm.id
    };

    match state.realm_service.delete_realm(&realm_id).await {
        Ok(_) => {
            // Fire admin event for realm deletion
            let auth_details = crate::models::events::AuthDetails {
                user_id: "system".to_string(),
                username: Some("system".to_string()),
                ip_address: None,
                user_agent: None,
            };

            let admin_event = crate::services::events::AdminEventBuilder::new(
                realm_id.to_string(),
                auth_details,
                crate::models::events::ResourceType::Realm,
                crate::models::events::OperationType::Delete,
                format!("/realms/{}", realm_id),
            )
            .build();

            if let Err(e) = state.event_manager.write().await.fire_admin_event(admin_event, false).await {
                tracing::error!("Failed to fire realm deletion admin event: {}", e);
            }

            Ok(StatusCode::NO_CONTENT)
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
pub struct SetRealmStatusRequest {
    pub enabled: bool,
}

/// Enable or disable a realm
pub async fn set_realm_status(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
    Json(request): Json<SetRealmStatusRequest>,
) -> Result<StatusCode, StatusCode> {
    let realm_id = if let Ok(uuid) = Uuid::parse_str(&identifier) {
        uuid
    } else {
        // Get realm by name to find ID
        let realm = state.realm_service.get_realm_by_name(&identifier)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;
        realm.id
    };

    match state.realm_service.set_realm_enabled(&realm_id, request.enabled).await {
        Ok(_) => {
            // Fire admin event for realm status change
            let auth_details = crate::models::events::AuthDetails {
                user_id: "system".to_string(),
                username: Some("system".to_string()),
                ip_address: None,
                user_agent: None,
            };

            let admin_event = crate::services::events::AdminEventBuilder::new(
                realm_id.to_string(),
                auth_details,
                crate::models::events::ResourceType::Realm,
                crate::models::events::OperationType::Action,
                format!("/realms/{}/status", realm_id),
            )
            .representation(format!("{{\"enabled\": {}}}", request.enabled))
            .build();

            if let Err(e) = state.event_manager.write().await.fire_admin_event(admin_event, false).await {
                tracing::error!("Failed to fire realm status change admin event: {}", e);
            }

            Ok(StatusCode::OK)
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
