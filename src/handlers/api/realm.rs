use crate::models::realm::Realm;
use crate::services::realm_store::RealmStore;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;

/// Create realm management routes
pub fn create_realm_routes() -> Router<Arc<RealmStore>> {
    Router::new()
        .route("/realms", get(get_realms))
        .route("/realms/{name}", get(get_realm_by_name))
        .route("/realms", post(create_realm))
        .route("/realms/{name}", delete(delete_realm))
}

/// Get all realms in the system
pub async fn get_realms(
    State(store): State<Arc<RealmStore>>,
) -> Result<Json<Vec<Realm>>, StatusCode> {
    let realms = store.get_all();
    Ok(Json(realms))
}

/// Get a specific realm by name
pub async fn get_realm_by_name(
    State(store): State<Arc<RealmStore>>,
    Path(name): Path<String>,
) -> Result<Json<Realm>, StatusCode> {
    if let Some(realm) = store.get_by_name(&name) {
        Ok(Json(realm))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
/// Request payload for creating a new authentication realm
pub struct CreateRealmRequest {
    /// The unique name identifier for the realm
    pub name: String,
    /// Whether the realm should be enabled upon creation
    pub enabled: Option<bool>,
}

/// Create a new realm in the system
pub async fn create_realm(
    State(_store): State<Arc<RealmStore>>,
    Json(_req): Json<CreateRealmRequest>,
) -> Result<StatusCode, StatusCode> {
    // TODO: Implement proper realm creation with all required fields
    // For now, return Not Implemented
    Err(StatusCode::NOT_IMPLEMENTED)
}

/// Delete a realm from the system
pub async fn delete_realm(
    State(store): State<Arc<RealmStore>>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut realms = store.realms.lock().unwrap();
    let len_before = realms.len();
    realms.retain(|r| r.name != name);
    if realms.len() < len_before {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
