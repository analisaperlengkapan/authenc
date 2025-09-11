use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, delete},
    Router,
};
use crate::services::realm_store::RealmStore;
use crate::models::realm::Realm;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub fn create_realm_routes() -> Router<Arc<RealmStore>> {
    Router::new()
        .route("/realms", get(get_realms))
        .route("/realms/{name}", get(get_realm_by_name))
        .route("/realms", post(create_realm))
        .route("/realms/{name}", delete(delete_realm))
}

pub async fn get_realms(
    State(store): State<Arc<RealmStore>>,
) -> Result<Json<Vec<Realm>>, StatusCode> {
    let realms = store.get_all();
    Ok(Json(realms))
}

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
pub struct CreateRealmRequest {
    pub name: String,
    pub enabled: Option<bool>,
}

pub async fn create_realm(
    State(_store): State<Arc<RealmStore>>,
    Json(_req): Json<CreateRealmRequest>,
) -> Result<StatusCode, StatusCode> {
    // TODO: Implement proper realm creation with all required fields
    // For now, return Not Implemented
    Err(StatusCode::NOT_IMPLEMENTED)
}

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