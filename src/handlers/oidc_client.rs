//! OIDC Client management handlers for Axum
//!
//! This module provides endpoints for managing OIDC clients
//! including listing, creating, and deleting clients.

use crate::models::oidc_client::OidcClient;
use crate::services::stores::oidc_client_store::OidcClientStore;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request payload for creating an OIDC client
#[derive(Debug, Deserialize)]
pub struct CreateOidcClientRequest {
    /// Client identifier
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// List of allowed redirect URIs
    pub redirect_uris: Vec<String>,
    /// Human-readable client name
    pub name: String,
}

/// Response for OIDC client operations
#[derive(Debug, Serialize)]
pub struct OidcClientResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Message describing the result
    pub message: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

/// List all OIDC clients
///
/// GET /oidc/clients
pub async fn list_oidc_clients(
    State(store): State<Arc<OidcClientStore>>,
) -> Result<Json<Vec<OidcClient>>, (StatusCode, Json<ErrorResponse>)> {
    match store.all().await {
        Ok(clients) => Ok(Json(clients)),
        Err(e) => {
            tracing::error!("Failed to list OIDC clients: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Client store error: {}", e),
                }),
            ))
        }
    }
}

/// Create a new OIDC client
///
/// POST /oidc/clients
pub async fn create_oidc_client(
    State(store): State<Arc<OidcClientStore>>,
    Json(req): Json<CreateOidcClientRequest>,
) -> impl IntoResponse {
    let client = OidcClient {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: req.client_id.clone(),
        client_secret: req.client_secret,
        redirect_uris: req.redirect_uris,
        name: req.name,
        realm_id: uuid::Uuid::nil(), // Default/Global realm for simple OIDC clients
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match store.add(client).await {
        Ok(_) => {
            tracing::info!("Created OIDC client: {}", req.client_id);
            (
                StatusCode::CREATED,
                Json(OidcClientResponse {
                    success: true,
                    message: "OIDC client created".to_string(),
                }),
            )
        }
        Err(e) => {
            tracing::error!("Failed to create OIDC client: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OidcClientResponse {
                    success: false,
                    message: format!("Client store error: {}", e),
                }),
            )
        }
    }
}

/// Delete an OIDC client
///
/// DELETE /oidc/clients/{client_id}
pub async fn delete_oidc_client(
    State(store): State<Arc<OidcClientStore>>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    match store.delete(&client_id).await {
        Ok(true) => {
            tracing::info!("Deleted OIDC client: {}", client_id);
            (
                StatusCode::OK,
                Json(OidcClientResponse {
                    success: true,
                    message: "OIDC client deleted".to_string(),
                }),
            )
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(OidcClientResponse {
                success: false,
                message: "Client not found".to_string(),
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to delete OIDC client: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OidcClientResponse {
                    success: false,
                    message: format!("Client store error: {}", e),
                }),
            )
        }
    }
}

/// Get a specific OIDC client by ID
///
/// GET /oidc/clients/{client_id}
pub async fn get_oidc_client(
    State(store): State<Arc<OidcClientStore>>,
    Path(client_id): Path<String>,
) -> Result<Json<OidcClient>, (StatusCode, Json<ErrorResponse>)> {
    match store.get(&client_id).await {
        Ok(Some(client)) => Ok(Json(client)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Client not found".to_string(),
            }),
        )),
        Err(e) => {
            tracing::error!("Failed to get OIDC client: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Client store error: {}", e),
                }),
            ))
        }
    }
}

/// Create OIDC client management routes for the application
pub fn create_oidc_client_routes() -> Router<Arc<OidcClientStore>> {
    Router::new()
        .route("/oidc/clients", get(list_oidc_clients))
        .route("/oidc/clients", post(create_oidc_client))
        .route("/oidc/clients/{client_id}", get(get_oidc_client))
        .route("/oidc/clients/{client_id}", delete(delete_oidc_client))
}
