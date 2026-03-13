use crate::app::AppState;
use crate::handlers::api::auth_bearer::AuthBearer;
use authenc_models::models::events::{OperationType, ResourceType};
use authenc_models::models::oidc_client::OidcClient;
use authenc_services::services::events::AdminEventBuilder;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use std::sync::Arc;

/// Create client management routes for a realm
pub fn create_client_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/realms/{realm}/clients", get(get_clients))
        .route("/realms/{realm}/clients", post(create_client))
        .route("/realms/{realm}/clients/{client_id}", get(get_client))
        .route("/realms/{realm}/clients/{client_id}", put(update_client))
        .route("/realms/{realm}/clients/{client_id}", delete(delete_client))
}

/// Get all clients in the specified realm
pub async fn get_clients(
    State(state): State<Arc<AppState>>,
    AuthBearer(_auth): AuthBearer,
    Path(realm): Path<String>,
) -> Result<Json<Vec<OidcClient>>, StatusCode> {
    // Get realm by name to validate it exists
    let _realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    match state.oidc_client_store.all().await {
        Ok(clients) => {
            // Filter clients by realm and remove sensitive data
            let safe_clients: Vec<OidcClient> = clients
                .into_iter()
                .filter(|c| c.realm_id == _realm_obj.id)
                .map(|mut c| {
                    c.client_secret = "".to_string();
                    c
                })
                .collect();
            Ok(Json(safe_clients))
        },

        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Get a specific client by client ID
pub async fn get_client(
    State(state): State<Arc<AppState>>,
    AuthBearer(_auth): AuthBearer,
    Path((realm, client_id)): Path<(String, String)>,
) -> Result<Json<OidcClient>, StatusCode> {
    // Get realm by name to validate it exists
    let _realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    match state.oidc_client_store.get(&client_id).await {
        Ok(Some(client)) => Ok(Json(client)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize, Clone)]
/// Request payload for creating a new client within a realm
pub struct CreateClientRequest {
    /// OAuth 2.0 client identifier
    pub client_id: String,
    /// OAuth 2.0 client secret
    pub client_secret: String,
    /// List of allowed redirect URIs
    pub redirect_uris: Vec<String>,
    /// Human-readable display name for the client
    pub name: String,
    /// Whether the client is enabled
    pub enabled: Option<bool>,
}

/// Create a new client in the specified realm
pub async fn create_client(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path(realm): Path<String>,
    Json(req): Json<CreateClientRequest>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Check if client already exists
    if state
        .oidc_client_store
        .get(&req.client_id)
        .await
        .unwrap_or(None)
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    // Create the client
    let client = OidcClient {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: req.client_id.clone(),
        client_secret: req.client_secret.clone(),
        redirect_uris: req.redirect_uris.clone(),
        name: req.name.clone(),
        realm_id: realm_obj.id,
        enabled: req.enabled.unwrap_or(true),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    if let Err(_) = state.oidc_client_store.add(client.clone()).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let resource_path = format!("/realms/{}/clients/{}", realm, client.client_id);
    let representation = serde_json::to_string(&client).unwrap_or_default();

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::Client,
        OperationType::Create,
        resource_path,
    )
    .representation(representation)
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!("Failed to fire admin event for client creation: {}", e);
    }

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, Clone)]
/// Request payload for updating a client
pub struct UpdateClientRequest {
    /// OAuth 2.0 client secret (optional)
    pub client_secret: Option<String>,
    /// List of allowed redirect URIs (optional)
    pub redirect_uris: Option<Vec<String>>,
    /// Human-readable display name for the client (optional)
    pub name: Option<String>,
    /// Whether the client is enabled (optional)
    pub enabled: Option<bool>,
}

/// Update an existing client
pub async fn update_client(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, client_id)): Path<(String, String)>,
    Json(req): Json<UpdateClientRequest>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get the existing client
    let mut client = match state.oidc_client_store.get(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Store the old representation for the event
    let _old_representation = serde_json::to_string(&client).unwrap_or_default();

    // Update the client fields
    if let Some(client_secret) = req.client_secret {
        client.client_secret = client_secret;
    }
    if let Some(redirect_uris) = req.redirect_uris {
        client.redirect_uris = redirect_uris;
    }
    if let Some(name) = req.name {
        client.name = name;
    }
    if let Some(enabled) = req.enabled {
        client.enabled = enabled;
    }

    // For now, we'll delete and re-add since the store doesn't have an update method
    // In a real implementation, you'd want an update method
    if state.oidc_client_store.delete(&client_id).await.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    if state
        .oidc_client_store
        .add(client.clone())
        .await
        .is_err()
    {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let resource_path = format!("/realms/{}/clients/{}", realm, client_id);
    let new_representation = serde_json::to_string(&client).unwrap_or_default();

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::Client,
        OperationType::Update,
        resource_path,
    )
    .representation(new_representation)
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!("Failed to fire admin event for client update: {}", e);
    }

    Ok(StatusCode::OK)
}

/// Delete a client from the specified realm
pub async fn delete_client(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, client_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get the client before deleting for event representation
    let client = match state.oidc_client_store.get(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Delete the client
    match state.oidc_client_store.delete(&client_id).await {
        Ok(true) => {
            // Fire admin event
            let auth_details = crate::models::events::AuthDetails {
                user_id: auth.sub.clone(),
                username: None,   // Could be looked up from user store if needed
                ip_address: None, // Could be extracted from request headers
                user_agent: None, // Could be extracted from request headers
            };

            let resource_path = format!("/realms/{}/clients/{}", realm, client_id);
            let representation = serde_json::to_string(&client).unwrap_or_default();

            let admin_event = AdminEventBuilder::new(
                realm_obj.id.to_string(),
                auth_details,
                ResourceType::Client,
                OperationType::Delete,
                resource_path,
            )
            .representation(representation)
            .build();

            if let Err(e) = state
                .event_manager
                .write()
                .await
                .fire_admin_event(admin_event, true)
                .await
            {
                tracing::error!("Failed to fire admin event for client deletion: {}", e);
            }

            Ok(StatusCode::NO_CONTENT)
        }
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
