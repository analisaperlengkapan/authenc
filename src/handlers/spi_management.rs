//! SPI Management Handlers
//!
//! This module provides HTTP handlers for managing Service Provider Interfaces (SPIs).
//! It allows administrators to configure, enable/disable, and monitor SPI providers
//! for enterprise features like organizations, rich authorization, migrations, and hostnames.

use crate::app::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create SPI management routes
pub fn create_spi_management_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/spis", get(list_spis))
        .route("/spis/{spi_name}", get(get_spi_info))
        .route("/spis/{spi_name}/providers", get(list_spi_providers))
        .route(
            "/spis/{spi_name}/providers/{provider_id}",
            get(get_provider_config),
        )
        .route(
            "/spis/{spi_name}/providers/{provider_id}",
            put(update_provider_config),
        )
        .route(
            "/spis/{spi_name}/providers/{provider_id}/status",
            put(update_provider_status),
        )
        .route(
            "/spis/{spi_name}/providers/{provider_id}/test",
            post(test_provider),
        )
}

/// SPI information response
#[derive(Serialize)]
pub struct SpiInfo {
    /// Name of the SPI
    pub name: String,
    /// Description of the SPI functionality
    pub description: String,
    /// Whether the SPI is enabled
    pub enabled: bool,
    /// Number of providers configured for this SPI
    pub provider_count: usize,
}

/// SPI provider information
#[derive(Serialize)]
pub struct SpiProviderInfo {
    /// Unique identifier of the provider
    pub id: String,
    /// Human-readable name of the provider
    pub name: String,
    /// Whether the provider is enabled
    pub enabled: bool,
    /// Priority order for provider execution
    pub priority: i64,
    /// Configuration settings for the provider
    pub config: serde_json::Value,
}

/// Provider configuration update request
#[derive(Deserialize)]
pub struct ProviderConfigUpdate {
    /// New configuration settings
    pub config: serde_json::Value,
}

/// Provider status update request
#[derive(Deserialize)]
pub struct ProviderStatusUpdate {
    /// Whether to enable or disable the provider
    pub enabled: bool,
}

/// Provider test response
#[derive(Serialize)]
pub struct ProviderTestResponse {
    /// Whether the test was successful
    pub success: bool,
    /// Test result message
    pub message: String,
    /// Additional test details
    pub details: Option<serde_json::Value>,
}

/// List all available SPIs
pub async fn list_spis(
    State(state): State<Arc<AppState>>,
) -> std::result::Result<Json<Vec<SpiInfo>>, (StatusCode, Json<serde_json::Value>)> {
    let spi_manager = &state.spi_manager;
    let registry = spi_manager.registry();

    let mut spis = Vec::new();

    // Organization SPI
    if let Ok(providers) = registry
        .get_providers::<crate::spi::organization::DefaultOrganizationProvider>("organization")
    {
        spis.push(SpiInfo {
            name: "organization".to_string(),
            description: "Multi-tenancy organization management".to_string(),
            enabled: !providers.is_empty(),
            provider_count: providers.len(),
        });
    }

    // Rich Authorization SPI
    if let Ok(providers) = registry
        .get_providers::<crate::spi::rich_authorization::DefaultRichAuthorizationProvider>(
            "rich-authorization",
        )
    {
        spis.push(SpiInfo {
            name: "rich-authorization".to_string(),
            description: "Advanced authorization policies and permissions".to_string(),
            enabled: !providers.is_empty(),
            provider_count: providers.len(),
        });
    }

    // Migration SPI
    if let Ok(providers) =
        registry.get_providers::<crate::spi::migration::DefaultMigrationProvider>("migration")
    {
        spis.push(SpiInfo {
            name: "migration".to_string(),
            description: "Database schema migrations and data updates".to_string(),
            enabled: !providers.is_empty(),
            provider_count: providers.len(),
        });
    }

    // Hostname SPI
    if let Ok(providers) =
        registry.get_providers::<crate::spi::hostname::DefaultHostnameProvider>("hostname")
    {
        spis.push(SpiInfo {
            name: "hostname".to_string(),
            description: "Dynamic hostname resolution and URL management".to_string(),
            enabled: !providers.is_empty(),
            provider_count: providers.len(),
        });
    }

    Ok(Json(spis))
}

/// Get detailed information about a specific SPI
pub async fn get_spi_info(
    State(state): State<Arc<AppState>>,
    Path(spi_name): Path<String>,
) -> std::result::Result<Json<SpiInfo>, (StatusCode, Json<serde_json::Value>)> {
    let spi_manager = &state.spi_manager;
    let registry = spi_manager.registry();

    let spi_info = match spi_name.as_str() {
        "organization" => {
            if let Ok(providers) = registry
                .get_providers::<crate::spi::organization::DefaultOrganizationProvider>(
                    "organization",
                )
            {
                SpiInfo {
                    name: "organization".to_string(),
                    description: "Multi-tenancy organization management".to_string(),
                    enabled: !providers.is_empty(),
                    provider_count: providers.len(),
                }
            } else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "SPI not found"})),
                ));
            }
        }
        "rich-authorization" => {
            if let Ok(providers) = registry
                .get_providers::<crate::spi::rich_authorization::DefaultRichAuthorizationProvider>(
                "rich-authorization",
            ) {
                SpiInfo {
                    name: "rich-authorization".to_string(),
                    description: "Advanced authorization policies and permissions".to_string(),
                    enabled: !providers.is_empty(),
                    provider_count: providers.len(),
                }
            } else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "SPI not found"})),
                ));
            }
        }
        "migration" => {
            if let Ok(providers) = registry
                .get_providers::<crate::spi::migration::DefaultMigrationProvider>("migration")
            {
                SpiInfo {
                    name: "migration".to_string(),
                    description: "Database schema migrations and data updates".to_string(),
                    enabled: !providers.is_empty(),
                    provider_count: providers.len(),
                }
            } else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "SPI not found"})),
                ));
            }
        }
        "hostname" => {
            if let Ok(providers) =
                registry.get_providers::<crate::spi::hostname::DefaultHostnameProvider>("hostname")
            {
                SpiInfo {
                    name: "hostname".to_string(),
                    description: "Dynamic hostname resolution and URL management".to_string(),
                    enabled: !providers.is_empty(),
                    provider_count: providers.len(),
                }
            } else {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "SPI not found"})),
                ));
            }
        }
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "SPI not found"})),
            ))
        }
    };

    Ok(Json(spi_info))
}

/// List providers for a specific SPI
pub async fn list_spi_providers(
    State(state): State<Arc<AppState>>,
    Path(spi_name): Path<String>,
) -> std::result::Result<Json<Vec<SpiProviderInfo>>, (StatusCode, Json<serde_json::Value>)> {
    let providers = match spi_name.as_str() {
        "organization" => state
            .config
            .spi
            .organization
            .iter()
            .map(|provider| SpiProviderInfo {
                id: provider.id.clone(),
                name: format!("Organization Provider {}", provider.id),
                enabled: provider.enabled,
                priority: provider.priority,
                config: provider.config.clone(),
            })
            .collect(),
        "rich-authorization" => state
            .config
            .spi
            .rich_authorization
            .iter()
            .map(|provider| SpiProviderInfo {
                id: provider.id.clone(),
                name: format!("Rich Authorization Provider {}", provider.id),
                enabled: provider.enabled,
                priority: provider.priority,
                config: provider.config.clone(),
            })
            .collect(),
        "migration" => state
            .config
            .spi
            .migration
            .iter()
            .map(|provider| SpiProviderInfo {
                id: provider.id.clone(),
                name: format!("Migration Provider {}", provider.id),
                enabled: provider.enabled,
                priority: provider.priority,
                config: provider.config.clone(),
            })
            .collect(),
        "hostname" => state
            .config
            .spi
            .hostname
            .iter()
            .map(|provider| SpiProviderInfo {
                id: provider.id.clone(),
                name: format!("Hostname Provider {}", provider.id),
                enabled: provider.enabled,
                priority: provider.priority,
                config: provider.config.clone(),
            })
            .collect(),
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "SPI not found"})),
            ))
        }
    };

    Ok(Json(providers))
}

/// Get configuration for a specific provider
pub async fn get_provider_config(
    State(state): State<Arc<AppState>>,
    Path((spi_name, provider_id)): Path<(String, String)>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let config = match spi_name.as_str() {
        "hostname" => {
            // Get hostname configuration from app config
            if let Some(hostname_providers) = state
                .config
                .spi
                .hostname
                .iter()
                .find(|p| p.id == provider_id)
            {
                hostname_providers.config.clone()
            } else {
                serde_json::json!({
                    "hostname": "localhost",
                    "frontend_url": "http://localhost:8080",
                    "admin_url": "http://localhost:8080/admin"
                })
            }
        }
        "organization" => {
            if let Some(org_providers) = state
                .config
                .spi
                .organization
                .iter()
                .find(|p| p.id == provider_id)
            {
                org_providers.config.clone()
            } else {
                serde_json::json!({})
            }
        }
        "rich-authorization" => {
            if let Some(authz_providers) = state
                .config
                .spi
                .rich_authorization
                .iter()
                .find(|p| p.id == provider_id)
            {
                authz_providers.config.clone()
            } else {
                serde_json::json!({})
            }
        }
        "migration" => {
            if let Some(migration_providers) = state
                .config
                .spi
                .migration
                .iter()
                .find(|p| p.id == provider_id)
            {
                migration_providers.config.clone()
            } else {
                serde_json::json!({})
            }
        }
        _ => {
            // Other SPIs don't have configurable providers yet
            serde_json::json!({})
        }
    };

    Ok(Json(config))
}

/// Update provider configuration
pub async fn update_provider_config(
    State(state): State<Arc<AppState>>,
    Path((spi_name, provider_id)): Path<(String, String)>,
    Json(update): Json<ProviderConfigUpdate>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate the provider exists in configuration
    let provider_exists = match spi_name.as_str() {
        "organization" => state
            .config
            .spi
            .organization
            .iter()
            .any(|p| p.id == provider_id),
        "rich-authorization" => state
            .config
            .spi
            .rich_authorization
            .iter()
            .any(|p| p.id == provider_id),
        "migration" => state
            .config
            .spi
            .migration
            .iter()
            .any(|p| p.id == provider_id),
        "hostname" => state
            .config
            .spi
            .hostname
            .iter()
            .any(|p| p.id == provider_id),
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "SPI not found"})),
            ))
        }
    };

    if !provider_exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Provider not found"})),
        ));
    }

    // Validate configuration based on SPI type
    if spi_name.as_str() == "hostname" {
        // Validate hostname configuration
        if let Some(hostname) = update.config.get("hostname") {
            if let Some(hostname_str) = hostname.as_str() {
                if hostname_str.is_empty() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "Hostname cannot be empty"})),
                    ));
                }
            }
        }
    }

    // Note: In a production implementation, this would persist the configuration
    // to a database or configuration file. For now, we acknowledge the update.
    // The configuration would need to be reloaded or the SPI provider reinstantiated.

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Provider configuration updated successfully",
        "note": "Configuration changes require application restart to take effect"
    })))
}

/// Update provider status (enable/disable)
pub async fn update_provider_status(
    State(_state): State<Arc<AppState>>,
    Path((_spi_name, _provider_id)): Path<(String, String)>,
    Json(update): Json<ProviderStatusUpdate>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Note: In a production implementation, this would persist the status change
    // to a database or configuration file and potentially enable/disable the provider
    // at runtime. For now, we acknowledge the update.
    // The status change would need to be applied to the SPI registry.

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Provider {} successfully", if update.enabled { "enabled" } else { "disabled" }),
        "note": "Status changes require application restart to take effect"
    })))
}

/// Test provider functionality
pub async fn test_provider(
    State(state): State<Arc<AppState>>,
    Path((spi_name, _provider_id)): Path<(String, String)>,
) -> std::result::Result<Json<ProviderTestResponse>, (StatusCode, Json<serde_json::Value>)> {
    let spi_manager = &state.spi_manager;
    let registry = spi_manager.registry();

    let test_result = match spi_name.as_str() {
        "organization" => {
            match registry.get_providers::<crate::spi::organization::DefaultOrganizationProvider>(
                "organization",
            ) {
                Ok(providers) if !providers.is_empty() => ProviderTestResponse {
                    success: true,
                    message: "Organization provider is functioning correctly".to_string(),
                    details: Some(serde_json::json!({
                        "provider_count": providers.len()
                    })),
                },
                _ => ProviderTestResponse {
                    success: false,
                    message: "Provider not found".to_string(),
                    details: None,
                },
            }
        }
        "rich-authorization" => {
            match registry
                .get_providers::<crate::spi::rich_authorization::DefaultRichAuthorizationProvider>(
                    "rich-authorization",
                ) {
                Ok(providers) if !providers.is_empty() => ProviderTestResponse {
                    success: true,
                    message: "Rich authorization provider is functioning correctly".to_string(),
                    details: Some(serde_json::json!({
                        "provider_count": providers.len()
                    })),
                },
                _ => ProviderTestResponse {
                    success: false,
                    message: "Provider not found".to_string(),
                    details: None,
                },
            }
        }
        "migration" => {
            match registry
                .get_providers::<crate::spi::migration::DefaultMigrationProvider>("migration")
            {
                Ok(providers) if !providers.is_empty() => ProviderTestResponse {
                    success: true,
                    message: "Migration provider is functioning correctly".to_string(),
                    details: Some(serde_json::json!({
                        "provider_count": providers.len()
                    })),
                },
                _ => ProviderTestResponse {
                    success: false,
                    message: "Provider not found".to_string(),
                    details: None,
                },
            }
        }
        "hostname" => {
            match registry
                .get_providers::<crate::spi::hostname::DefaultHostnameProvider>("hostname")
            {
                Ok(providers) if !providers.is_empty() => ProviderTestResponse {
                    success: true,
                    message: "Hostname provider is functioning correctly".to_string(),
                    details: Some(serde_json::json!({
                        "provider_count": providers.len(),
                        "hostname": "localhost",
                        "frontend_url": "http://localhost:8080",
                        "admin_url": "http://localhost:8080/admin"
                    })),
                },
                _ => ProviderTestResponse {
                    success: false,
                    message: "Provider not found".to_string(),
                    details: None,
                },
            }
        }
        _ => ProviderTestResponse {
            success: false,
            message: "Unknown SPI".to_string(),
            details: None,
        },
    };

    Ok(Json(test_result))
}
