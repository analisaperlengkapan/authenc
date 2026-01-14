use crate::error::{AuthencError, Result};
use crate::services::device::{
    DeviceRegistrationRequest, DeviceService, TrustEvaluationContext,
};
use axum::{
    Router,
    extract::{Extension, Path, Query, State, Json},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use crate::app::AppState;

/// Create device management routes
pub fn create_device_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(register_device))
        .route("/", get(list_devices))
        .route("/{id}", get(get_device))
        .route("/{id}", put(update_device))
        .route("/{id}", delete(delete_device))
        .route("/{id}/trust", post(evaluate_trust))
        .route("/{id}/sessions", get(get_device_sessions))
        .route("/{id}/sessions", post(create_session))
        .route(
            "/sessions/{session_id}/activity",
            put(update_session_activity),
        )
        .route("/sessions/{session_id}", delete(end_session))
}

/// Register device request
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    /// Human-readable name for the device
    pub device_name: String,
    /// Operating system name (e.g., "iOS", "Android", "Windows")
    pub os: String,
    /// Operating system version
    pub os_version: String,
    /// Browser name if applicable
    pub browser: Option<String>,
    /// Browser version if applicable
    pub browser_version: Option<String>,
    /// IP address of the device during registration
    pub ip_address: String,
    /// User agent string from the device
    pub user_agent: String,
    /// Whether the device has biometric authentication capabilities
    pub has_biometrics: bool,
    /// Whether the device has hardware security features
    pub has_hardware_security: bool,
    /// Whether the device has screen lock enabled
    pub has_screen_lock: bool,
    /// Whether the device has encryption enabled
    pub encryption_enabled: bool,
    /// Whether the device supports remote wipe functionality
    pub remote_wipe_capable: bool,
    /// Whether jailbreak/root detection was triggered
    pub jailbreak_detected: bool,
}

/// Register device handler
pub async fn register_device(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let device_request = DeviceRegistrationRequest {
        device_name: request.device_name,
        os: request.os,
        os_version: request.os_version,
        browser: request.browser,
        browser_version: request.browser_version,
        ip_address: request.ip_address,
        user_agent: request.user_agent,
        security_features: crate::services::device::DeviceSecurityFeatures {
            has_biometrics: request.has_biometrics,
            has_hardware_security: request.has_hardware_security,
            has_screen_lock: request.has_screen_lock,
            encryption_enabled: request.encryption_enabled,
            remote_wipe_capable: request.remote_wipe_capable,
            jailbreak_detected: request.jailbreak_detected,
        },
    };

    match service.register_device(user_id, device_request).await {
        Ok(device) => Ok(Json(serde_json::json!({
            "success": true,
            "device": device
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// List devices handler
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    match service.get_user_devices(user_id).await {
        Ok(devices) => Ok(Json(serde_json::json!({
            "success": true,
            "devices": devices
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Get device handler
pub async fn get_device(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    // Check ownership before returning device details
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    match service.get_device(id).await {
        Ok(Some(device)) => {
            if device.user_id != user_id {
                return Err(AuthencError::forbidden("Access denied to this device"));
            }
            Ok(Json(serde_json::json!({
                "success": true,
                "device": device
            })))
        }
        Ok(None) => Err(AuthencError::resource_not_found("Resource not found")),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Update device request
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateDeviceRequest {
    /// Optional new name for the device
    pub device_name: Option<String>,
    /// Optional updated trust score (0.0 to 1.0)
    pub trust_score: Option<f64>,
    /// Optional trust status override
    pub is_trusted: Option<bool>,
}

/// Update device handler
/// Update device handler
#[axum::debug_handler]
pub async fn update_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Json(update_request): Json<UpdateDeviceRequest>,
) -> crate::error::Result<impl axum::response::IntoResponse> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Verify ownership
    let device_opt = service.get_device(id).await.map_err(|_| AuthencError::internal("Error checking device"))?;

    if let Some(device) = device_opt {
        if device.user_id != user_id {
            return Err(AuthencError::forbidden("Access denied to this device"));
        }
    } else {
        return Err(AuthencError::resource_not_found("Device not found"));
    }


    let updates = crate::services::device::DeviceUpdateRequest {
        device_name: update_request.device_name,
        trust_score: update_request.trust_score,
        is_trusted: update_request.is_trusted,
        security_features: None,
    };

    match service.update_device(id, updates).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Device updated successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Delete device handler
pub async fn delete_device(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Verify ownership
    if let Some(device) = service.get_device(id).await.map_err(|_| AuthencError::internal("Error checking device"))? {
        if device.user_id != user_id {
            return Err(AuthencError::forbidden("Access denied to this device"));
        }
    } else {
        return Err(AuthencError::resource_not_found("Device not found"));
    }

    // Delete the device using the service
    match service.delete_device(id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Device deleted successfully"
        }))),
        Err(e) => Err(e),
    }
}

/// Evaluate device trust request
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluateTrustRequest {
    /// Whether this is the first login for this user
    pub is_first_login: bool,
    /// Whether this device is known/registered
    pub known_device: bool,
    /// Whether the login time is unusual
    pub unusual_time: bool,
    /// Whether the location has changed significantly
    pub location_changed: bool,
    /// IP reputation score (0.0 to 1.0, higher is better)
    pub ip_reputation: f64,
    /// Whether the device fingerprint matches known patterns
    pub fingerprint_match: bool,
}

/// Evaluate device trust handler
pub async fn evaluate_trust(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(request): Json<EvaluateTrustRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let device = match service.get_device(id).await {
        Ok(Some(device)) => {
            if device.user_id != user_id {
                return Err(AuthencError::forbidden("Access denied to this device"));
            }
            device
        },
        Ok(None) => return Err(AuthencError::resource_not_found("Resource not found")),
        Err(_) => return Err(AuthencError::internal("Internal server error")),
    };

    let context = TrustEvaluationContext {
        is_first_login: request.is_first_login,
        known_device: request.known_device,
        unusual_time: request.unusual_time,
        location_changed: request.location_changed,
        ip_reputation: request.ip_reputation,
        fingerprint_match: request.fingerprint_match,
    };

    match service.evaluate_trust(&device, &context).await {
        Ok(trust_result) => Ok(Json(serde_json::json!({
            "success": true,
            "trust_result": trust_result
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Get device sessions handler
pub async fn get_device_sessions(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Verify ownership
    if let Some(device) = service.get_device(id).await.map_err(|_| AuthencError::internal("Error checking device"))?
        && device.user_id != user_id {
            return Err(AuthencError::forbidden("Access denied to this device"));
        }

    match service.get_device_sessions(id).await {
        Ok(sessions) => Ok(Json(serde_json::json!({
            "success": true,
            "sessions": sessions
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Create session request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    /// Unique session identifier
    pub session_id: String,
    /// IP address where the session was created
    pub ip_address: String,
}

/// Create device session handler
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Verify ownership
    if let Some(device) = service.get_device(id).await.map_err(|_| AuthencError::internal("Error checking device"))?
        && device.user_id != user_id {
            return Err(AuthencError::forbidden("Access denied to this device"));
        }

    match service
        .create_session(id, user_id, request.session_id, request.ip_address)
        .await
    {
        Ok(session) => Ok(Json(serde_json::json!({
            "success": true,
            "session": session
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Update session activity handler
pub async fn update_session_activity(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    match service.update_session_activity(session_id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Session activity updated"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// End session handler
pub async fn end_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(state.database.clone());

    match service.end_session(session_id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Session ended successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}
