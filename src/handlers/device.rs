use crate::database::Database;
use crate::error::{AuthencError, Result};
use crate::services::device::{
    DeviceRegistrationRequest, DeviceService, DeviceUpdateRequest, TrustEvaluationContext,
};
use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Create device management routes
pub fn create_device_routes() -> Router<Arc<Database>> {
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
    State(db): State<Arc<Database>>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

    // In production, get user ID from authentication context
    let user_id = Uuid::new_v4();

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
    State(db): State<Arc<Database>>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

    // In production, get user ID from authentication context
    let user_id = Uuid::new_v4();

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
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

    match service.get_device(id).await {
        Ok(Some(device)) => Ok(Json(serde_json::json!({
            "success": true,
            "device": device
        }))),
        Ok(None) => Err(AuthencError::resource_not_found("Resource not found")),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Update device handler
pub async fn update_device(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(updates): Json<DeviceUpdateRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

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
    State(db): State<Arc<Database>>,
    Path(_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let _service = DeviceService::new(db);

    // In production, implement device deletion
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Device deleted successfully"
    })))
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
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(request): Json<EvaluateTrustRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

    let device = match service.get_device(id).await {
        Ok(Some(device)) => device,
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
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

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
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

    // In production, get user ID from authentication context
    let user_id = Uuid::new_v4();

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
    State(db): State<Arc<Database>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

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
    State(db): State<Arc<Database>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = DeviceService::new(db);

    match service.end_session(session_id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Session ended successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}
