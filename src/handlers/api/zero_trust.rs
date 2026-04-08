use axum::{
    Router,
    extract::{ConnectInfo, Query, State},
    response::Json,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AuthencError;
use authenc_services::services::security::zero_trust::{
    AdaptiveControls, AuthContext, RiskAssessment, RiskLevel,
    ContinuousAuthService, Location, DeviceInfo,
    extract_os, extract_browser,
};

#[derive(Deserialize)]
/// Request payload for assessing security risk of a user action
pub struct AssessRiskRequest {
    /// Session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: Uuid,
    /// Device fingerprint for tracking
    pub device_fingerprint: String,
    /// User agent string
    pub user_agent: String,
    /// IP address of the request
    pub ip_address: String,
    /// Geographic location information
    pub location: Option<Location>,
}

#[derive(Serialize)]
/// Response payload containing risk assessment results
pub struct RiskAssessmentResponse {
    /// Server-generated device identifier (use this for verify_session)
    pub device_id: String,
    /// Risk score between 0.0 and 1.0
    pub score: f64,
    /// Risk level classification
    pub level: RiskLevel,
    /// Factors contributing to the risk score
    pub factors: Vec<String>,
    /// Recommended actions to mitigate risk
    pub recommendations: Vec<String>,
    /// Timestamp when assessment was performed
    pub assessed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
/// Request payload for updating adaptive security controls
pub struct UpdateAdaptiveControlsRequest {
    /// Session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: Uuid,
    /// Adaptive controls to apply
    pub controls: AdaptiveControls,
}

#[derive(Serialize)]
/// Response payload containing updated adaptive controls
pub struct AdaptiveControlsResponse {
    /// Session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: Uuid,
    /// Applied adaptive controls
    pub controls: AdaptiveControls,
    /// Timestamp when controls were updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
/// Request payload for verifying session validity
pub struct VerifySessionRequest {
    /// Session identifier (for logging/context)
    pub session_id: String,
    /// Server-generated device identifier (returned by assess_risk)
    pub device_id: String,
}

#[derive(Serialize)]
/// Response payload containing session verification results
pub struct SessionVerificationResponse {
    /// Whether the session is valid
    pub valid: bool,
    /// Current risk score for the session
    pub risk_score: f64,
    /// Whether additional authentication is required
    pub requires_additional_auth: bool,
    /// Active adaptive controls for the session
    pub adaptive_controls: AdaptiveControls,
}

#[derive(Deserialize)]
/// Query parameters for retrieving risk analytics data
pub struct GetRiskAnalyticsQuery {
    /// Filter by realm ID
    pub realm_id: Option<Uuid>,
    /// Start date for analytics period
    pub from_date: Option<chrono::DateTime<chrono::Utc>>,
    /// End date for analytics period
    pub to_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// Assess risk for a user action
pub async fn assess_risk(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<AssessRiskRequest>,
) -> Result<Json<RiskAssessmentResponse>, AuthencError> {
    // Always use the real connection IP for security decisions, never the
    // client-provided ip_address.  A malicious client could spoof a private IP
    // (e.g. 192.168.1.1) to gain higher trust scores, or send another user's
    // IP to inherit their device trust entry.
    let real_ip = addr.ip().to_string();

    // Create device info, parsing OS and browser from the user agent
    let device_info = DeviceInfo {
        user_agent: request.user_agent.clone(),
        ip_address: real_ip.clone(),
        location: request.location.clone(),
        os: extract_os(&request.user_agent),
        browser: extract_browser(&request.user_agent),
        screen_resolution: None,
        timezone: None,
        fingerprint: Some(request.device_fingerprint.clone()),
    };

    // Compute the server-side fingerprint to look up previous last_seen.
    // This gives calculate_time_risk a meaningful inactivity duration instead of
    // always seeing ~0 (which would pin the time risk at the minimum 0.1).
    let server_fingerprint = format!(
        "fp_{}_{}_{}",
        request.user_agent, real_ip, extract_os(&request.user_agent)
    );
    let last_activity = state.zero_trust_manager
        .get_device_last_seen(&server_fingerprint)
        .unwrap_or_else(chrono::Utc::now);

    // Evaluate device trust (reuses existing entry for the same server-generated fingerprint).
    // New entries are persisted inside evaluate_device_trust, so no extra registration needed.
    let device_trust = state.zero_trust_manager.evaluate_device_trust(&device_info).await
        .map_err(|e| AuthencError::internal(e))?;

    // Save device_id before device_trust is moved into AuthContext
    let device_id = device_trust.device_id.clone();

    // Create auth context for assessment
    let context = AuthContext {
        session_id: request.session_id.clone(),
        user_id: request.user_id,
        device_trust,
        risk_assessment: RiskAssessment {
            score: 0.0,
            level: RiskLevel::Low,
            factors: vec![],
            recommendations: vec![],
            assessed_at: chrono::Utc::now(),
        },
        last_activity,
        adaptive_controls: AdaptiveControls {
            require_mfa: false,
            require_device_verification: false,
            session_timeout: 3600,
            max_concurrent_sessions: 5,
            allowed_locations: vec![],
            blocked_actions: vec![],
        },
    };

    // Assess risk
    let assessment = state.zero_trust_manager.assess_risk(&context).await
        .map_err(|e| AuthencError::internal(e))?;

    let response = RiskAssessmentResponse {
        device_id,
        score: assessment.score,
        level: assessment.level,
        factors: assessment.factors.into_iter().map(|f| f.description).collect(),
        recommendations: assessment.recommendations,
        assessed_at: assessment.assessed_at,
    };

    Ok(Json(response))
}

/// Update adaptive controls for a user
pub async fn update_adaptive_controls(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<UpdateAdaptiveControlsRequest>,
) -> Result<Json<AdaptiveControlsResponse>, AuthencError> {
    // In a real implementation, we would store these controls in a session or database
    let response = AdaptiveControlsResponse {
        session_id: request.session_id,
        user_id: request.user_id,
        controls: request.controls,
        updated_at: chrono::Utc::now(),
    };
    Ok(Json(response))
}

/// Verify session security
pub async fn verify_session(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifySessionRequest>,
) -> Result<Json<SessionVerificationResponse>, AuthencError> {
    // Use the server-generated device_id (fingerprint) for trust store lookup,
    // not the client-controlled session_id.
    let (valid, risk_score, requires_additional_auth) = match state.zero_trust_manager.verify_session(&request.device_id).await {
        Ok(true) => (true, 0.1, false),   // Low risk — session is valid, no extra auth needed
        Ok(false) => (true, 0.5, true),   // Elevated risk — session is valid but step-up auth recommended
        Err(_) => (false, 0.8, true),     // High risk — verification failed, session invalid
    };

    let response = SessionVerificationResponse {
        valid,
        risk_score,
        requires_additional_auth,
        adaptive_controls: state.zero_trust_manager.generate_adaptive_controls(risk_score),
    };
    Ok(Json(response))
}

/// Get risk analytics
pub async fn get_risk_analytics(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<GetRiskAnalyticsQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Mock response
    let analytics = serde_json::json!({
        "total_sessions": 100,
        "risky_sessions": 5,
        "average_risk_score": 0.15,
        "top_risk_factors": ["Unusual location", "New device"]
    });
    Ok(Json(analytics))
}

/// Get security dashboard data
pub async fn get_security_dashboard(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<GetRiskAnalyticsQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Mock response
    let dashboard = serde_json::json!({
        "active_sessions": 25,
        "trusted_devices": 18,
        "risky_sessions": 2,
        "security_events_today": 3,
        "compliance_rate": 0.95
    });
    Ok(Json(dashboard))
}

/// Create zero trust routes
pub fn create_zero_trust_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/risk/assess", post(assess_risk))
        .route("/adaptive-controls", put(update_adaptive_controls))
        .route("/session/verify", post(verify_session))
        .route("/analytics/risk", get(get_risk_analytics))
        .route("/dashboard/security", get(get_security_dashboard))
}
