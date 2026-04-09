use axum::{
    Router,
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    response::Json,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AuthencError;
use crate::middleware::auth::AuthUser;
use authenc_services::services::security::zero_trust::{
    AdaptiveControls, AuthContext, RiskAssessment, RiskLevel,
    ContinuousAuthService, Location, DeviceInfo, ZeroTrustManager,
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
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Json(request): Json<AssessRiskRequest>,
) -> Result<Json<RiskAssessmentResponse>, AuthencError> {
    // Use the authenticated user's ID from the JWT token, never the client-provided
    // user_id.  A malicious client could send another user's UUID to pollute that
    // user's known-IP list in the anomaly detector, weakening future anomaly
    // detection for them.
    let authenticated_user_id: Uuid = auth_user.id.parse()
        .map_err(|_| AuthencError::internal("Invalid user ID in auth token".to_string()))?;

    // Always use the real connection IP for security decisions, never the
    // client-provided ip_address.  A malicious client could spoof a private IP
    // (e.g. 192.168.1.1) to gain higher trust scores, or send another user's
    // IP to inherit their device trust entry.
    let real_ip = addr.ip().to_string();

    // Use the real HTTP User-Agent header for trust scoring, not the client-provided
    // JSON field.  While the UA header is also client-controlled, it is the canonical
    // source that proxies/WAFs can inspect and normalize.  Accepting a separate JSON
    // field would let an attacker craft a UA string (e.g. containing "Chrome/" and
    // "Windows") to inflate trust scores by ~45 points without the header matching.
    let real_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Create device info, parsing OS and browser from the real HTTP User-Agent header
    let device_info = DeviceInfo {
        user_agent: real_user_agent.clone(),
        ip_address: real_ip.clone(),
        location: request.location.clone(),
        os: extract_os(&real_user_agent),
        browser: extract_browser(&real_user_agent),
        screen_resolution: None,
        timezone: None,
        fingerprint: Some(request.device_fingerprint.clone()),
    };

    // Compute the server-side fingerprint to look up previous last_seen.
    // This gives calculate_time_risk a meaningful inactivity duration instead of
    // always seeing ~0 (which would pin the time risk at the minimum 0.1).
    // Uses the shared helper to stay in sync with evaluate_device_trust.
    let server_fingerprint = ZeroTrustManager::compute_device_fingerprint(&device_info);
    let last_activity = state.zero_trust_manager
        .get_device_last_seen(&server_fingerprint)
        .unwrap_or_else(chrono::Utc::now);

    // Evaluate device trust (reuses existing entry for the same server-generated fingerprint).
    // New entries are persisted inside evaluate_device_trust, so no extra registration needed.
    let device_trust = state.zero_trust_manager.evaluate_device_trust(&device_info).await
        .map_err(|e| AuthencError::internal(e))?;

    // Save device_id before device_trust is moved into AuthContext
    let device_id = device_trust.device_id.clone();

    // Create auth context for assessment — use the authenticated user's ID, not the
    // client-supplied request.user_id, to prevent cross-user anomaly detector pollution.
    let context = AuthContext {
        session_id: request.session_id.clone(),
        user_id: authenticated_user_id,
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
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Json(request): Json<UpdateAdaptiveControlsRequest>,
) -> Result<Json<AdaptiveControlsResponse>, AuthencError> {
    // Use the authenticated user's ID from the JWT token, never the client-provided
    // user_id.  When this is wired to real storage, trusting the client-provided
    // user_id would let any authenticated user modify another user's controls.
    let authenticated_user_id: Uuid = auth_user.id.parse()
        .map_err(|_| AuthencError::internal("Invalid user ID in auth token".to_string()))?;

    // In a real implementation, we would store these controls in a session or database
    let response = AdaptiveControlsResponse {
        session_id: request.session_id,
        user_id: authenticated_user_id,
        controls: request.controls,
        updated_at: chrono::Utc::now(),
    };
    Ok(Json(response))
}

/// Verify session security
pub async fn verify_session(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(_auth_user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Json(request): Json<VerifySessionRequest>,
) -> Result<Json<SessionVerificationResponse>, AuthencError> {
    // Recompute the device fingerprint from the caller's actual connection
    // parameters and verify it matches the client-provided device_id.
    // This prevents authenticated users from probing other devices' trust
    // levels — the fingerprint is derived from the real IP + UA + OS, so
    // only the device that originally called assess_risk can verify itself.
    let real_ip = addr.ip().to_string();
    let real_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let caller_device_info = DeviceInfo {
        user_agent: real_user_agent.clone(),
        ip_address: real_ip,
        location: None,
        os: extract_os(&real_user_agent),
        browser: extract_browser(&real_user_agent),
        screen_resolution: None,
        timezone: None,
        fingerprint: None,
    };
    let expected_device_id = ZeroTrustManager::compute_device_fingerprint(&caller_device_info);
    if request.device_id != expected_device_id {
        // The caller's connection doesn't match the device_id they claim to own.
        // Fail closed — treat as high risk / invalid.
        let response = SessionVerificationResponse {
            valid: false,
            risk_score: 0.9,
            requires_additional_auth: true,
            adaptive_controls: state.zero_trust_manager.generate_adaptive_controls(0.9),
        };
        return Ok(Json(response));
    }

    // verify_session_with_score returns the actual combined risk score so we
    // can feed it into generate_adaptive_controls without losing precision.
    let (valid, risk_score, requires_additional_auth) = match state.zero_trust_manager.verify_session_with_score(&request.device_id) {
        Ok((true, score)) if score <= 0.3 => (true, score, false),  // Low risk — no extra auth needed
        Ok((true, score)) => (true, score, true),                   // Elevated risk — step-up auth recommended
        Ok((false, score)) => (false, score, true),                 // High risk — session invalid
        Err(_) => (false, 0.8, true),                               // Lock/internal error — fail closed
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
    // Placeholder response — not wired to real data yet.
    // The `placeholder` flag lets the UI indicate these are sample values.
    let analytics = serde_json::json!({
        "placeholder": true,
        "total_sessions": 0,
        "risky_sessions": 0,
        "average_risk_score": 0.0,
        "top_risk_factors": []
    });
    Ok(Json(analytics))
}

/// Get security dashboard data
pub async fn get_security_dashboard(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<GetRiskAnalyticsQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Placeholder response — not wired to real data yet.
    // The `placeholder` flag lets the UI indicate these are sample values.
    let dashboard = serde_json::json!({
        "placeholder": true,
        "active_sessions": 0,
        "trusted_devices": 0,
        "risky_sessions": 0,
        "security_events_today": 0,
        "compliance_rate": 0.0
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
