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

/// Extract the real client IP address, preferring trusted proxy headers over the
/// raw connection address.
///
/// Behind a reverse proxy (nginx, AWS ALB, Cloudflare, etc.), `ConnectInfo`
/// returns the **proxy's** IP, not the end-user's.  This function checks
/// `X-Forwarded-For` and `X-Real-IP` headers first, falling back to the
/// connection address only when neither header is present.
///
/// # Security considerations
///
/// These headers are trivially spoofable by direct clients.  In production,
/// the application **must** be deployed behind a trusted reverse proxy that
/// strips or overwrites `X-Forwarded-For` / `X-Real-IP` before forwarding.
/// Without that guarantee, an attacker can inject arbitrary IPs to:
///   - inherit another device's trust entry,
///   - inflate trust scores by claiming a private IP,
///   - evade rate limiting.
///
/// When `X-Forwarded-For` contains multiple IPs (comma-separated), the
/// **leftmost** (first) value is used — this is the original client IP
/// appended by the first proxy in the chain.  If your proxy chain uses
/// a right-to-left convention, adjust accordingly.
fn extract_client_ip(headers: &HeaderMap, addr: &SocketAddr) -> String {
    // Prefer X-Forwarded-For (de-facto standard, set by most reverse proxies).
    // Take the first (leftmost) IP — the original client address.
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                let trimmed = first_ip.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    // Fall back to X-Real-IP (set by nginx with `proxy_set_header X-Real-IP`).
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    // No proxy headers — use the raw connection address.
    addr.ip().to_string()
}

#[derive(Deserialize)]
/// Request payload for assessing security risk of a user action
pub struct AssessRiskRequest {
    /// Session identifier
    pub session_id: String,
    /// User identifier (ignored — the authenticated user's ID from the JWT token is used instead)
    #[serde(default)]
    pub user_id: Option<Uuid>,
    /// Device fingerprint for tracking
    pub device_fingerprint: String,
    /// User agent string (ignored — the HTTP User-Agent header is used instead)
    #[serde(default)]
    pub user_agent: Option<String>,
    /// IP address of the request (ignored — the real connection IP is used instead)
    #[serde(default)]
    pub ip_address: Option<String>,
    /// Geographic location information (ignored — server-side geolocation should be used)
    #[serde(default)]
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
    /// User identifier (ignored — the authenticated user's ID from the JWT token is used instead)
    #[serde(default)]
    pub user_id: Option<Uuid>,
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
    /// Human-readable reason when `valid` is false (e.g. "device_mismatch",
    /// "high_risk", "internal_error").  Absent when `valid` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

    // Always use the real client IP for security decisions, never the
    // client-provided ip_address.  A malicious client could spoof a private IP
    // (e.g. 192.168.1.1) to gain higher trust scores, or send another user's
    // IP to inherit their device trust entry.
    //
    // extract_client_ip checks X-Forwarded-For / X-Real-IP headers first so
    // that deployments behind a reverse proxy see the actual client IP instead
    // of the proxy's IP (which would cause all clients to share a single
    // device fingerprint and trust entry).
    let real_ip = extract_client_ip(&headers, &addr);

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
    //
    // NOTE: `location` is always `None` because we never trust client-provided
    // location data.  This means `calculate_location_risk` always returns 0.3
    // (the "no location data" fallback) and the high-risk country / VPN detection
    // logic in that function is currently dead code.  To activate location-based
    // risk detection, integrate a server-side IP geolocation service here and
    // populate `location` from the resolved `real_ip`.
    let device_info = DeviceInfo {
        user_agent: real_user_agent.clone(),
        ip_address: real_ip.clone(),
        location: None, // Never trust client-provided location; use server-side IP geolocation
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
    //
    // NOTE: There is a benign TOCTOU between this read and the subsequent
    // `evaluate_device_trust` write — a concurrent request could create or
    // update the entry in between.  In the worst case, `last_activity` defaults
    // to `Utc::now()` (for a new device), resulting in the minimum time risk
    // score of 0.1.  This errs on the safe side (under-counting time risk).
    let server_fingerprint = ZeroTrustManager::compute_device_fingerprint(&device_info);
    let last_activity = state.zero_trust_manager
        .get_device_last_seen(&server_fingerprint)
        .unwrap_or_else(|e| {
            eprintln!("[SECURITY] Failed to read device last_seen: {}", e);
            None
        })
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
    let real_ip = extract_client_ip(&headers, &addr);
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
        // This commonly happens when the client's IP changed between assess_risk
        // and verify_session (e.g. mobile network switch, DHCP renewal).  The
        // client should call assess_risk again to obtain a fresh device_id.
        let response = SessionVerificationResponse {
            valid: false,
            risk_score: 0.9,
            requires_additional_auth: true,
            adaptive_controls: state.zero_trust_manager.generate_adaptive_controls(0.9),
            reason: Some("device_mismatch".to_string()),
        };
        return Ok(Json(response));
    }

    // verify_session_with_score returns the actual combined risk score so we
    // can feed it into generate_adaptive_controls without losing precision.
    let (valid, risk_score, requires_additional_auth, reason) = match state.zero_trust_manager.verify_session_with_score(&request.device_id) {
        Ok((true, score)) if score <= 0.3 => (true, score, false, None),           // Low risk — no extra auth needed
        Ok((true, score)) => (true, score, true, None),                            // Elevated risk — step-up auth recommended
        Ok((false, score)) => (false, score, true, Some("high_risk".to_string())), // High risk — session invalid
        Err(_) => (false, 0.8, true, Some("internal_error".to_string())),          // Lock/internal error — fail closed
    };

    let response = SessionVerificationResponse {
        valid,
        risk_score,
        requires_additional_auth,
        adaptive_controls: state.zero_trust_manager.generate_adaptive_controls(risk_score),
        reason,
    };
    Ok(Json(response))
}

/// Get risk analytics
pub async fn get_risk_analytics(
    State(_state): State<Arc<AppState>>,
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Query(_query): Query<GetRiskAnalyticsQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Only administrators should access security analytics.
    //
    // TODO: When real data is wired up, `realm-admin` users must be restricted
    // to their own realm.  Currently `AuthUser` does not carry a `realm_id`, so
    // a realm-admin for realm A can query analytics for realm B by passing a
    // different `realm_id` in the query params.  The `admin` (global) role is
    // unaffected.  Until `AuthUser` is extended with realm context, consider
    // restricting this endpoint to the `admin` role only.
    if !auth_user.roles.iter().any(|r| r == "admin" || r == "realm-admin") {
        return Err(AuthencError::forbidden("Admin role required to access risk analytics"));
    }

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
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Query(_query): Query<GetRiskAnalyticsQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Only administrators should access the security dashboard.
    //
    // TODO: Same realm-admin authorization gap as `get_risk_analytics` — see
    // the comment there for details.
    if !auth_user.roles.iter().any(|r| r == "admin" || r == "realm-admin") {
        return Err(AuthencError::forbidden("Admin role required to access security dashboard"));
    }

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
