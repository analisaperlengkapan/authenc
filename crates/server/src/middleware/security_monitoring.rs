use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

use authenc_services::services::stores::pg_audit_log_store::PgAuditLogStore;

/// Configuration for security monitoring
#[derive(Clone, Debug)]
pub struct SecurityMonitoringConfig {
    /// Whether security monitoring is enabled
    pub enabled: bool,
    /// Threshold for suspicious activity alerts (requests per minute)
    pub suspicious_threshold_rpm: u64,
    /// Paths to monitor for security events
    pub monitored_paths: Vec<String>,
    /// Whether to log all authentication attempts
    pub log_auth_attempts: bool,
    /// Whether to log all authorization failures
    pub log_authz_failures: bool,
}

impl Default for SecurityMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_threshold_rpm: 100,
            monitored_paths: vec![
                "/auth/login".to_string(),
                "/auth/register".to_string(),
                "/account".to_string(),
                "/admin".to_string(),
            ],
            log_auth_attempts: true,
            log_authz_failures: true,
        }
    }
}

/// Security monitoring state
#[derive(Clone)]
pub struct SecurityMonitoringState {
    config: SecurityMonitoringConfig,
    audit_store: Option<Arc<PgAuditLogStore>>,
}

impl SecurityMonitoringState {
    /// Create a new security monitoring state with the given configuration and audit store
    pub fn new(
        config: SecurityMonitoringConfig,
        audit_store: Option<Arc<PgAuditLogStore>>,
    ) -> Self {
        Self {
            config,
            audit_store,
        }
    }

    /// Log a security event
    async fn log_security_event(&self, event_type: &str, details: serde_json::Value) {
        if let Some(audit_store) = &self.audit_store {
            let event = authenc_api::models::audit_log::AuditLog {
                timestamp: chrono::Utc::now(),
                event: event_type.to_string(),
                user_id: details
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                client_id: details
                    .get("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                status: details
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                detail: Some(serde_json::to_string(&details).unwrap_or_default()),
            };

            if let Err(e) = audit_store.add_log(&event).await {
                error!("Failed to store security audit event: {}", e);
            }
        } else {
            // Fallback to logging if audit store is not available
            info!("Security event: {} - {}", event_type, details);
        }
    }
}

/// Middleware for security monitoring and alerting
pub async fn security_monitoring_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<SecurityMonitoringState>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    if !state.config.enabled {
        return next.run(request).await;
    }

    let start_time = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let ip = addr.ip().to_string();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Check for suspicious patterns
    let suspicious_indicators = detect_suspicious_activity(&request, &ip);

    let mut response = next.run(request).await;
    let duration = start_time.elapsed();
    let status_code = response.status();

    // Log security events
    if state
        .config
        .monitored_paths
        .iter()
        .any(|p| path.starts_with(p))
    {
        let event_details = serde_json::json!({
            "ip": ip,
            "method": method.as_str(),
            "path": path,
            "status_code": status_code.as_u16(),
            "duration_ms": duration.as_millis(),
            "user_agent": user_agent,
            "suspicious_indicators": suspicious_indicators
        });

        // Log authentication attempts
        if state.config.log_auth_attempts && path.contains("/auth/") {
            let event_type = match status_code {
                StatusCode::OK => "AUTH_SUCCESS",
                StatusCode::UNAUTHORIZED => "AUTH_FAILURE",
                _ => "AUTH_ATTEMPT",
            };
            state
                .log_security_event(event_type, event_details.clone())
                .await;
        }

        // Log authorization failures
        if state.config.log_authz_failures && status_code == StatusCode::FORBIDDEN {
            state
                .log_security_event("AUTHZ_FAILURE", event_details.clone())
                .await;
        }

        // Log suspicious activity
        if !suspicious_indicators.is_empty() {
            warn!(
                "Suspicious activity detected: {} from IP {}",
                suspicious_indicators.join(", "),
                ip
            );
            state
                .log_security_event("SUSPICIOUS_ACTIVITY", event_details)
                .await;
        }
    }

    // Add security headers to response
    if let Some(headers) = response.headers_mut().get_mut("X-Security-Monitoring") {
        *headers = format!("monitored; duration={}ms", duration.as_millis())
            .parse()
            .unwrap();
    } else {
        response.headers_mut().insert(
            "X-Security-Monitoring",
            format!("monitored; duration={}ms", duration.as_millis())
                .parse()
                .unwrap(),
        );
    }

    response
}

/// Detect suspicious activity patterns
fn detect_suspicious_activity(request: &Request<Body>, _ip: &str) -> Vec<String> {
    let mut indicators = Vec::new();
    let path = request.uri().path();
    let method = request.method();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Check for common attack patterns
    if path.contains("..") || path.contains("\\") {
        indicators.push("path_traversal".to_string());
    }

    if method == Method::TRACE && !path.starts_with("/health") {
        indicators.push("trace_method".to_string());
    }

    if user_agent.is_empty() || user_agent == "unknown" {
        indicators.push("missing_user_agent".to_string());
    }

    // Check for SQL injection patterns (basic detection)
    let query = request.uri().query().unwrap_or("");
    let decoded_query = urlencoding::decode(query).unwrap_or_else(|_| query.into());
    if decoded_query.contains("'")
        || decoded_query.contains("1=1")
        || decoded_query.contains("OR 1=1")
    {
        indicators.push("potential_sql_injection".to_string());
    }

    // Check for XSS patterns in query parameters
    if decoded_query.contains("<script") || decoded_query.contains("javascript:") {
        indicators.push("potential_xss".to_string());
    }

    // Check for unusual request patterns
    if request.headers().get("x-forwarded-for").is_some()
        && request.headers().get("x-real-ip").is_some()
    {
        indicators.push("multiple_proxy_headers".to_string());
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, extract::Request, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_suspicious_activity_detection() {
        let request = Request::builder()
            .uri("/admin?query=1%3D1")
            .method("GET")
            .header("user-agent", "suspicious-scanner")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"potential_sql_injection".to_string()));
    }

    #[tokio::test]
    async fn test_security_monitoring_middleware() {
        let state = Arc::new(SecurityMonitoringState::new(
            SecurityMonitoringConfig::default(),
            None, // No audit store for test
        ));

        let app =
            Router::new()
                .route("/test", get(|| async { "OK" }))
                .layer(axum::middleware::from_fn(move |req, next| {
                    let state = state.clone();
                    security_monitoring_middleware(
                        axum::extract::ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            8080,
                        ))),
                        axum::extract::State(state),
                        req,
                        next,
                    )
                }));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(response.headers().contains_key("x-security-monitoring"));
    }

    #[tokio::test]
    async fn test_security_monitoring_disabled() {
        let config = SecurityMonitoringConfig {
            enabled: false,
            ..Default::default()
        };
        let state = Arc::new(SecurityMonitoringState::new(config, None));

        let app =
            Router::new()
                .route("/test", get(|| async { "OK" }))
                .layer(axum::middleware::from_fn(move |req, next| {
                    let state = state.clone();
                    security_monitoring_middleware(
                        axum::extract::ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            8080,
                        ))),
                        axum::extract::State(state),
                        req,
                        next,
                    )
                }));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        // Should not add security monitoring header when disabled
        assert!(!response.headers().contains_key("x-security-monitoring"));
    }

    #[tokio::test]
    async fn test_suspicious_activity_path_traversal() {
        let request = Request::builder()
            .uri("/admin/../../../etc/passwd")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"path_traversal".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_activity_trace_method() {
        let request = Request::builder()
            .uri("/admin/users")
            .method("TRACE")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"trace_method".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_activity_missing_user_agent() {
        let request = Request::builder()
            .uri("/admin")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"missing_user_agent".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_activity_sql_injection() {
        let request = Request::builder()
            .uri("/search?q=%27%20OR%20%271%27%3D%271")
            .method("GET")
            .header("user-agent", "test-agent")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"potential_sql_injection".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_activity_xss() {
        let request = Request::builder()
            .uri("/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E")
            .method("GET")
            .header("user-agent", "test-agent")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"potential_xss".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_activity_multiple_proxy_headers() {
        let request = Request::builder()
            .uri("/admin")
            .method("GET")
            .header("user-agent", "test-agent")
            .header("x-forwarded-for", "192.168.1.1")
            .header("x-real-ip", "10.0.0.1")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.contains(&"multiple_proxy_headers".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_activity_no_indicators() {
        let request = Request::builder()
            .uri("/api/users")
            .method("GET")
            .header("user-agent", "Mozilla/5.0")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        assert!(indicators.is_empty());
    }

    #[tokio::test]
    async fn test_security_monitoring_config_defaults() {
        let config = SecurityMonitoringConfig::default();

        assert!(config.enabled);
        assert_eq!(config.suspicious_threshold_rpm, 100);
        assert!(config.monitored_paths.contains(&"/auth/login".to_string()));
        assert!(config.monitored_paths.contains(&"/admin".to_string()));
        assert!(config.log_auth_attempts);
        assert!(config.log_authz_failures);
    }

    #[tokio::test]
    async fn test_security_monitoring_trace_on_health_allowed() {
        let request = Request::builder()
            .uri("/health")
            .method("TRACE")
            .body(Body::empty())
            .unwrap();

        let indicators = detect_suspicious_activity(&request, "127.0.0.1");
        // TRACE method should not be flagged as suspicious for health endpoints
        assert!(!indicators.contains(&"trace_method".to_string()));
    }
}
