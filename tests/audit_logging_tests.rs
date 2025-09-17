// Advanced Audit Logging Tests
// Testing comprehensive audit trails, compliance logging, and security event monitoring

use axum::{
    extract::{Json, State},
    http::{header::HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AuditState {
    audit_logs: Arc<Mutex<HashMap<String, AuditLogEntry>>>,
    compliance_logs: Arc<Mutex<HashMap<String, ComplianceLogEntry>>>,
    security_events: Arc<Mutex<HashMap<String, SecurityEvent>>>,
    retention_policies: Arc<Mutex<HashMap<String, RetentionPolicy>>>,
    audit_trails: Arc<Mutex<HashMap<String, Vec<AuditTrailEntry>>>>,
    compliance_reports: Arc<Mutex<HashMap<String, ComplianceReport>>>,
}

#[derive(Clone)]
struct AuditLogEntry {
    id: String,
    timestamp: String,
    user_id: Option<String>,
    session_id: Option<String>,
    action: String,
    resource: String,
    resource_id: Option<String>,
    method: String,
    endpoint: String,
    ip_address: String,
    user_agent: String,
    status_code: u16,
    response_time_ms: u64,
    request_size_bytes: u64,
    response_size_bytes: u64,
    metadata: HashMap<String, String>,
    sensitive_data_accessed: bool,
    compliance_flags: Vec<String>,
}

#[derive(Clone)]
struct ComplianceLogEntry {
    id: String,
    timestamp: String,
    compliance_standard: String,
    requirement_id: String,
    user_id: Option<String>,
    action: String,
    status: String, // "compliant", "non_compliant", "warning"
    details: String,
    evidence: HashMap<String, String>,
    remediation_required: bool,
    severity: String, // "low", "medium", "high", "critical"
}

#[derive(Clone)]
struct SecurityEvent {
    id: String,
    timestamp: String,
    event_type: String,
    severity: String,
    user_id: Option<String>,
    session_id: Option<String>,
    ip_address: String,
    user_agent: String,
    description: String,
    indicators: Vec<String>,
    response_actions: Vec<String>,
    resolved: bool,
    resolution_timestamp: Option<String>,
    resolution_details: Option<String>,
}

#[derive(Clone)]
struct RetentionPolicy {
    id: String,
    name: String,
    data_type: String,
    retention_days: u32,
    archive_after_days: u32,
    delete_after_days: u32,
    encryption_required: bool,
    compliance_standards: Vec<String>,
}

#[derive(Clone)]
struct AuditTrailEntry {
    id: String,
    timestamp: String,
    user_id: String,
    action: String,
    before_state: Option<serde_json::Value>,
    after_state: Option<serde_json::Value>,
    reason: Option<String>,
    authorized_by: Option<String>,
    ip_address: String,
    session_id: String,
}

#[derive(Clone)]
struct ComplianceReport {
    id: String,
    report_type: String,
    compliance_standard: String,
    generated_at: String,
    period_start: String,
    period_end: String,
    overall_status: String,
    findings: Vec<ComplianceFinding>,
    recommendations: Vec<String>,
    next_review_date: String,
}

#[derive(Clone)]
struct ComplianceFinding {
    id: String,
    requirement_id: String,
    status: String,
    description: String,
    severity: String,
    evidence: Vec<String>,
    remediation_steps: Vec<String>,
}

impl AuditState {
    fn new() -> Self {
        Self {
            audit_logs: Arc::new(Mutex::new(HashMap::new())),
            compliance_logs: Arc::new(Mutex::new(HashMap::new())),
            security_events: Arc::new(Mutex::new(HashMap::new())),
            retention_policies: Arc::new(Mutex::new(HashMap::new())),
            audit_trails: Arc::new(Mutex::new(HashMap::new())),
            compliance_reports: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_audit_log_creation_and_querying() {
    let audit_state = AuditState::new();

    let app =
        Router::new()
            .route(
                "/audit/logs",
                post(
                    move |State(state): State<AuditState>,
                          Json(log_entry): Json<serde_json::Value>| async move {
                        let mut audit_logs = state.audit_logs.lock().await;

                        let id = format!("audit_{}", audit_logs.len() + 1);
                        let timestamp = log_entry
                            .get("timestamp")
                            .and_then(|t| t.as_str())
                            .unwrap_or("2024-12-01T12:00:00Z");
                        let user_id = log_entry.get("user_id").and_then(|u| u.as_str());
                        let session_id = log_entry.get("session_id").and_then(|s| s.as_str());
                        let action = log_entry
                            .get("action")
                            .and_then(|a| a.as_str())
                            .unwrap_or("unknown");
                        let resource = log_entry
                            .get("resource")
                            .and_then(|r| r.as_str())
                            .unwrap_or("unknown");
                        let resource_id = log_entry.get("resource_id").and_then(|r| r.as_str());
                        let method = log_entry
                            .get("method")
                            .and_then(|m| m.as_str())
                            .unwrap_or("GET");
                        let endpoint = log_entry
                            .get("endpoint")
                            .and_then(|e| e.as_str())
                            .unwrap_or("/");
                        let ip_address = log_entry
                            .get("ip_address")
                            .and_then(|i| i.as_str())
                            .unwrap_or("127.0.0.1");
                        let user_agent = log_entry
                            .get("user_agent")
                            .and_then(|u| u.as_str())
                            .unwrap_or("Unknown");
                        let status_code = log_entry
                            .get("status_code")
                            .and_then(|s| s.as_u64())
                            .unwrap_or(200) as u16;
                        let response_time_ms = log_entry
                            .get("response_time_ms")
                            .and_then(|r| r.as_u64())
                            .unwrap_or(100);
                        let request_size_bytes = log_entry
                            .get("request_size_bytes")
                            .and_then(|r| r.as_u64())
                            .unwrap_or(1024);
                        let response_size_bytes = log_entry
                            .get("response_size_bytes")
                            .and_then(|r| r.as_u64())
                            .unwrap_or(2048);
                        let sensitive_data_accessed = log_entry
                            .get("sensitive_data_accessed")
                            .and_then(|s| s.as_bool())
                            .unwrap_or(false);

                        let metadata = if let Some(meta) =
                            log_entry.get("metadata").and_then(|m| m.as_object())
                        {
                            meta.iter()
                                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                                .collect()
                        } else {
                            HashMap::new()
                        };

                        let compliance_flags = if let Some(flags) =
                            log_entry.get("compliance_flags").and_then(|f| f.as_array())
                        {
                            flags
                                .iter()
                                .filter_map(|f| f.as_str())
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            Vec::new()
                        };

                        let entry = AuditLogEntry {
                            id: id.clone(),
                            timestamp: timestamp.to_string(),
                            user_id: user_id.map(|s| s.to_string()),
                            session_id: session_id.map(|s| s.to_string()),
                            action: action.to_string(),
                            resource: resource.to_string(),
                            resource_id: resource_id.map(|s| s.to_string()),
                            method: method.to_string(),
                            endpoint: endpoint.to_string(),
                            ip_address: ip_address.to_string(),
                            user_agent: user_agent.to_string(),
                            status_code,
                            response_time_ms,
                            request_size_bytes,
                            response_size_bytes,
                            metadata,
                            sensitive_data_accessed,
                            compliance_flags,
                        };

                        audit_logs.insert(id.clone(), entry);

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "audit_id": id,
                            "status": "logged",
                            "timestamp": timestamp
                        })))
                    },
                ),
            )
            .route(
                "/audit/logs/search",
                post(
                    move |State(state): State<AuditState>,
                          Json(search): Json<serde_json::Value>| async move {
                        let audit_logs = state.audit_logs.lock().await;

                        let user_id = search.get("user_id").and_then(|u| u.as_str());
                        let action = search.get("action").and_then(|a| a.as_str());
                        let resource = search.get("resource").and_then(|r| r.as_str());
                        let from_date = search
                            .get("from_date")
                            .and_then(|f| f.as_str())
                            .unwrap_or("");
                        let to_date = search
                            .get("to_date")
                            .and_then(|t| t.as_str())
                            .unwrap_or("9999-12-31T23:59:59Z");
                        let ip_address = search.get("ip_address").and_then(|i| i.as_str());
                        let status_code = search
                            .get("status_code")
                            .and_then(|s| s.as_u64())
                            .map(|s| s as u16);
                        let sensitive_only = search
                            .get("sensitive_only")
                            .and_then(|s| s.as_bool())
                            .unwrap_or(false);

                        let mut matching_logs = Vec::new();

                        for (_, log_entry) in audit_logs.iter() {
                            // Apply filters
                            if let Some(uid) = user_id {
                                if log_entry.user_id.as_ref() != Some(&uid.to_string()) {
                                    continue;
                                }
                            }

                            if let Some(act) = action {
                                if log_entry.action != act {
                                    continue;
                                }
                            }

                            if let Some(res) = resource {
                                if log_entry.resource != res {
                                    continue;
                                }
                            }

                            if log_entry.timestamp.as_str() < from_date
                                || log_entry.timestamp.as_str() > to_date
                            {
                                continue;
                            }

                            if let Some(ip) = ip_address {
                                if log_entry.ip_address != *ip {
                                    continue;
                                }
                            }

                            if let Some(sc) = status_code {
                                if log_entry.status_code != sc {
                                    continue;
                                }
                            }

                            if sensitive_only && !log_entry.sensitive_data_accessed {
                                continue;
                            }

                            matching_logs.push(json!({
                                "id": log_entry.id,
                                "timestamp": log_entry.timestamp,
                                "user_id": log_entry.user_id,
                                "action": log_entry.action,
                                "resource": log_entry.resource,
                                "resource_id": log_entry.resource_id,
                                "method": log_entry.method,
                                "endpoint": log_entry.endpoint,
                                "ip_address": log_entry.ip_address,
                                "status_code": log_entry.status_code,
                                "response_time_ms": log_entry.response_time_ms,
                                "sensitive_data_accessed": log_entry.sensitive_data_accessed,
                                "compliance_flags": log_entry.compliance_flags
                            }));
                        }

                        // Sort by timestamp (most recent first)
                        matching_logs.sort_by(|a, b| {
                            b["timestamp"]
                                .as_str()
                                .unwrap_or("")
                                .cmp(a["timestamp"].as_str().unwrap_or(""))
                        });

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "logs": matching_logs,
                            "total_found": matching_logs.len(),
                            "filters_applied": {
                                "user_id": user_id,
                                "action": action,
                                "resource": resource,
                                "date_range": format!("{} to {}", from_date, to_date),
                                "sensitive_only": sensitive_only
                            }
                        })))
                    },
                ),
            )
            .with_state(audit_state);

    let server = TestServer::new(app).unwrap();

    // Test creating audit logs
    let log_data = json!({
        "timestamp": "2024-12-01T12:00:00Z",
        "user_id": "user_123",
        "session_id": "session_456",
        "action": "user_login",
        "resource": "authentication",
        "resource_id": "user_123",
        "method": "POST",
        "endpoint": "/auth/login",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "status_code": 200,
        "response_time_ms": 150,
        "request_size_bytes": 512,
        "response_size_bytes": 1024,
        "sensitive_data_accessed": false,
        "compliance_flags": ["GDPR", "SOX"],
        "metadata": {
            "login_method": "password",
            "mfa_used": "true"
        }
    });
    let response = server.post("/audit/logs").json(&log_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["audit_id"].as_str().is_some());

    // Test searching audit logs
    let search_data = json!({
        "user_id": "user_123",
        "action": "user_login",
        "from_date": "2024-12-01T00:00:00Z",
        "to_date": "2024-12-01T23:59:59Z"
    });
    let response = server.post("/audit/logs/search").json(&search_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_found"], 1);
    assert_eq!(body["logs"][0]["action"], "user_login");
    assert_eq!(body["logs"][0]["user_id"], "user_123");

    // Test searching with sensitive data filter
    let sensitive_search = json!({
        "sensitive_only": true,
        "from_date": "2024-12-01T00:00:00Z"
    });
    let response = server
        .post("/audit/logs/search")
        .json(&sensitive_search)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_found"], 0); // No sensitive data access in our test log
}

#[tokio::test]
async fn test_compliance_logging_and_reporting() {
    let audit_state = AuditState::new();

    let app = Router::new()
        .route(
            "/compliance/logs",
            post(
                move |State(state): State<AuditState>,
                      Json(compliance_entry): Json<serde_json::Value>| async move {
                    let mut compliance_logs = state.compliance_logs.lock().await;

                    let id = format!("compliance_{}", compliance_logs.len() + 1);
                    let timestamp = compliance_entry
                        .get("timestamp")
                        .and_then(|t| t.as_str())
                        .unwrap_or("2024-12-01T12:00:00Z");
                    let compliance_standard = compliance_entry
                        .get("compliance_standard")
                        .and_then(|c| c.as_str())
                        .unwrap_or("GDPR");
                    let requirement_id = compliance_entry
                        .get("requirement_id")
                        .and_then(|r| r.as_str())
                        .unwrap_or("REQ_001");
                    let user_id = compliance_entry.get("user_id").and_then(|u| u.as_str());
                    let action = compliance_entry
                        .get("action")
                        .and_then(|a| a.as_str())
                        .unwrap_or("data_access");
                    let status = compliance_entry
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("compliant");
                    let details = compliance_entry
                        .get("details")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
                    let remediation_required = compliance_entry
                        .get("remediation_required")
                        .and_then(|r| r.as_bool())
                        .unwrap_or(false);
                    let severity = compliance_entry
                        .get("severity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("low");

                    let evidence = if let Some(ev) =
                        compliance_entry.get("evidence").and_then(|e| e.as_object())
                    {
                        ev.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                            .collect()
                    } else {
                        HashMap::new()
                    };

                    let entry = ComplianceLogEntry {
                        id: id.clone(),
                        timestamp: timestamp.to_string(),
                        compliance_standard: compliance_standard.to_string(),
                        requirement_id: requirement_id.to_string(),
                        user_id: user_id.map(|s| s.to_string()),
                        action: action.to_string(),
                        status: status.to_string(),
                        details: details.to_string(),
                        evidence,
                        remediation_required,
                        severity: severity.to_string(),
                    };

                    compliance_logs.insert(id.clone(), entry);

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "compliance_id": id,
                        "status": "logged",
                        "timestamp": timestamp,
                        "requires_attention": remediation_required
                    })))
                },
            ),
        )
        .route(
            "/compliance/reports/generate",
            post(
                move |State(state): State<AuditState>,
                      Json(report_request): Json<serde_json::Value>| async move {
                    let compliance_logs = state.compliance_logs.lock().await;
                    let mut compliance_reports = state.compliance_reports.lock().await;

                    let report_type = report_request
                        .get("report_type")
                        .and_then(|r| r.as_str())
                        .unwrap_or("quarterly");
                    let compliance_standard = report_request
                        .get("compliance_standard")
                        .and_then(|c| c.as_str())
                        .unwrap_or("GDPR");
                    let period_start = report_request
                        .get("period_start")
                        .and_then(|p| p.as_str())
                        .unwrap_or("2024-10-01T00:00:00Z");
                    let period_end = report_request
                        .get("period_end")
                        .and_then(|p| p.as_str())
                        .unwrap_or("2024-12-31T23:59:59Z");

                    // Filter compliance logs for the period
                    let relevant_logs: Vec<_> = compliance_logs
                        .values()
                        .filter(|log| {
                            log.compliance_standard == compliance_standard
                                && log.timestamp.as_str() >= period_start
                                && log.timestamp.as_str() <= period_end
                        })
                        .collect();

                    // Calculate compliance status
                    let total_logs = relevant_logs.len();
                    let compliant_count = relevant_logs
                        .iter()
                        .filter(|log| log.status == "compliant")
                        .count();
                    let non_compliant_count = relevant_logs
                        .iter()
                        .filter(|log| log.status == "non_compliant")
                        .count();
                    let warning_count = relevant_logs
                        .iter()
                        .filter(|log| log.status == "warning")
                        .count();

                    let overall_status = if non_compliant_count > 0 {
                        "non_compliant"
                    } else if warning_count > 0 {
                        "warning"
                    } else {
                        "compliant"
                    };

                    // Generate findings
                    let findings: Vec<ComplianceFinding> = relevant_logs
                        .iter()
                        .filter(|log| log.status != "compliant")
                        .map(|log| ComplianceFinding {
                            id: format!("finding_{}", log.id),
                            requirement_id: log.requirement_id.clone(),
                            status: log.status.clone(),
                            description: log.details.clone(),
                            severity: log.severity.clone(),
                            evidence: vec![format!("Log ID: {}", log.id)],
                            remediation_steps: if log.remediation_required {
                                vec!["Review and implement corrective actions".to_string()]
                            } else {
                                vec![]
                            },
                        })
                        .collect();

                    let report_id = format!("report_{}", compliance_reports.len() + 1);
                    let generated_at = "2024-12-01T12:00:00Z".to_string();
                    let next_review_date = "2025-03-01T00:00:00Z".to_string();

                    let report = ComplianceReport {
                        id: report_id.clone(),
                        report_type: report_type.to_string(),
                        compliance_standard: compliance_standard.to_string(),
                        generated_at: generated_at.clone(),
                        period_start: period_start.to_string(),
                        period_end: period_end.to_string(),
                        overall_status: overall_status.to_string(),
                        findings: findings.clone(),
                        recommendations: vec![
                            "Implement automated compliance monitoring".to_string(),
                            "Regular security training for staff".to_string(),
                            "Enhance access control mechanisms".to_string(),
                        ],
                        next_review_date,
                    };

                    compliance_reports.insert(report_id.clone(), report);

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "report_id": report_id,
                        "generated_at": generated_at,
                        "overall_status": overall_status,
                        "total_logs_reviewed": total_logs,
                        "compliant_count": compliant_count,
                        "non_compliant_count": non_compliant_count,
                        "warning_count": warning_count,
                        "findings_count": findings.len(),
                        "recommendations_count": 3
                    })))
                },
            ),
        )
        .route(
            "/compliance/reports/{report_id}",
            get(
                move |State(state): State<AuditState>,
                      axum::extract::Path(report_id): axum::extract::Path<String>| async move {
                    let compliance_reports = state.compliance_reports.lock().await;

                    if let Some(report) = compliance_reports.get(&report_id) {
                        let findings: Vec<serde_json::Value> = report
                            .findings
                            .iter()
                            .map(|f| {
                                json!({
                                    "id": f.id,
                                    "requirement_id": f.requirement_id,
                                    "status": f.status,
                                    "description": f.description,
                                    "severity": f.severity,
                                    "evidence": f.evidence,
                                    "remediation_steps": f.remediation_steps
                                })
                            })
                            .collect();

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "report_id": report.id,
                            "report_type": report.report_type,
                            "compliance_standard": report.compliance_standard,
                            "generated_at": report.generated_at,
                            "period_start": report.period_start,
                            "period_end": report.period_end,
                            "overall_status": report.overall_status,
                            "findings": findings,
                            "recommendations": report.recommendations,
                            "next_review_date": report.next_review_date
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .with_state(audit_state);

    let server = TestServer::new(app).unwrap();

    // Test creating compliance logs
    let compliance_data = json!({
        "timestamp": "2024-12-01T12:00:00Z",
        "compliance_standard": "GDPR",
        "requirement_id": "GDPR_32",
        "user_id": "user_123",
        "action": "data_processing",
        "status": "compliant",
        "details": "User data processed with proper consent",
        "remediation_required": false,
        "severity": "low",
        "evidence": {
            "consent_obtained": "true",
            "processing_purpose": "user_authentication"
        }
    });
    let response = server.post("/compliance/logs").json(&compliance_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["compliance_id"].as_str().is_some());
    assert_eq!(body["requires_attention"], false);

    // Test generating compliance report
    let report_request = json!({
        "report_type": "monthly",
        "compliance_standard": "GDPR",
        "period_start": "2024-12-01T00:00:00Z",
        "period_end": "2024-12-31T23:59:59Z"
    });
    let response = server
        .post("/compliance/reports/generate")
        .json(&report_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["report_id"].as_str().is_some());
    assert_eq!(body["overall_status"], "compliant");
    assert_eq!(body["total_logs_reviewed"], 1);
    assert_eq!(body["compliant_count"], 1);

    // Test retrieving compliance report
    let report_id = body["report_id"].as_str().unwrap();
    let response = server
        .get(&format!("/compliance/reports/{}", report_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["overall_status"], "compliant");
    assert!(body["findings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_security_event_monitoring() {
    let audit_state = AuditState::new();

    let app = Router::new()
        .route("/security/events", post(move |State(state): State<AuditState>, Json(event): Json<serde_json::Value>| async move {
            let mut security_events = state.security_events.lock().await;

            let id = format!("security_{}", security_events.len() + 1);
            let timestamp = event.get("timestamp").and_then(|t| t.as_str()).unwrap_or("2024-12-01T12:00:00Z");
            let event_type = event.get("event_type").and_then(|e| e.as_str()).unwrap_or("unknown");
            let severity = event.get("severity").and_then(|s| s.as_str()).unwrap_or("low");
            let user_id = event.get("user_id").and_then(|u| u.as_str());
            let session_id = event.get("session_id").and_then(|s| s.as_str());
            let ip_address = event.get("ip_address").and_then(|i| i.as_str()).unwrap_or("127.0.0.1");
            let user_agent = event.get("user_agent").and_then(|u| u.as_str()).unwrap_or("Unknown");
            let description = event.get("description").and_then(|d| d.as_str()).unwrap_or("");

            let indicators = if let Some(ind) = event.get("indicators").and_then(|i| i.as_array()) {
                ind.iter().filter_map(|i| i.as_str()).map(|s| s.to_string()).collect()
            } else {
                Vec::new()
            };

            let response_actions = if let Some(actions) = event.get("response_actions").and_then(|a| a.as_array()) {
                actions.iter().filter_map(|a| a.as_str()).map(|s| s.to_string()).collect()
            } else {
                Vec::new()
            };

            let security_event = SecurityEvent {
                id: id.clone(),
                timestamp: timestamp.to_string(),
                event_type: event_type.to_string(),
                severity: severity.to_string(),
                user_id: user_id.map(|s| s.to_string()),
                session_id: session_id.map(|s| s.to_string()),
                ip_address: ip_address.to_string(),
                user_agent: user_agent.to_string(),
                description: description.to_string(),
                indicators,
                response_actions,
                resolved: false,
                resolution_timestamp: None,
                resolution_details: None,
            };

            security_events.insert(id.clone(), security_event);

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "event_id": id,
                "status": "logged",
                "severity": severity,
                "timestamp": timestamp
            })))
        }))
        .route("/security/events/{event_id}/resolve", post(move |State(state): State<AuditState>, axum::extract::Path(event_id): axum::extract::Path<String>, Json(resolution): Json<serde_json::Value>| async move {
            let mut security_events = state.security_events.lock().await;

            if let Some(event) = security_events.get_mut(&event_id) {
                let resolution_details = resolution.get("details").and_then(|d| d.as_str()).unwrap_or("");
                let resolution_timestamp = "2024-12-01T13:00:00Z".to_string();

                event.resolved = true;
                event.resolution_timestamp = Some(resolution_timestamp.clone());
                event.resolution_details = Some(resolution_details.to_string());

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "event_id": event_id,
                    "resolved": true,
                    "resolution_timestamp": resolution_timestamp,
                    "details": resolution_details
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/security/events/dashboard", get(move |State(state): State<AuditState>| async move {
            let security_events = state.security_events.lock().await;

            let total_events = security_events.len();
            let unresolved_events = security_events.values().filter(|e| !e.resolved).count();
            let critical_events = security_events.values().filter(|e| e.severity == "critical").count();
            let high_severity_events = security_events.values().filter(|e| e.severity == "high").count();

            let events_by_type: HashMap<String, usize> = security_events.values()
                .fold(HashMap::new(), |mut acc, event| {
                    *acc.entry(event.event_type.clone()).or_insert(0) += 1;
                    acc
                });

            let recent_events: Vec<serde_json::Value> = security_events.values()
                .filter(|e| !e.resolved)
                .take(10)
                .map(|e| json!({
                    "id": e.id,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "description": e.description,
                    "timestamp": e.timestamp,
                    "ip_address": e.ip_address
                }))
                .collect();

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "total_events": total_events,
                "unresolved_events": unresolved_events,
                "critical_events": critical_events,
                "high_severity_events": high_severity_events,
                "events_by_type": events_by_type,
                "recent_unresolved_events": recent_events,
                "last_updated": "2024-12-01T12:00:00Z"
            })))
        }))
        .with_state(audit_state);

    let server = TestServer::new(app).unwrap();

    // Test creating security events
    let event_data = json!({
        "timestamp": "2024-12-01T12:00:00Z",
        "event_type": "brute_force_attempt",
        "severity": "high",
        "user_id": "user_123",
        "session_id": "session_456",
        "ip_address": "192.168.1.100",
        "user_agent": "Bot/1.0",
        "description": "Multiple failed login attempts detected from suspicious IP",
        "indicators": ["multiple_failed_logins", "suspicious_user_agent", "unusual_timing"],
        "response_actions": ["block_ip_temporarily", "notify_security_team", "require_mfa"]
    });
    let response = server.post("/security/events").json(&event_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let event_id = body["event_id"].as_str().unwrap();

    // Test resolving security event
    let resolution_data = json!({
        "details": "IP blocked for 24 hours, MFA required for user account"
    });
    let response = server
        .post(&format!("/security/events/{}/resolve", event_id))
        .json(&resolution_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["resolved"], true);

    // Test security dashboard
    let response = server.get("/security/events/dashboard").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_events"], 1);
    assert_eq!(body["unresolved_events"], 0); // Event was resolved
    assert_eq!(body["high_severity_events"], 1);
}

#[tokio::test]
async fn test_audit_trail_and_retention_policies() {
    let audit_state = AuditState::new();

    let app = Router::new()
        .route("/audit/trails/{user_id}", post(move |State(state): State<AuditState>, axum::extract::Path(user_id): axum::extract::Path<String>, Json(trail_entry): Json<serde_json::Value>| async move {
            let mut audit_trails = state.audit_trails.lock().await;

            let id = format!("trail_{}", audit_trails.len() + 1);
            let timestamp = trail_entry.get("timestamp").and_then(|t| t.as_str()).unwrap_or("2024-12-01T12:00:00Z");
            let action = trail_entry.get("action").and_then(|a| a.as_str()).unwrap_or("unknown");
            let before_state = trail_entry.get("before_state");
            let after_state = trail_entry.get("after_state");
            let reason = trail_entry.get("reason").and_then(|r| r.as_str());
            let authorized_by = trail_entry.get("authorized_by").and_then(|a| a.as_str());
            let ip_address = trail_entry.get("ip_address").and_then(|i| i.as_str()).unwrap_or("127.0.0.1");
            let session_id = trail_entry.get("session_id").and_then(|s| s.as_str()).unwrap_or("");

            let entry = AuditTrailEntry {
                id: id.clone(),
                timestamp: timestamp.to_string(),
                user_id: user_id.clone(),
                action: action.to_string(),
                before_state: before_state.cloned(),
                after_state: after_state.cloned(),
                reason: reason.map(|s| s.to_string()),
                authorized_by: authorized_by.map(|s| s.to_string()),
                ip_address: ip_address.to_string(),
                session_id: session_id.to_string(),
            };

            audit_trails.entry(user_id.clone())
                .or_insert_with(Vec::new)
                .push(entry);

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "trail_id": id,
                "user_id": user_id,
                "status": "recorded",
                "timestamp": timestamp
            })))
        }))
        .route("/audit/trails/{user_id}/history", get(move |State(state): State<AuditState>, axum::extract::Path(user_id): axum::extract::Path<String>| async move {
            let audit_trails = state.audit_trails.lock().await;

            if let Some(trails) = audit_trails.get(&user_id) {
                let trail_entries: Vec<serde_json::Value> = trails.iter()
                    .map(|entry| json!({
                        "id": entry.id,
                        "timestamp": entry.timestamp,
                        "action": entry.action,
                        "before_state": entry.before_state,
                        "after_state": entry.after_state,
                        "reason": entry.reason,
                        "authorized_by": entry.authorized_by,
                        "ip_address": entry.ip_address,
                        "session_id": entry.session_id
                    }))
                    .collect();

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "user_id": user_id,
                    "total_entries": trail_entries.len(),
                    "entries": trail_entries
                })))
            } else {
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "user_id": user_id,
                    "total_entries": 0,
                    "entries": []
                })))
            }
        }))
        .route("/audit/retention/policies", post(move |State(state): State<AuditState>, Json(policy): Json<serde_json::Value>| async move {
            let mut retention_policies = state.retention_policies.lock().await;

            let id = format!("policy_{}", retention_policies.len() + 1);
            let name = policy.get("name").and_then(|n| n.as_str()).unwrap_or("Default Policy");
            let data_type = policy.get("data_type").and_then(|d| d.as_str()).unwrap_or("audit_logs");
            let retention_days = policy.get("retention_days").and_then(|r| r.as_u64()).unwrap_or(2555) as u32; // 7 years
            let archive_after_days = policy.get("archive_after_days").and_then(|a| a.as_u64()).unwrap_or(365) as u32;
            let delete_after_days = policy.get("delete_after_days").and_then(|d| d.as_u64()).unwrap_or(2555) as u32;
            let encryption_required = policy.get("encryption_required").and_then(|e| e.as_bool()).unwrap_or(true);

            let compliance_standards = if let Some(standards) = policy.get("compliance_standards").and_then(|s| s.as_array()) {
                standards.iter().filter_map(|s| s.as_str()).map(|s| s.to_string()).collect()
            } else {
                vec!["GDPR".to_string(), "SOX".to_string()]
            };

            let retention_policy = RetentionPolicy {
                id: id.clone(),
                name: name.to_string(),
                data_type: data_type.to_string(),
                retention_days,
                archive_after_days,
                delete_after_days,
                encryption_required,
                compliance_standards,
            };

            retention_policies.insert(id.clone(), retention_policy);

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "policy_id": id,
                "status": "created",
                "retention_days": retention_days,
                "encryption_required": encryption_required
            })))
        }))
        .route("/audit/retention/cleanup", post(move |State(state): State<AuditState>, Json(cleanup_request): Json<serde_json::Value>| async move {
            let retention_policies = state.retention_policies.lock().await;
            let mut audit_logs = state.audit_logs.lock().await;
            let mut compliance_logs = state.compliance_logs.lock().await;

            let policy_id = cleanup_request.get("policy_id").and_then(|p| p.as_str()).unwrap_or("");
            let dry_run = cleanup_request.get("dry_run").and_then(|d| d.as_bool()).unwrap_or(true);

            if let Some(policy) = retention_policies.get(policy_id) {
                let mut cleanup_results = HashMap::new();

                // Simulate cleanup based on data type
                match policy.data_type.as_str() {
                    "audit_logs" => {
                        let expired_count = audit_logs.values()
                            .filter(|log| {
                                // Simple date comparison simulation
                                log.timestamp.as_str() < "2024-01-01T00:00:00Z"
                            })
                            .count();

                        if !dry_run {
                            // In real implementation, would delete expired logs
                            audit_logs.retain(|_, log| log.timestamp.as_str() >= "2024-01-01T00:00:00Z");
                        }

                        cleanup_results.insert("audit_logs", json!({
                            "expired_count": expired_count,
                            "retained_count": audit_logs.len(),
                            "policy_applied": policy.name
                        }));
                    }
                    "compliance_logs" => {
                        let expired_count = compliance_logs.values()
                            .filter(|log| log.timestamp.as_str() < "2024-01-01T00:00:00Z")
                            .count();

                        if !dry_run {
                            compliance_logs.retain(|_, log| log.timestamp.as_str() >= "2024-01-01T00:00:00Z");
                        }

                        cleanup_results.insert("compliance_logs", json!({
                            "expired_count": expired_count,
                            "retained_count": compliance_logs.len(),
                            "policy_applied": policy.name
                        }));
                    }
                    _ => {}
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "cleanup_id": format!("cleanup_{}", chrono::Utc::now().timestamp()),
                    "policy_id": policy_id,
                    "dry_run": dry_run,
                    "results": cleanup_results,
                    "timestamp": "2024-12-01T12:00:00Z"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(audit_state);

    let server = TestServer::new(app).unwrap();

    // Test creating audit trail entries
    let trail_data = json!({
        "timestamp": "2024-12-01T12:00:00Z",
        "action": "password_change",
        "before_state": {"password_hash": "old_hash"},
        "after_state": {"password_hash": "new_hash"},
        "reason": "Security policy requirement",
        "authorized_by": "user_123",
        "ip_address": "192.168.1.100",
        "session_id": "session_456"
    });
    let response = server
        .post("/audit/trails/user_123")
        .json(&trail_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["trail_id"].as_str().is_some());

    // Test retrieving audit trail history
    let response = server.get("/audit/trails/user_123/history").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_entries"], 1);
    assert_eq!(body["entries"][0]["action"], "password_change");

    // Test creating retention policy
    let policy_data = json!({
        "name": "GDPR Audit Log Retention",
        "data_type": "audit_logs",
        "retention_days": 2555,
        "archive_after_days": 365,
        "delete_after_days": 2555,
        "encryption_required": true,
        "compliance_standards": ["GDPR", "SOX", "HIPAA"]
    });
    let response = server
        .post("/audit/retention/policies")
        .json(&policy_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let policy_id = body["policy_id"].as_str().unwrap();

    // Test retention cleanup (dry run)
    let cleanup_data = json!({
        "policy_id": policy_id,
        "dry_run": true
    });
    let response = server
        .post("/audit/retention/cleanup")
        .json(&cleanup_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["dry_run"], true);
    assert!(body["results"]["audit_logs"]["expired_count"]
        .as_u64()
        .is_some());
}
