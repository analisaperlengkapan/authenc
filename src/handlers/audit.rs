use crate::services::pg_audit_log_store::PgAuditLogStore;
use crate::services::services::user_store::UserStore;
// Legacy Actix-web handler - needs migration to Axum
// TODO: Migrate to Axum handlers
// TODO: Migrate to Axum - temporarily commented out
// use axum::{extract::Query, response::Json};
use chrono::{DateTime, Utc};
use std::fmt::Write;

#[derive(serde::Deserialize)]
pub struct AuditLogQuery {
    pub event: Option<String>,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub status: Option<String>,
    pub from: Option<String>, // ISO8601
    pub to: Option<String>,   // ISO8601
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn get_audit_logs(
    req: HttpRequest,
    query: web::Query<AuditLogQuery>,
    audit_log_store: web::Data<PgAuditLogStore>,
    user_store: web::Data<UserStore>,
) -> HttpResponse {
    let auth = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());
    if let Some(auth) = auth {
        if let Some(_token) = auth.strip_prefix("Bearer ") {
            if let Some(user) = user_store.get_by_username("admin") {
                if user.username == "admin" {
                    let mut logs = match audit_log_store.all().await {
                        Ok(l) => l,
                        Err(e) => {
                            log::error!("audit log query error: {e}");
                            return HttpResponse::InternalServerError()
                                .body("Failed to query audit logs");
                        }
                    };
                    if let Some(ref event) = query.event {
                        logs.retain(|l| l.event == *event);
                    }
                    if let Some(ref user_id) = query.user_id {
                        logs.retain(|l| l.user_id.as_deref() == Some(user_id.as_str()));
                    }
                    if let Some(ref client_id) = query.client_id {
                        logs.retain(|l| l.client_id.as_deref() == Some(client_id.as_str()));
                    }
                    if let Some(ref status) = query.status {
                        logs.retain(|l| l.status == *status);
                    }
                    if let Some(ref from) = query.from {
                        if let Ok(from_dt) = DateTime::parse_from_rfc3339(from) {
                            let from_utc = from_dt.with_timezone(&Utc);
                            logs.retain(|l| l.timestamp >= from_utc);
                        }
                    }
                    if let Some(ref to) = query.to {
                        if let Ok(to_dt) = DateTime::parse_from_rfc3339(to) {
                            let to_utc = to_dt.with_timezone(&Utc);
                            logs.retain(|l| l.timestamp <= to_utc);
                        }
                    }
                    let offset = query.offset.unwrap_or(0);
                    let limit = query.limit.unwrap_or(100);
                    let total = logs.len();
                    let logs = logs
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    return HttpResponse::Ok().json(serde_json::json!({
                        "total": total,
                        "logs": logs,
                    }));
                } else {
                    return HttpResponse::Forbidden().body("Not admin");
                }
            } else {
                return HttpResponse::Unauthorized().body("User not found");
            }
        }
    }
    HttpResponse::Unauthorized().body("Invalid or missing token")
}

pub async fn export_audit_logs_csv(
    req: HttpRequest,
    query: web::Query<AuditLogQuery>,
    audit_log_store: web::Data<PgAuditLogStore>,
    user_store: web::Data<UserStore>,
) -> HttpResponse {
    let auth = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());
    if let Some(auth) = auth {
        if let Some(_token) = auth.strip_prefix("Bearer ") {
            if let Some(user) = user_store.get_by_username("admin") {
                if user.username == "admin" {
                    let mut logs = match audit_log_store.all().await {
                        Ok(l) => l,
                        Err(e) => {
                            log::error!("audit log query error: {e}");
                            return HttpResponse::InternalServerError()
                                .body("Failed to query audit logs");
                        }
                    };
                    if let Some(ref event) = query.event {
                        logs.retain(|l| l.event == *event);
                    }
                    if let Some(ref user_id) = query.user_id {
                        logs.retain(|l| l.user_id.as_deref() == Some(user_id.as_str()));
                    }
                    if let Some(ref client_id) = query.client_id {
                        logs.retain(|l| l.client_id.as_deref() == Some(client_id.as_str()));
                    }
                    if let Some(ref status) = query.status {
                        logs.retain(|l| l.status == *status);
                    }
                    if let Some(ref from) = query.from {
                        if let Ok(from_dt) = chrono::DateTime::parse_from_rfc3339(from) {
                            let from_utc = from_dt.with_timezone(&chrono::Utc);
                            logs.retain(|l| l.timestamp >= from_utc);
                        }
                    }
                    if let Some(ref to) = query.to {
                        if let Ok(to_dt) = chrono::DateTime::parse_from_rfc3339(to) {
                            let to_utc = to_dt.with_timezone(&chrono::Utc);
                            logs.retain(|l| l.timestamp <= to_utc);
                        }
                    }
                    let mut wtr = String::new();
                    wtr.push_str("timestamp,event,user_id,client_id,status,detail\n");
                    for log in logs {
                        let ts = log.timestamp.to_rfc3339();
                        let event = &log.event;
                        let user_id = log.user_id.as_deref().unwrap_or("");
                        let client_id = log.client_id.as_deref().unwrap_or("");
                        let status = &log.status;
                        let detail = log
                            .detail
                            .as_deref()
                            .unwrap_or("")
                            .replace('\n', " ")
                            .replace('"', "'");
                        let _ = writeln!(
                            wtr,
                            "\"{ts}\",\"{event}\",\"{user_id}\",\"{client_id}\",\"{status}\",\"{detail}\""
                        );
                    }
                    return HttpResponse::Ok().content_type("text/csv").body(wtr);
                } else {
                    return HttpResponse::Forbidden().body("Not admin");
                }
            } else {
                return HttpResponse::Unauthorized().body("User not found");
            }
        }
    }
    HttpResponse::Unauthorized().body("Invalid or missing token")
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/logs", web::get().to(get_audit_logs))
        .route("/logs/export", web::get().to(export_audit_logs_csv));
}
