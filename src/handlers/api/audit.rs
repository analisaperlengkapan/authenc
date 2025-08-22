use actix_web::{web, HttpResponse, Responder, post};
use chrono::Utc;
use serde::{Serialize, Deserialize};
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditLog {
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub realm: String,
    pub details: Option<String>,
}

pub struct AuditLogStore {
    pub logs: Mutex<Vec<AuditLog>>,
}

impl AuditLogStore {
    pub fn new() -> Self {
        Self { logs: Mutex::new(vec![]) }
    }
    pub fn add_log(&self, log: AuditLog) {
        self.logs.lock().unwrap().push(log);
    }
    pub fn get_all(&self) -> Vec<AuditLog> {
        self.logs.lock().unwrap().clone()
    }
}

#[post("/realms/{realm}/audit")]
pub async fn add_audit_log(
    data: web::Data<AuditLogStore>,
    path: web::Path<String>,
    req: web::Json<AuditLog>,
) -> impl Responder {
    let mut log = req.into_inner();
    log.realm = path.into_inner();
    log.timestamp = Utc::now().to_rfc3339();
    data.add_log(log);
    HttpResponse::Created().body("Audit log added")
}

#[actix_web::get("/realms/{realm}/audit")]
pub async fn get_audit_logs(
    data: web::Data<AuditLogStore>,
    path: web::Path<String>,
) -> impl Responder {
    let realm = path.into_inner();
    let logs = data.get_all();
    let filtered: Vec<AuditLog> = logs.into_iter().filter(|l| l.realm == realm).collect();
    HttpResponse::Ok().json(filtered)
}
