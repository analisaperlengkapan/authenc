use actix_web::{post, get, web, HttpResponse, Responder};

#[post("/audit")] 
pub async fn add_audit_log() -> impl Responder {
    HttpResponse::Ok().body("add_audit_log")
}

#[get("/audit")]
pub async fn get_audit_logs() -> impl Responder {
    HttpResponse::Ok().body("get_audit_logs")
}
