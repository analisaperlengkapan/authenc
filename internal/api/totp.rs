use actix_web::{post, delete, web, HttpResponse, Responder};
use crate::services::totp_store::TotpStore;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct EnableTotpRequest {
    pub user_id: String,
    pub secret: String, // base32
}

#[post("/users/{id}/totp")]
pub async fn enable_totp(
    totp_store: web::Data<TotpStore>,
    path: web::Path<String>,
    req: web::Json<EnableTotpRequest>,
) -> impl Responder {
    let user_id = path.into_inner();
    totp_store.set_secret(&user_id, &req.secret);
    HttpResponse::Ok().body("TOTP enabled")
}

#[delete("/users/{id}/totp")]
pub async fn disable_totp(
    totp_store: web::Data<TotpStore>,
    path: web::Path<String>,
) -> impl Responder {
    let user_id = path.into_inner();
    totp_store.remove_secret(&user_id);
    HttpResponse::Ok().body("TOTP disabled")
}
