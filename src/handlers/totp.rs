use crate::services::totp_store::TotpStore;
// TODO: Migrate to Axum - temporarily commented out
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
    if let Err(e) = totp_store.set_secret(&user_id, &req.secret) {
        log::warn!("Failed to set TOTP secret: {}", e);
    }
    HttpResponse::Ok().body("TOTP enabled")
}

#[delete("/users/{id}/totp")]
pub async fn disable_totp(
    totp_store: web::Data<TotpStore>,
    path: web::Path<String>,
) -> impl Responder {
    let user_id = path.into_inner();
    if let Err(e) = totp_store.remove_secret(&user_id) {
        log::warn!("Failed to remove TOTP secret: {}", e);
    }
    HttpResponse::Ok().body("TOTP disabled")
}
