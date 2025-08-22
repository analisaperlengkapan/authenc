use crate::services::totp_store::TotpStore;
use actix_web::{post, web, HttpResponse, Responder};
use serde::Deserialize;
use totp_rs::{Algorithm, TOTP};

#[derive(Deserialize)]
pub struct VerifyTotpRequest {
    pub user_id: String,
    pub code: String,
}

#[post("/users/{id}/totp/verify")]
pub async fn verify_totp(
    totp_store: web::Data<TotpStore>,
    path: web::Path<String>,
    req: web::Json<VerifyTotpRequest>,
) -> impl Responder {
    let user_id = path.into_inner();
    match totp_store.get_secret(&user_id) {
        Ok(Some(secret)) => {
            let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.as_bytes().to_vec());
            match totp {
                Ok(totp) => {
                    if totp.check_current(&req.code).unwrap_or(false) {
                        HttpResponse::Ok().body("TOTP valid")
                    } else {
                        HttpResponse::Unauthorized().body("Invalid TOTP code")
                    }
                }
                Err(_) => HttpResponse::InternalServerError().body("TOTP error"),
            }
        }
        Ok(None) => HttpResponse::BadRequest().body("TOTP not enabled for user"),
        Err(e) => HttpResponse::InternalServerError().body(format!("TOTP store error: {e}")),
    }
}
