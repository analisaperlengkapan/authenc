use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use crate::services::session_store::SessionStore;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

fn extract_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

#[get("/sessions")]
pub async fn list_sessions(
    session_store: web::Data<SessionStore>,
    req: HttpRequest,
) -> impl Responder {
    let token = match extract_token(&req) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Missing token"),
    };
    let secret = std::env::var("AUTHENCE_JWT_SECRET").unwrap_or_else(|_| "dev_secret_key_change_me".to_string());
    let decoded = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default());
    let user_id = match decoded {
        Ok(data) => data.claims.sub,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };
    let sessions = session_store.all_for_user(&user_id);
    HttpResponse::Ok().json(sessions)
}

#[post("/logout")]
pub async fn logout(
    session_store: web::Data<SessionStore>,
    req: HttpRequest,
) -> impl Responder {
    let token = match extract_token(&req) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Missing token"),
    };
    session_store.remove(&token);
    HttpResponse::Ok().body("Logged out")
}
