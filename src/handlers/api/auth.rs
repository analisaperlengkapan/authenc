use actix_web::{post, web, HttpResponse, Responder, HttpRequest};
use crate::error::ApiError;
use serde::Deserialize;
use crate::models::user::User;
use crate::utils::crypto::password;
use crate::utils::jwt;
use crate::services::user_store::UserStore;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub realm: String,
}

#[post("/login")]
pub async fn login(
    req: web::Json<LoginRequest>,
    http_req: HttpRequest,
    i18n: web::Data<crate::utils::i18n::I18n>,
    user_store: web::Data<UserStore>,
) -> impl Responder {
    let locale = http_req
        .headers()
        .get("Accept-Language")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("en-US");

    let users = user_store.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.username == req.username && u.realm == req.realm) {
        if password::verify_password(&user.password_hash, &req.password).unwrap_or(false) {
            let token = jwt::generate_jwt(&user.id).unwrap();
            let msg = i18n.t(locale, "login_success", None);
            return HttpResponse::Ok().json(serde_json::json!({"access_token": token, "message": msg}));
        }
    }
    let msg = i18n.t(locale, "login_failed", None);
    ApiError { code: 401, message: msg }.error_response()
}
