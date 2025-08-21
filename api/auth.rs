use actix_web::{post, web, HttpResponse, Responder, HttpRequest};
use crate::error::ApiError;
use serde::Deserialize;
use crate::model::user::User;
use crate::crypto::{password, jwt};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[post("/login")]
pub async fn login(req: web::Json<LoginRequest>, http_req: HttpRequest, i18n: web::Data<crate::i18n::I18n>) -> impl Responder {
    // Dummy user for demonstration
    let user = User {
        id: "1".to_string(),
        username: req.username.clone(),
        email: "user@example.com".to_string(),
        password_hash: password::hash_password("password").unwrap(),
        is_active: true,
    };

    let locale = http_req
        .headers()
        .get("Accept-Language")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("en-US");

    if password::verify_password(&user.password_hash, &req.password).unwrap_or(false) {
        let token = jwt::generate_jwt(&user.id).unwrap();
        let msg = i18n.t(locale, "login_success", None);
        HttpResponse::Ok().json(serde_json::json!({"token": token, "message": msg}))
    } else {
        let msg = i18n.t(locale, "login_failed", None);
        ApiError { code: 401, message: msg }.error_response()
    }
}
