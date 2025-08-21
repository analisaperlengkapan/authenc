use actix_web::{post, web, HttpResponse, Responder};
use crate::services::user_store::UserStore;
use serde::Deserialize;


#[derive(Deserialize)]
pub struct LoginRequest {
	pub username: String,
	pub password: String,
}

#[post("/login")]
pub async fn login(
	user_store: web::Data<UserStore>,
	req: web::Json<LoginRequest>,
) -> impl Responder {
	if user_store.verify_password(&req.username, &req.password) {
		HttpResponse::Ok().body("login success")
	} else {
		HttpResponse::Unauthorized().body("invalid credentials")
	}
}
