
use actix_web::{post, web, HttpResponse, Responder};
use crate::services::user_store::UserStore;
use crate::services::totp_store::TotpStore;
use crate::services::session_store::SessionStore;
use serde::Deserialize;
use totp_rs::{Algorithm, TOTP};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;

#[derive(Deserialize)]
pub struct LoginRequest {
	pub username: String,
	pub password: String,
	pub totp_code: Option<String>,
}


#[derive(Serialize)]
struct Claims {
	sub: String,
	exp: usize,
}

#[post("/login")]
pub async fn login(
	user_store: web::Data<UserStore>,
	totp_store: web::Data<TotpStore>,
	session_store: web::Data<SessionStore>,
	req: web::Json<LoginRequest>,
) -> impl Responder {
	if !user_store.verify_password(&req.username, &req.password) {
		return HttpResponse::Unauthorized().body("invalid credentials");
	}

	// Check if user has TOTP enabled
	let user = match user_store.get_by_username(&req.username) {
		Some(u) => u,
		None => return HttpResponse::Unauthorized().body("invalid credentials"),
	};
	if let Some(secret) = totp_store.get_secret(&user.id) {
		// Require TOTP code
		let code = match &req.totp_code {
			Some(c) => c,
			None => return HttpResponse::Unauthorized().body("TOTP code required"),
		};
		let totp = TOTP::new(
			Algorithm::SHA1,
			6,
			1,
			30,
			secret.as_bytes().to_vec(),
		);
		match totp {
			Ok(totp) => {
				if !totp.check_current(code).unwrap_or(false) {
					return HttpResponse::Unauthorized().body("Invalid TOTP code");
				}
			}
			Err(_) => return HttpResponse::InternalServerError().body("TOTP error"),
		}
	}

	// Issue JWT
	let expiration = chrono::Utc::now().timestamp() as usize + 3600; // 1 hour expiry
	let claims = Claims {
		sub: user.id.clone(),
		exp: expiration,
	};
	let secret = std::env::var("AUTHENCE_JWT_SECRET").unwrap_or_else(|_| "dev_secret_key_change_me".to_string());
	let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())) {
		Ok(t) => t,
		Err(_) => return HttpResponse::InternalServerError().body("Token generation error"),
	};
	session_store.add(&token, &user.id);
	HttpResponse::Ok().json(serde_json::json!({"token": token}))
}
