
use actix_web::{post, web, HttpResponse, Responder};
use crate::services::user_store::UserStore;
use crate::services::federation_provider::FederationRegistry;
use crate::services::totp_store::TotpStore;
use crate::services::session_store::SessionStore;
use crate::services::brute_force_protector::BruteForceProtector;
use serde::Deserialize;
use crate::services::anomaly_detector::AnomalyDetector;
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
	brute_force: web::Data<BruteForceProtector>,
	anomaly_detector: web::Data<AnomalyDetector>,
	federation_registry: web::Data<FederationRegistry>,
	req: web::Json<LoginRequest>,
	req_head: actix_web::HttpRequest,
) -> impl Responder {
	let key = &req.username;
	if brute_force.register_attempt(key) {
		return HttpResponse::TooManyRequests().body("Too many failed attempts. Please try again later.");
	}

	// Try local user store first
	let mut user = user_store.get_by_username(&req.username);
	let mut valid = user.as_ref().map(|_| user_store.verify_password(&req.username, &req.password)).unwrap_or(false);
	// If not found or invalid, try federation
	if !valid {
		user = federation_registry.get_user_by_username(&req.username);
		valid = user.as_ref().map(|_| federation_registry.verify_password(&req.username, &req.password)).unwrap_or(false);
	}
	if !valid {
		return HttpResponse::Unauthorized().body("invalid credentials");
	}
	// On success, clear attempts
	brute_force.clear(key);
	// Anomaly detection: check if login from new IP
	if let Some(ref user) = user {
		let ip = req_head.connection_info().realip_remote_addr().unwrap_or("").to_string();
		let is_new_ip = anomaly_detector.is_new_ip(&user.id, &ip);
		if is_new_ip {
			// TODO: log anomaly, send notification, or require extra verification
			println!("[ANOMALY] User {} login from new IP: {}", user.username, ip);
		}
	}
	let user = match user {
		Some(u) => u,
		None => return HttpResponse::Unauthorized().body("invalid credentials"),
	};

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
