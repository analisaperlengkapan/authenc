use actix_web::{get, post, put, delete, web, HttpResponse, Responder};
use crate::services::user_store::UserStore;
use crate::model::user::User;
use crate::services::password_policy::PasswordPolicy;
use serde::Deserialize;

#[get("/users")]
pub async fn get_users(user_store: web::Data<UserStore>) -> impl Responder {
	let users = user_store.all();
	HttpResponse::Ok().json(users)
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
	pub username: Option<String>,
	pub email: Option<String>,
	pub password: Option<String>,
	pub is_active: Option<bool>,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
	pub username: String,
	pub email: String,
	pub password: String,
}

#[post("/users")]
pub async fn create_user(
	user_store: web::Data<UserStore>,
	req: web::Json<CreateUserRequest>,
) -> impl Responder {
	let policy = PasswordPolicy::default();
	if let Err(msg) = policy.validate(&req.password) {
		return HttpResponse::BadRequest().body(format!("Password policy violation: {}", msg));
	}
	let user = User {
		id: uuid::Uuid::new_v4().to_string(),
		username: req.username.clone(),
		email: req.email.clone(),
		password_hash: req.password.clone(), // For demo, store plain. Use hash in prod.
		is_active: true,
	};
	user_store.add_user(user);
	HttpResponse::Created().body("user created")
}

#[get("/users/{id}")]
pub async fn get_user_by_id() -> impl Responder {
	HttpResponse::Ok().body("get_user_by_id")
}

#[put("/users/{id}")]
pub async fn update_user() -> impl Responder {
	HttpResponse::Ok().body("update_user")
}

#[delete("/users/{id}")]
pub async fn delete_user() -> impl Responder {
	HttpResponse::Ok().body("delete_user")
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
	pub password: String,
}

#[post("/users/{id}/password")]
pub async fn update_password(
	user_store: web::Data<UserStore>,
	path: web::Path<String>,
	req: web::Json<UpdatePasswordRequest>,
) -> impl Responder {
	let policy = PasswordPolicy::default();
	if let Err(msg) = policy.validate(&req.password) {
		return HttpResponse::BadRequest().body(format!("Password policy violation: {}", msg));
	}
	let id = path.into_inner();
	let updated = user_store.update(&id, None, None, Some(&req.password), None);
	if updated.is_some() {
		HttpResponse::Ok().body("Password updated")
	} else {
		HttpResponse::NotFound().body("User not found")
	}
}
// Stub for api::user
