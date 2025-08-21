use actix_web::{get, post, put, delete, web, HttpResponse, Responder};
use crate::services::user_store::UserStore;
use crate::model::user::User;
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

#[post("/users/{id}/password")]
pub async fn update_password() -> impl Responder {
	HttpResponse::Ok().body("update_password")
}
// Stub for api::user
