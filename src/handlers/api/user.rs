use actix_web::patch;
#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[patch("/realms/{realm}/users/{id}/password")]
pub async fn update_password(
    data: web::Data<UserStore>,
    _auth: AuthBearer,
    path: Path<(String, String)>,
    req: web::Json<UpdatePasswordRequest>,
) -> impl Responder {
    let (realm, id) = path.into_inner();
    let mut users = data.users.lock().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.id == id && u.realm == realm) {
        if crate::crypto::password::verify_password(&user.password_hash, &req.old_password).unwrap_or(false) {
            match crate::crypto::password::hash_password(&req.new_password) {
                Ok(new_hash) => {
                    user.password_hash = new_hash;
                    HttpResponse::Ok().body("Password updated")
                },
                Err(_) => HttpResponse::InternalServerError().body("Failed to hash new password"),
            }
        } else {
            HttpResponse::Unauthorized().body("Old password incorrect")
        }
    } else {
        HttpResponse::NotFound().body("User not found")
    }
}
use actix_web::{get, post, put, delete, web, HttpResponse, Responder};
use crate::handlers::api::auth_bearer::AuthBearer;
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
}

#[put("/realms/{realm}/users/{id}")]
pub async fn update_user(
    data: web::Data<UserStore>,
    _auth: AuthBearer,
    path: Path<(String, String)>,
    req: web::Json<UpdateUserRequest>,
) -> impl Responder {
    let (realm, id) = path.into_inner();
    let mut users = data.users.lock().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.id == id && u.realm == realm) {
        if let Some(username) = &req.username {
            user.username = username.clone();
        }
        if let Some(email) = &req.email {
            user.email = email.clone();
        }
        return HttpResponse::Ok().body("User updated");
    }
    HttpResponse::NotFound().body("User not found")
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub roles: Option<Vec<String>>,
}

#[post("/realms/{realm}/users")]
pub async fn create_user(
    data: web::Data<UserStore>,
    path: Path<(String,)>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    let realm = &path.0;
    let users = data.users.lock().unwrap();
    if users.iter().any(|u| (u.username == req.username || u.email == req.email) && &u.realm == realm) {
        return HttpResponse::BadRequest().body("Username or email already exists in this realm");
    }
    drop(users);

    let password_hash = match password::hash_password(&req.password) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password"),
    };
    let user = User {
        id: Uuid::new_v4().to_string(),
        username: req.username.clone(),
        email: req.email.clone(),
        password_hash,
        is_active: true,
        roles: req.roles.clone().unwrap_or_else(|| vec!["user".to_string()]),
        realm: realm.clone(),
    };
    data.add_user(user);
    HttpResponse::Created().body("User created")
}

#[delete("/realms/{realm}/users/{id}")]
pub async fn delete_user(
    data: web::Data<UserStore>,
    auth: AuthBearer,
    path: Path<(String, String)>,
) -> impl Responder {
    let (realm, id) = path.into_inner();
    // Only admin can delete users
    let users = data.users.lock().unwrap();
    let maybe_admin = users.iter().find(|u| u.id == auth.0.sub && u.realm == realm);
    if maybe_admin.map(|u| u.roles.iter().any(|r| r == "admin")).unwrap_or(false) == false {
        return HttpResponse::Forbidden().body("Only admin can delete users");
    }
    drop(users);
    let mut users = data.users.lock().unwrap();
    let len_before = users.len();
    users.retain(|u| !(u.id == id && u.realm == realm));
    if users.len() < len_before {
        HttpResponse::Ok().body("User deleted")
    } else {
        HttpResponse::NotFound().body("User not found")
    }
}
use crate::services::user_store::UserStore;
use crate::model::user::User;
use actix_web::{http::header::AUTHORIZATION, post};
use crate::crypto::jwt;
use crate::crypto::{jwt, password};
use serde::Deserialize;
use uuid::Uuid;
use actix_web::web::Path;

#[get("/realms/{realm}/users")]
pub async fn get_users(
    data: web::Data<UserStore>,
    _auth: AuthBearer,
    path: Path<(String,)>,
) -> impl Responder {
    let realm = &path.0;
    let users = data.get_all();
    let filtered: Vec<User> = users.into_iter().filter(|u| &u.realm == realm).collect();
    HttpResponse::Ok().json(filtered)
}

#[get("/realms/{realm}/users/{id}")]
pub async fn get_user_by_id(
    data: web::Data<UserStore>,
    _auth: AuthBearer,
    path: Path<(String, String)>,
) -> impl Responder {
    let (realm, id) = path.into_inner();
    let users = data.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.id == id && u.realm == realm) {
        HttpResponse::Ok().json(user)
    } else {
        HttpResponse::NotFound().body("User not found")
    }
}
