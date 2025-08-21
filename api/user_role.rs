use actix_web::{post, delete, web, HttpResponse, Responder};
use crate::services::user_store::UserStore;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RoleAssignmentRequest {
    pub user_id: String,
    pub role: String,
}

#[post("/realms/{realm}/users/{user_id}/roles/{role}")]
pub async fn assign_role(
    data: web::Data<UserStore>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    let (realm, user_id, role) = path.into_inner();
    let mut users = data.users.lock().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.id == user_id && u.realm == realm) {
        if !user.roles.contains(&role) {
            user.roles.push(role.clone());
        }
        HttpResponse::Ok().body("Role assigned")
    } else {
        HttpResponse::NotFound().body("User not found")
    }
}

#[delete("/realms/{realm}/users/{user_id}/roles/{role}")]
pub async fn unassign_role(
    data: web::Data<UserStore>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    let (realm, user_id, role) = path.into_inner();
    let mut users = data.users.lock().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.id == user_id && u.realm == realm) {
        user.roles.retain(|r| r != &role);
        HttpResponse::Ok().body("Role unassigned")
    } else {
        HttpResponse::NotFound().body("User not found")
    }
}
