use actix_web::{web, HttpResponse, Responder, get};
use crate::services::{user_store::UserStore, role_store::RoleStore};

#[get("/realms/{realm}/users/{user_id}/permissions")]
pub async fn get_user_permissions(
    user_store: web::Data<UserStore>,
    role_store: web::Data<RoleStore>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (realm, user_id) = path.into_inner();
    let users = user_store.users.lock().unwrap();
    let user = if let Some(u) = users.iter().find(|u| u.id == user_id && u.realm == realm) {
        u
    } else {
        return HttpResponse::NotFound().body("User not found");
    };
    let roles = role_store.roles.lock().unwrap();
    let mut permissions = vec![];
    for role_name in &user.roles {
        if let Some(role) = roles.iter().find(|r| r.realm == realm && &r.name == role_name) {
            for perm in &role.permissions {
                if !permissions.contains(perm) {
                    permissions.push(perm.clone());
                }
            }
        }
    }
    HttpResponse::Ok().json(permissions)
}
