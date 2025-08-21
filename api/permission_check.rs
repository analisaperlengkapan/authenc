use actix_web::{web, HttpResponse, Responder, get};
use crate::services::{user_store::UserStore, role_store::RoleStore};
use crate::api::auth_bearer::AuthBearer;

#[get("/realms/{realm}/permissions/check")]
pub async fn check_user_permission(
    user_store: web::Data<UserStore>,
    role_store: web::Data<RoleStore>,
    path: web::Path<String>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    let realm = path.into_inner();
    let auth: Result<AuthBearer, _> = req.extract();
    let auth = match auth {
        Ok(a) => a,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };
    let user_id = auth.0.sub;
    let perm = req.query_string().split("permission=").nth(1).unwrap_or("");
    if perm.is_empty() {
        return HttpResponse::BadRequest().body("Missing permission query param");
    }
    let users = user_store.users.lock().unwrap();
    let user = if let Some(u) = users.iter().find(|u| u.id == user_id && u.realm == realm) {
        u
    } else {
        return HttpResponse::NotFound().body("User not found");
    };
    let roles = role_store.roles.lock().unwrap();
    for role_name in &user.roles {
        if let Some(role) = roles.iter().find(|r| r.realm == realm && &r.name == role_name) {
            if role.permissions.iter().any(|p| p == perm) {
                return HttpResponse::Ok().body("true");
            }
        }
    }
    HttpResponse::Ok().body("false")
}
