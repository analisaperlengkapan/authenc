use actix_web::{delete, get, post, web, HttpResponse, Responder};
use crate::services::role_store::RoleStore;
use crate::model::role::Role;
use serde::Deserialize;
use uuid::Uuid;

#[get("/realms/{realm}/roles")]
pub async fn get_roles(data: web::Data<RoleStore>, path: web::Path<String>) -> impl Responder {
    let realm = path.into_inner();
    let roles = data.get_all();
    let filtered: Vec<Role> = roles.into_iter().filter(|r| r.realm == realm).collect();
    HttpResponse::Ok().json(filtered)
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
}

#[post("/realms/{realm}/roles")]
pub async fn create_role(data: web::Data<RoleStore>, path: web::Path<String>, req: web::Json<CreateRoleRequest>) -> impl Responder {
    let realm = path.into_inner();
    let roles = data.roles.lock().unwrap();
    if roles.iter().any(|r| r.realm == realm && r.name == req.name) {
        return HttpResponse::BadRequest().body("Role already exists in this realm");
    }
    drop(roles);
    let role = Role {
        id: Uuid::new_v4().to_string(),
        name: req.name.clone(),
        realm: realm.clone(),
    };
    data.add_role(role);
    HttpResponse::Created().body("Role created")
}

#[delete("/realms/{realm}/roles/{name}")]
pub async fn delete_role(data: web::Data<RoleStore>, path: web::Path<(String, String)>) -> impl Responder {
    let (realm, name) = path.into_inner();
    if data.delete_by_name(&realm, &name) {
        HttpResponse::Ok().body("Role deleted")
    } else {
        HttpResponse::NotFound().body("Role not found")
    }
}

#[post("/realms/{realm}/roles/{role}/permissions/{permission}")]
pub async fn assign_permission_to_role(
    data: web::Data<RoleStore>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    let (realm, role_name, permission) = path.into_inner();
    let mut roles = data.roles.lock().unwrap();
    if let Some(role) = roles.iter_mut().find(|r| r.realm == realm && r.name == role_name) {
        if !role.permissions.contains(&permission) {
            role.permissions.push(permission.clone());
        }
        HttpResponse::Ok().body("Permission assigned to role")
    } else {
        HttpResponse::NotFound().body("Role not found")
    }
}

#[delete("/realms/{realm}/roles/{role}/permissions/{permission}")]
pub async fn unassign_permission_from_role(
    data: web::Data<RoleStore>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    let (realm, role_name, permission) = path.into_inner();
    let mut roles = data.roles.lock().unwrap();
    if let Some(role) = roles.iter_mut().find(|r| r.realm == realm && r.name == role_name) {
        role.permissions.retain(|p| p != &permission);
        HttpResponse::Ok().body("Permission unassigned from role")
    } else {
        HttpResponse::NotFound().body("Role not found")
    }
}
