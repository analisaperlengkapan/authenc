use actix_web::{get, post, delete, web, HttpResponse, Responder};
use crate::services::permission_store::PermissionStore;
use crate::model::permission::Permission;
use serde::Deserialize;
use uuid::Uuid;

#[get("/realms/{realm}/permissions")]
pub async fn get_permissions(data: web::Data<PermissionStore>, path: web::Path<String>) -> impl Responder {
    let realm = path.into_inner();
    let permissions = data.get_all();
    let filtered: Vec<Permission> = permissions.into_iter().filter(|p| p.realm == realm).collect();
    HttpResponse::Ok().json(filtered)
}

#[derive(Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub description: Option<String>,
}

#[post("/realms/{realm}/permissions")]
pub async fn create_permission(data: web::Data<PermissionStore>, path: web::Path<String>, req: web::Json<CreatePermissionRequest>) -> impl Responder {
    let realm = path.into_inner();
    let permissions = data.permissions.lock().unwrap();
    if permissions.iter().any(|p| p.realm == realm && p.name == req.name) {
        return HttpResponse::BadRequest().body("Permission already exists in this realm");
    }
    drop(permissions);
    let permission = Permission {
        id: Uuid::new_v4().to_string(),
        name: req.name.clone(),
        realm: realm.clone(),
        description: req.description.clone(),
    };
    data.add_permission(permission);
    HttpResponse::Created().body("Permission created")
}

#[delete("/realms/{realm}/permissions/{name}")]
pub async fn delete_permission(data: web::Data<PermissionStore>, path: web::Path<(String, String)>) -> impl Responder {
    let (realm, name) = path.into_inner();
    if data.delete_by_name(&realm, &name) {
        HttpResponse::Ok().body("Permission deleted")
    } else {
        HttpResponse::NotFound().body("Permission not found")
    }
}
