use crate::services::group_store::GroupStore;
// TODO: Migrate to Axum - temporarily commented out
// use axum::{extract::Query, response::Json};ponder};
// TODO: Migrate to Axum - temporarily commented out
// use axum::{extract::Query, response::Json};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub realm_id: Uuid,
}

#[post("/groups")]
pub async fn create_group(
    group_store: web::Data<GroupStore>,
    req: web::Json<CreateGroupRequest>,
) -> impl Responder {
    let group = group_store.create(req.realm_id, &req.name, req.description.clone());
    HttpResponse::Created().json(group)
}

#[get("/groups")]
pub async fn get_groups(group_store: web::Data<GroupStore>) -> impl Responder {
    let groups = group_store.all();
    HttpResponse::Ok().json(groups)
}

#[get("/groups/{id}")]
pub async fn get_group_by_id(
    group_store: web::Data<GroupStore>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    match group_store.get(&id) {
        Some(group) => HttpResponse::Ok().json(group),
        None => HttpResponse::NotFound().body("Group not found"),
    }
}

#[delete("/groups/{id}")]
pub async fn delete_group(
    group_store: web::Data<GroupStore>,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    let deleted = group_store.delete(&id);
    if deleted {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().body("Group not found")
    }
}

#[post("/groups/{id}/members/{user_id}")]
pub async fn add_group_member() -> impl Responder {
    HttpResponse::NotImplemented().body("Group membership management not implemented yet")
}

#[delete("/groups/{id}/members/{user_id}")]
pub async fn remove_group_member() -> impl Responder {
    HttpResponse::NotImplemented().body("Group membership management not implemented yet")
}

#[post("/groups/{id}/roles/{role_id}")]
pub async fn add_group_role() -> impl Responder {
    HttpResponse::NotImplemented().body("Group role management not implemented yet")
}

#[delete("/groups/{id}/roles/{role_id}")]
pub async fn remove_group_role() -> impl Responder {
    HttpResponse::NotImplemented().body("Group role management not implemented yet")
}
