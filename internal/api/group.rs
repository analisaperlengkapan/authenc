use actix_web::{get, post, delete, web, HttpResponse, Responder};
use crate::services::group_store::GroupStore;
// use crate::model::group::Group;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[post("/groups")]
pub async fn create_group(
    group_store: web::Data<GroupStore>,
    req: web::Json<CreateGroupRequest>,
) -> impl Responder {
    let group = group_store.create(&req.name, req.description.clone());
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
    path: web::Path<String>,
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
    path: web::Path<String>,
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
pub async fn add_group_member(
    group_store: web::Data<GroupStore>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (group_id, user_id) = path.into_inner();
    if group_store.add_member(&group_id, &user_id) {
        HttpResponse::Ok().body("Member added")
    } else {
        HttpResponse::NotFound().body("Group not found")
    }
}

#[delete("/groups/{id}/members/{user_id}")]
pub async fn remove_group_member(
    group_store: web::Data<GroupStore>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (group_id, user_id) = path.into_inner();
    if group_store.remove_member(&group_id, &user_id) {
        HttpResponse::Ok().body("Member removed")
    } else {
        HttpResponse::NotFound().body("Group not found")
    }
}

#[post("/groups/{id}/roles/{role_id}")]
pub async fn add_group_role(
    group_store: web::Data<GroupStore>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (group_id, role_id) = path.into_inner();
    if group_store.add_role(&group_id, &role_id) {
        HttpResponse::Ok().body("Role added")
    } else {
        HttpResponse::NotFound().body("Group not found")
    }
}

#[delete("/groups/{id}/roles/{role_id}")]
pub async fn remove_group_role(
    group_store: web::Data<GroupStore>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (group_id, role_id) = path.into_inner();
    if group_store.remove_role(&group_id, &role_id) {
        HttpResponse::Ok().body("Role removed")
    } else {
        HttpResponse::NotFound().body("Group not found")
    }
}
