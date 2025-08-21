use actix_web::{get, post, delete, web, HttpResponse, Responder};

#[get("/permissions")]
pub async fn get_permissions() -> impl Responder {
    HttpResponse::Ok().body("get_permissions")
}

#[post("/permissions")]
pub async fn create_permission() -> impl Responder {
    HttpResponse::Ok().body("create_permission")
}

#[delete("/permissions/{id}")]
pub async fn delete_permission() -> impl Responder {
    HttpResponse::Ok().body("delete_permission")
}

#[post("/roles/{role_id}/permissions/{perm_id}/assign")]
pub async fn assign_permission_to_role() -> impl Responder {
    HttpResponse::Ok().body("assign_permission_to_role")
}

#[post("/roles/{role_id}/permissions/{perm_id}/unassign")]
pub async fn unassign_permission_from_role() -> impl Responder {
    HttpResponse::Ok().body("unassign_permission_from_role")
}

#[get("/users/{user_id}/permissions")]
pub async fn get_user_permissions() -> impl Responder {
    HttpResponse::Ok().body("get_user_permissions")
}

#[get("/users/{user_id}/permissions/check")]
pub async fn check_user_permission() -> impl Responder {
    HttpResponse::Ok().body("check_user_permission")
}
