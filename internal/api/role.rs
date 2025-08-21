use actix_web::{get, post, delete, web, HttpResponse, Responder};

#[get("/roles")]
pub async fn get_roles() -> impl Responder {
    HttpResponse::Ok().body("get_roles")
}

#[post("/roles")]
pub async fn create_role() -> impl Responder {
    HttpResponse::Ok().body("create_role")
}

#[delete("/roles/{id}")]
pub async fn delete_role() -> impl Responder {
    HttpResponse::Ok().body("delete_role")
}

#[post("/roles/{id}/assign")]
pub async fn assign_role() -> impl Responder {
    HttpResponse::Ok().body("assign_role")
}

#[post("/roles/{id}/unassign")]
pub async fn unassign_role() -> impl Responder {
    HttpResponse::Ok().body("unassign_role")
}
