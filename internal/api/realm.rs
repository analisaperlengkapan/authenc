use actix_web::{get, post, delete, web, HttpResponse, Responder};

#[get("/realms")]
pub async fn get_realms() -> impl Responder {
    HttpResponse::Ok().body("get_realms")
}

#[get("/realms/{name}")]
pub async fn get_realm_by_name() -> impl Responder {
    HttpResponse::Ok().body("get_realm_by_name")
}

#[post("/realms")]
pub async fn create_realm() -> impl Responder {
    HttpResponse::Ok().body("create_realm")
}

#[delete("/realms/{name}")]
pub async fn delete_realm() -> impl Responder {
    HttpResponse::Ok().body("delete_realm")
}
