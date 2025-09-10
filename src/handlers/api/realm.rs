use actix_web::{get, post, put, delete, web, HttpResponse, Responder};
use crate::services::realm_store::RealmStore;
use crate::models::realm::Realm;
use serde::Deserialize;
use uuid::Uuid;

#[get("/realms")]
pub async fn get_realms(data: web::Data<RealmStore>) -> impl Responder {
    let realms = data.get_all();
    HttpResponse::Ok().json(realms)
}

#[get("/realms/{name}")]
pub async fn get_realm_by_name(data: web::Data<RealmStore>, path: web::Path<String>) -> impl Responder {
    let name = path.into_inner();
    if let Some(realm) = data.get_by_name(&name) {
        HttpResponse::Ok().json(realm)
    } else {
        HttpResponse::NotFound().body("Realm not found")
    }
}

#[derive(Deserialize)]
pub struct CreateRealmRequest {
    pub name: String,
    pub enabled: Option<bool>,
}

#[post("/realms")]
pub async fn create_realm(data: web::Data<RealmStore>, req: web::Json<CreateRealmRequest>) -> impl Responder {
    let realms = data.realms.lock().unwrap();
    if realms.iter().any(|r| r.name == req.name) {
        return HttpResponse::BadRequest().body("Realm already exists");
    }
    drop(realms);
    let realm = Realm {
        id: Uuid::new_v4().to_string(),
        name: req.name.clone(),
        enabled: req.enabled.unwrap_or(true),
    };
    data.add_realm(realm);
    HttpResponse::Created().body("Realm created")
}

#[delete("/realms/{name}")]
pub async fn delete_realm(data: web::Data<RealmStore>, path: web::Path<String>) -> impl Responder {
    let name = path.into_inner();
    let mut realms = data.realms.lock().unwrap();
    let len_before = realms.len();
    realms.retain(|r| r.name != name);
    if realms.len() < len_before {
        HttpResponse::Ok().body("Realm deleted")
    } else {
        HttpResponse::NotFound().body("Realm not found")
    }
}
