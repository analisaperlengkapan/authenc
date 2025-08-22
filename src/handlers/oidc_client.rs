use crate::models::oidc_client::OidcClient;
use crate::services::oidc_client_store::OidcClientStore;
use actix_web::{delete, get, post, web, HttpResponse, Responder};
use serde::Deserialize;

#[get("/oidc/clients")]
pub async fn list_oidc_clients(store: web::Data<OidcClientStore>) -> impl Responder {
    match store.all() {
        Ok(clients) => HttpResponse::Ok().json(clients),
        Err(e) => HttpResponse::InternalServerError().body(format!("Client store error: {e}")),
    }
}

#[derive(Deserialize)]
pub struct CreateOidcClientRequest {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub name: String,
}

#[post("/oidc/clients")]
pub async fn create_oidc_client(
    store: web::Data<OidcClientStore>,
    req: web::Json<CreateOidcClientRequest>,
) -> impl Responder {
    let client = OidcClient {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: req.client_id.clone(),
        client_secret: req.client_secret.clone(),
        redirect_uris: req.redirect_uris.clone(),
        name: req.name.clone(),
        enabled: true,
    };
    match store.add(client) {
        Ok(_) => HttpResponse::Created().body("OIDC client created"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Client store error: {e}")),
    }
}

#[delete("/oidc/clients/{client_id}")]
pub async fn delete_oidc_client(
    store: web::Data<OidcClientStore>,
    path: web::Path<String>,
) -> impl Responder {
    match store.delete(&path) {
        Ok(true) => HttpResponse::Ok().body("OIDC client deleted"),
        Ok(false) => HttpResponse::NotFound().body("Client not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Client store error: {e}")),
    }
}
