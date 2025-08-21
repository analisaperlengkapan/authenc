use actix_web::{get, post, delete, web, HttpResponse, Responder};
use crate::services::oidc_client_store::OidcClientStore;
use crate::model::oidc_client::OidcClient;
use serde::Deserialize;

#[get("/oidc/clients")]
pub async fn list_oidc_clients(store: web::Data<OidcClientStore>) -> impl Responder {
    let clients = store.all();
    HttpResponse::Ok().json(clients)
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
    store.add(client);
    HttpResponse::Created().body("OIDC client created")
}

#[delete("/oidc/clients/{client_id}")]
pub async fn delete_oidc_client(
    store: web::Data<OidcClientStore>,
    path: web::Path<String>,
) -> impl Responder {
    if store.delete(&path) {
        HttpResponse::Ok().body("OIDC client deleted")
    } else {
        HttpResponse::NotFound().body("Client not found")
    }
}
