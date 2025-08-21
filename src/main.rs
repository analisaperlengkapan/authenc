
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use authence::api;
use authence::services;

async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    println!("Authence server starting at http://127.0.0.1:8080");
    use services::user_store::UserStore;
    let user_store = web::Data::new(UserStore::new());
    let realm_store = web::Data::new(services::realm_store::RealmStore::new());
    let role_store = web::Data::new(services::role_store::RoleStore::new());
    let permission_store = web::Data::new(services::permission_store::PermissionStore::new());
    let audit_log_store = web::Data::new(services::audit_log_store::AuditLogStore::new());
    HttpServer::new(move || {
        App::new()
            .app_data(user_store.clone())
            .app_data(realm_store.clone())
            .app_data(role_store.clone())
            .app_data(permission_store.clone())
            .app_data(audit_log_store.clone())
            .route("/health", web::get().to(health))
            .service(api::auth::login)
            .service(api::user::get_users)
            .service(api::create_user)
            .service(api::get_user_by_id)
            .service(api::update_user)
            .service(api::delete_user)
            .service(api::update_password)
            .service(api::get_realms)
            .service(api::get_realm_by_name)
            .service(api::create_realm)
            .service(api::delete_realm)
            .service(api::get_roles)
            .service(api::create_role)
            .service(api::delete_role)
            .service(api::assign_permission_to_role)
            .service(api::unassign_permission_from_role)
            .service(api::get_user_permissions)
            .service(api::check_user_permission)
            .service(api::add_audit_log)
            .service(api::get_audit_logs)
            .service(api::assign_role)
            .service(api::unassign_role)
            .service(api::get_permissions)
            .service(api::create_permission)
            .service(api::delete_permission)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
