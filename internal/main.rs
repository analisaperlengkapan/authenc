use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use authence::api;
use authence::services;
// use actix_limitation::{Limiter, MemoryStore, RateLimiter};
use actix_web_prometheus::PrometheusMetricsBuilder;
mod i18n;
mod plugin;
use i18n::I18n;
use std::sync::Arc;

async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    // let store = MemoryStore::new();
    let i18n = Arc::new(I18n::new(&["en-US", "id-ID"], "./i18n"));
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .build()
        .unwrap();

    // Plugin system: load all .so plugins from plugins/ directory
    use plugin::PluginManager;
    use std::fs;
    let mut plugin_manager = PluginManager::new();
    if let Ok(entries) = fs::read_dir("./plugins") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "so" {
                    plugin_manager.load_plugin(path.as_os_str());
                }
            }
        }
    }
    plugin_manager.call_plugin_entries();
    println!("Authence server starting at http://127.0.0.1:8080");
    use crate::services::user_store::UserStore;
    let user_store = web::Data::new(UserStore::new());
    let realm_store = web::Data::new(crate::services::realm_store::RealmStore::new());
    let role_store = web::Data::new(crate::services::role_store::RoleStore::new());
    let permission_store = web::Data::new(crate::services::permission_store::PermissionStore::new());
    let audit_log_store = web::Data::new(crate::services::audit_log_store::AuditLogStore::new());
    HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            // .wrap(
            //     RateLimiter::new(
            //         Limiter::default()
            //             .with_store(store.clone())
            //             .with_interval(std::time::Duration::from_secs(60))
            //             .with_max_requests(5)
            //     )
            //     .for_path("/v1/login")
            // )
            .app_data(user_store.clone())
            .app_data(realm_store.clone())
            .app_data(role_store.clone())
            .app_data(permission_store.clone())
            .app_data(audit_log_store.clone())
            .app_data(web::Data::from(i18n.clone()))
            .service(
                web::scope("/v1")
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
                    .service(api::assign_role)
                    .service(api::unassign_role)
                    .service(api::get_permissions)
                    .service(api::create_permission)
                    .service(api::delete_permission)
                    .service(api::assign_permission_to_role)
                    .service(api::unassign_permission_from_role)
                    .service(api::get_user_permissions)
                    .service(api::check_user_permission)
                    .service(api::add_audit_log)
                    .service(api::get_audit_logs)
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
