use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use actix_web_prometheus::PrometheusMetricsBuilder;
use std::sync::Arc;
mod i18n;
mod plugin;

async fn health() -> impl Responder {
	HttpResponse::Ok().body("OK")
}

pub async fn run_server() -> std::io::Result<()> {
	env_logger::init();
	let i18n = Arc::new(i18n::I18n::new(&["en-US", "id-ID"], "./i18n"));
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
	use services::user_store::UserStore;
	let user_store = web::Data::new(UserStore::new());
	let realm_store = web::Data::new(services::realm_store::RealmStore::new());
	let role_store = web::Data::new(services::role_store::RoleStore::new());
	let permission_store = web::Data::new(services::permission_store::PermissionStore::new());
	let audit_log_store = web::Data::new(services::audit_log_store::AuditLogStore::new());
	HttpServer::new(move || {
		App::new()
			.wrap(prometheus.clone())
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
pub mod core;
pub mod api;
pub mod model;
pub mod crypto;
pub mod services;
pub mod integration;
