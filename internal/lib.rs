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
	let group_store = web::Data::new(services::group_store::GroupStore::new());
	let totp_store = web::Data::new(services::totp_store::TotpStore::new());
	let session_store = web::Data::new(services::session_store::SessionStore::new());
	let brute_force = web::Data::new(services::brute_force_protector::BruteForceProtector::new(5, 300)); // 5 attempts per 5 minutes
	let anomaly_detector = web::Data::new(services::anomaly_detector::AnomalyDetector::new());
	let oidc_code_store = web::Data::new(services::oidc_code_store::OidcCodeStore::new(600)); // 10 min TTL
	let oidc_client_store = web::Data::new(services::oidc_client_store::OidcClientStore::new());
	let mut federation_registry = services::federation_provider::FederationRegistry::new();
	federation_registry.register(Box::new(services::federation_provider::DummyFederationProvider));
	let federation_registry = web::Data::new(federation_registry);
	use std::sync::Arc;
	use api::auth_middleware::AuthMiddleware;
	let auth_middleware = AuthMiddleware { session_store: Arc::clone(&session_store) };
	HttpServer::new(move || {
		App::new()
			.wrap(prometheus.clone())
			.app_data(user_store.clone())
			.app_data(realm_store.clone())
			.app_data(role_store.clone())
			.app_data(permission_store.clone())
			.app_data(audit_log_store.clone())
			.app_data(group_store.clone())
			.app_data(totp_store.clone())
		.app_data(session_store.clone())
	.app_data(brute_force.clone())
	.app_data(anomaly_detector.clone())
	.app_data(web::Data::from(i18n.clone()))
	.app_data(oidc_code_store.clone())
	.app_data(oidc_client_store.clone())
		.app_data(federation_registry.clone())
			.service(
				web::scope("/v1")
					.route("/health", web::get().to(health))
					.service(api::auth::login)
					.service(api::create_user)
					// OIDC endpoints
					.service(api::oidc_discovery)
					.service(api::oidc_authorize)
					.service(api::oidc_token)
					.service(api::oidc_userinfo)
					.service(api::oidc_jwks)
					// OIDC client admin endpoints
					.service(api::list_oidc_clients)
					.service(api::create_oidc_client)
					.service(api::delete_oidc_client)
					// Protected endpoints
					.wrap(auth_middleware.clone())
					.service(api::user::get_users)
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
					// Group endpoints
					.service(api::group::create_group)
					.service(api::group::get_groups)
					.service(api::group::get_group_by_id)
					.service(api::group::delete_group)
					.service(api::group::add_group_member)
					.service(api::group::remove_group_member)
					.service(api::group::add_group_role)
					.service(api::group::remove_group_role)
					// TOTP endpoints
					.service(api::totp::enable_totp)
					.service(api::totp::disable_totp)
					.service(api::totp_verify::verify_totp)
					// Session endpoints
					.service(api::session::list_sessions)
					.service(api::session::logout)
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
