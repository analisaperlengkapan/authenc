use crate::app::AppState;
use authenc_database::database::Database;
use authenc_database::database::operations::identity_providers::get_identity_provider_by_entity_id;
use crate::error::AuthencError;
use authenc_models::models::user::JITUserProvisioningRequest;
use authenc_services::services::admin::AdminManager;
use authenc_services::services::federation::jit_provisioning::{
    DefaultJITProvisioningService, JITProvisioningService,
};
use authenc_services::services::protocols::saml::{SamlIdentityProvider, SamlService, SamlServiceProvider};
use axum::{
    Router,
    extract::{Query, State},
    response::{Html, Redirect},
    routing::{get, post},
};
use std::sync::Arc;

/// Escape HTML special characters to prevent XSS when rendering
/// user-controlled data (e.g. SAML assertion values) into HTML responses.
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Create SAML routes
pub fn create_saml_routes() -> Router<Database> {
    Router::new()
        .route("/sp/metadata", get(sp_metadata))
        .route("/idp/metadata", get(idp_metadata))
        .route("/auth", get(saml_auth))
        .route("/acs", post(saml_acs))
        .route("/slo", get(saml_slo))
}

fn get_default_sp_config() -> SamlServiceProvider {
    SamlServiceProvider {
        entity_id: "https://authenc.example.com/saml/sp".to_string(),
        realm_id: uuid::Uuid::nil(),
        assertion_consumer_service_url: "https://authenc.example.com/saml/acs".to_string(),
        single_logout_service_url: Some("https://authenc.example.com/saml/slo".to_string()),
        name_id_format: "urn:oasis:names:tc:SAML:1.0:nameid-format:emailAddress".to_string(),
        want_assertions_signed: true,
        want_response_signed: true,
    }
}

fn get_default_idp_config() -> SamlIdentityProvider {
    SamlIdentityProvider {
        id: uuid::Uuid::nil(),
        entity_id: "https://idp.example.com/saml/idp".to_string(),
        sso_url: "https://idp.example.com/saml/auth".to_string(),
        slo_url: Some("https://idp.example.com/saml/slo".to_string()),
        certificate: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...".to_string(),
        name_id_format: "urn:oasis:names:tc:SAML:1.0:nameid-format:emailAddress".to_string(),
        want_authn_requests_signed: true,
    }
}

/// SAML service provider metadata endpoint
pub async fn sp_metadata(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Html<String>, AuthencError> {
    let mut service = SamlService::new(Arc::new(db));

    let sp = get_default_sp_config();
    service.register_service_provider(sp.clone());

    let default_entity_id = sp.entity_id.clone();
    let entity_id = params.get("entity_id").unwrap_or(&default_entity_id);

    match service.generate_sp_metadata(entity_id) {
        Ok(metadata) => Ok(Html(metadata)),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// SAML identity provider metadata endpoint
pub async fn idp_metadata(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Html<String>, AuthencError> {
    let mut service = SamlService::new(Arc::new(db));

    let mut idp = get_default_idp_config();
    idp.entity_id = "https://authenc.example.com/saml/idp".to_string();
    idp.sso_url = "https://authenc.example.com/saml/auth".to_string();
    idp.slo_url = Some("https://authenc.example.com/saml/slo".to_string());

    service.register_identity_provider(idp.clone());

    let default_entity_id = idp.entity_id.clone();
    let entity_id = params.get("entity_id").unwrap_or(&default_entity_id);

    match service.generate_idp_metadata(entity_id) {
        Ok(metadata) => Ok(Html(metadata)),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// SAML authentication initiation
pub async fn saml_auth(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Redirect, AuthencError> {
    let mut service = SamlService::new(Arc::new(db));

    let sp = get_default_sp_config();
    service.register_service_provider(sp.clone());

    let idp = get_default_idp_config();
    service.register_identity_provider(idp.clone());

    let default_sp_entity_id = sp.entity_id.clone();
    let sp_entity_id = params.get("sp").unwrap_or(&default_sp_entity_id);

    let default_idp_entity_id = idp.entity_id.clone();
    let idp_entity_id = params.get("idp").unwrap_or(&default_idp_entity_id);

    let relay_state = params.get("RelayState").map(|s| s.as_str());

    match service
        .generate_authn_request(sp_entity_id, idp_entity_id, relay_state)
        .await
    {
        Ok(redirect_url) => Ok(Redirect::to(&redirect_url)),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// SAML assertion consumer service (ACS) endpoint
pub async fn saml_acs(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    body: String,
) -> std::result::Result<Html<String>, AuthencError> {
    let mut service = SamlService::new(Arc::new(db.clone()));

    // Parse form-urlencoded POST body (SAML HTTP-POST binding sends
    // SAMLResponse as application/x-www-form-urlencoded in the body).
    let form_params: std::collections::HashMap<String, String> = form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // Try POST body first (standard SAML HTTP-POST binding), then fall
    // back to query parameters (HTTP-Redirect binding or non-standard).
    let saml_response = if let Some(response) = form_params.get("SAMLResponse") {
        response.clone()
    } else if let Some(response) = params.get("SAMLResponse") {
        response.clone()
    } else {
        return Err(AuthencError::validation("Missing SAMLResponse parameter"));
    };

    let relay_state = form_params
        .get("RelayState")
        .or_else(|| params.get("RelayState"))
        .map(|s| s.as_str());

    let (issuer, xml) = service
        .get_issuer_and_xml_from_response(&saml_response)
        .map_err(|e| AuthencError::validation(format!("Failed to parse SAML response: {}", e)))?;

    let idp_data = get_identity_provider_by_entity_id(&db, &issuer)
        .await
        .map_err(|e| AuthencError::internal(format!("Database error: {}", e)))?
        .ok_or_else(|| {
            AuthencError::resource_not_found(format!(
                "Identity Provider not found for issuer: {}",
                issuer
            ))
        })?;

    let idp_config: SamlIdentityProvider = serde_json::from_value(idp_data.config.clone())
        .map_err(|e| {
            AuthencError::internal(format!("Invalid Identity Provider configuration: {}", e))
        })?;

    service.register_identity_provider(idp_config);

    match service
        .process_xml_response(&xml, relay_state, &issuer)
        .await
    {
        Ok(user_info) => {
            let admin_service = Arc::new(AdminManager::new(Arc::new(db.clone())));
            let jit_service = Arc::new(DefaultJITProvisioningService::new(
                Arc::new(db.clone()),
                admin_service,
            ));

            let get_attribute_value = |key: &str| -> Option<String> {
                user_info
                    .attributes
                    .get(key)
                    .and_then(|v| v.first())
                    .cloned()
            };

            log::info!(
                "Preparing JIT provisioning request for IDP: {}",
                idp_data.id
            );
            let jit_request = JITUserProvisioningRequest {
                identity_provider_id: idp_data.id,
                external_id: user_info.name_id.clone(),
                external_username: get_attribute_value("username"),
                external_email: get_attribute_value("email"),
                first_name: get_attribute_value("firstName"),
                last_name: get_attribute_value("lastName"),
                external_attributes: Some(
                    serde_json::to_value(&user_info.attributes)
                        .map_err(|_| AuthencError::internal("Failed to serialize attributes"))?,
                ),
                realm_id: idp_data.realm_id,
            };

            match jit_service.provision_user(jit_request).await {
                Ok(jit_response) => {
                    let html = format!(
                        r#"<!DOCTYPE html>
<html>
<head><title>SAML Login Success</title></head>
<body>
<h1>Login Successful</h1>
<p>Welcome, {}!</p>
<p>User ID: {}</p>
<p>Session Index: {}</p>
<p>Authentication Context: {}</p>
<p>JIT Provisioned: {}</p>
<pre>{}</pre>
</body>
</html>"#,
                        escape_html(&jit_response.user.username),
                        jit_response.user.id,
                        escape_html(&user_info.session_index),
                        escape_html(&user_info.authn_context_class_ref),
                        jit_response.created,
                        escape_html(&format!("{:?}", user_info.attributes))
                    );
                    Ok(Html(html))
                }
                Err(e) => {
                    let html = format!(
                        r#"<!DOCTYPE html>
<html>
<head><title>SAML Login Failed</title></head>
<body>
<h1>JIT Provisioning Failed</h1>
<p>Error: {}</p>
</body>
</html>"#,
                        escape_html(&e.to_string())
                    );
                    Ok(Html(html))
                }
            }
        }
        Err(_) => {
            let html = r#"<!DOCTYPE html>
<html>
<head><title>SAML Login Failed</title></head>
<body>
<h1>Login Failed</h1>
<p>SAML authentication failed. Please try again.</p>
</body>
</html>"#;
            Ok(Html(html.to_string()))
        }
    }
}

/// SAML single logout endpoint
pub async fn saml_slo(
    State(_db): State<Database>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Redirect, AuthencError> {
    Ok(Redirect::to("/"))
}

