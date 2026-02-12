//! SPI-based federation handlers
//!
//! This module provides HTTP handlers for federation capabilities using the SPI architecture.
//! It includes handlers for LDAP federation and social provider authentication.

use crate::app::AppState;
use crate::spi::ldap_federation::LdapFederationProvider;
use crate::spi::social::SocialProvider;
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Create federation routes using SPI providers
pub fn create_federation_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ldap/auth", post(ldap_authenticate))
        .route("/ldap/users", get(ldap_search_users))
        .route("/social/providers", get(list_social_providers))
        .route("/social/auth", post(social_authenticate))
        .route("/social/callback", get(social_callback))
}

/// LDAP authentication request
#[derive(Deserialize)]
pub struct LdapAuthRequest {
    /// Username for LDAP authentication
    pub username: String,
    /// Password for LDAP authentication
    pub password: String,
}

/// LDAP authentication response
#[derive(Serialize)]
pub struct LdapAuthResponse {
    /// Whether authentication was successful
    pub success: bool,
    /// User information if authentication succeeded
    pub user_info: Option<LdapUserInfo>,
    /// Authentication token (JWT) if successful
    pub token: Option<String>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// LDAP user information
#[derive(Serialize)]
pub struct LdapUserInfo {
    /// Username in LDAP
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// First name
    pub first_name: Option<String>,
    /// Last name
    pub last_name: Option<String>,
    /// Groups the user belongs to
    pub groups: Vec<String>,
}

/// LDAP user search request
#[derive(Deserialize)]
pub struct LdapUserSearchRequest {
    /// Search query string
    pub query: String,
    /// Maximum number of results to return
    pub limit: Option<usize>,
}

/// LDAP user search response
#[derive(Serialize)]
pub struct LdapUserSearchResponse {
    /// List of matching users
    pub users: Vec<LdapUserInfo>,
    /// Total number of matching users
    pub total: usize,
}

/// Social provider list response
#[derive(Serialize)]
pub struct SocialProvidersResponse {
    /// List of available social providers
    pub providers: Vec<String>,
}

/// Social authentication request
#[derive(Deserialize)]
pub struct SocialAuthRequest {
    /// Social provider name
    pub provider: String,
    /// Authorization code from provider
    pub code: String,
    /// State parameter for CSRF protection
    pub state: String,
    /// Redirect URI used in the flow
    pub redirect_uri: String,
}

/// Social authentication response
#[derive(Serialize)]
pub struct SocialAuthResponse {
    /// Whether authentication was successful
    pub success: bool,
    /// User information if authentication succeeded
    pub user_info: Option<SocialUserInfo>,
    /// Access token if authentication succeeded
    pub access_token: Option<String>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// Social user information
#[derive(Serialize)]
pub struct SocialUserInfo {
    /// Social provider name
    pub provider: String,
    /// User ID from the social provider
    pub provider_user_id: String,
    /// Email address from social provider
    pub email: Option<String>,
    /// Display name from social provider
    pub name: Option<String>,
    /// Avatar/profile image URL
    pub avatar_url: Option<String>,
}

/// Helper function to construct the social callback URI
fn construct_social_callback_uri(config: &crate::config::AppConfig) -> String {
    format!(
        "{}{}/auth/federation/social/callback",
        config.server.base_url.trim_end_matches('/'),
        config.server.public_prefix.trim_end_matches('/')
    )
}

/// Helper function to convert internal User model to LdapUserInfo
///
/// This function extracts groups from both "groups" and "memberOf" attributes,
/// sorting and deduplicating them.
fn convert_to_ldap_user_info(user: crate::models::User) -> LdapUserInfo {
    // Extract groups from user attributes
    let mut groups = Vec::new();
    if let Some(serde_json::Value::Object(attrs)) = &user.attributes {
        for key in ["groups", "memberOf"] {
            if let Some(val) = attrs.get(key) {
                match val {
                    serde_json::Value::Array(arr) => {
                        groups.extend(
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToString::to_string)),
                        );
                    }
                    serde_json::Value::String(s) => {
                        groups.push(s.clone());
                    }
                    _ => {}
                }
            }
        }

        // Deduplicate groups
        groups.sort();
        groups.dedup();
    }

    LdapUserInfo {
        username: user.username,
        email: Some(user.email),
        first_name: user.first_name,
        last_name: user.last_name,
        groups,
    }
}

/// Logic for processing LDAP authentication and JIT provisioning
pub async fn process_ldap_authentication(
    provider: &dyn LdapFederationProvider,
    state: &AppState,
    request: &LdapAuthRequest,
) -> std::result::Result<Json<LdapAuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Attempt authentication
    match provider
        .authenticate(&request.username, &request.password)
        .await
    {
        Ok(Some(user_info)) => {
            // Convert SPI user info to response format
            let ldap_user_info = convert_to_ldap_user_info(user_info.clone());

            // Perform JIT provisioning
            if let Some(realm_id) = user_info.realm_id {
                // Use a deterministic UUID for the default LDAP SPI provider
                // Using a constant UUID since we don't have v5 feature enabled
                let provider_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

                let jit_request = crate::models::user::JITUserProvisioningRequest {
                    identity_provider_id: provider_id,
                    external_id: user_info.username.clone(), // LDAP uses username/DN as external ID usually
                    external_username: Some(user_info.username.clone()),
                    external_email: Some(user_info.email.clone()),
                    first_name: user_info.first_name.clone(),
                    last_name: user_info.last_name.clone(),
                    external_attributes: user_info.attributes.clone(),
                    realm_id,
                };

                // Provision user
                match state.jit_provisioning_service.provision_user(jit_request).await {
                    Ok(response) => {
                        let user = response.user;

                        // Generate JWT
                        if let Ok(token) = authenc_crypto::utils::crypto::jwt::generate_jwt(&user.id.to_string()) {
                            Ok(Json(LdapAuthResponse {
                                success: true,
                                user_info: Some(ldap_user_info),
                                token: Some(token),
                                error: None,
                            }))
                        } else {
                             Ok(Json(LdapAuthResponse {
                                success: true,
                                user_info: Some(ldap_user_info),
                                token: None,
                                error: Some("Failed to generate token".to_string()),
                            }))
                        }
                    },
                    Err(e) => Ok(Json(LdapAuthResponse {
                        success: false,
                        user_info: None,
                        token: None,
                        error: Some(format!("JIT Provisioning failed: {}", e)),
                    }))
                }
            } else {
                 Ok(Json(LdapAuthResponse {
                    success: false,
                    user_info: None,
                    token: None,
                    error: Some("Realm ID missing in user info".to_string()),
                }))
            }
        }
        Ok(None) => Ok(Json(LdapAuthResponse {
            success: false,
            user_info: None,
            token: None,
            error: Some("Invalid credentials".to_string()),
        })),
        Err(e) => Ok(Json(LdapAuthResponse {
            success: false,
            user_info: None,
            token: None,
            error: Some(format!("Authentication error: {}", e)),
        })),
    }
}

/// LDAP authentication handler using SPI
pub async fn ldap_authenticate(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LdapAuthRequest>,
) -> std::result::Result<Json<LdapAuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get LDAP federation provider from SPI manager
    let spi_manager = &state.spi_manager;
    let provider = match spi_manager
        .registry()
        .get_provider::<crate::spi::ldap_federation::DefaultLdapFederationProvider>(
        "ldap-federation",
    ) {
        Ok(provider) => provider,
        Err(_) => {
            return Ok(Json(LdapAuthResponse {
                success: false,
                user_info: None,
                token: None,
                error: Some("LDAP federation not configured".to_string()),
            }));
        }
    };

    process_ldap_authentication(provider, &state, &request).await
}

/// LDAP user search handler using SPI
pub async fn ldap_search_users(
    State(state): State<Arc<AppState>>,
    Query(request): Query<LdapUserSearchRequest>,
) -> std::result::Result<Json<LdapUserSearchResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get LDAP federation provider from SPI manager
    let spi_manager = &state.spi_manager;
    let provider = match spi_manager
        .registry()
        .get_provider::<crate::spi::ldap_federation::DefaultLdapFederationProvider>(
        "ldap-federation",
    ) {
        Ok(provider) => provider,
        Err(_) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "LDAP federation not configured"})),
            ));
        }
    };

    // Search for users
    let limit = request.limit.unwrap_or(50);
    match provider.search_users(&request.query, limit).await {
        Ok(users) => {
            let users: Vec<LdapUserInfo> =
                users.into_iter().map(convert_to_ldap_user_info).collect();
            let total = users.len();

            Ok(Json(LdapUserSearchResponse { users, total }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Search error: {}", e)})),
        )),
    }
}

/// List available social providers
pub async fn list_social_providers(
    State(state): State<Arc<AppState>>,
) -> std::result::Result<Json<SocialProvidersResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get social providers from SPI manager
    let spi_manager = &state.spi_manager;
    let providers = match spi_manager
        .registry()
        .get_providers::<crate::spi::social::DefaultSocialProvider>("social")
    {
        Ok(providers) => providers,
        Err(_) => {
            return Ok(Json(SocialProvidersResponse { providers: vec![] }));
        }
    };

    // Collect provider types from all configured providers
    let provider_names: Vec<String> = providers
        .iter()
        .map(|p| match p.get_provider_type() {
            crate::spi::social::SocialProviderType::Google => "google".to_string(),
            crate::spi::social::SocialProviderType::Facebook => "facebook".to_string(),
            crate::spi::social::SocialProviderType::Twitter => "twitter".to_string(),
            crate::spi::social::SocialProviderType::GitHub => "github".to_string(),
            crate::spi::social::SocialProviderType::LinkedIn => "linkedin".to_string(),
            crate::spi::social::SocialProviderType::Microsoft => "microsoft".to_string(),
            crate::spi::social::SocialProviderType::Apple => "apple".to_string(),
            crate::spi::social::SocialProviderType::Custom(name) => name,
        })
        .collect();

    Ok(Json(SocialProvidersResponse {
        providers: provider_names,
    }))
}

/// Social authentication handler using SPI
pub async fn social_authenticate(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SocialAuthRequest>,
) -> std::result::Result<Json<SocialAuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get social provider from SPI manager
    let spi_manager = &state.spi_manager;
    let provider = match spi_manager
        .registry()
        .get_provider::<crate::spi::social::DefaultSocialProvider>("social")
    {
        Ok(provider) => provider,
        Err(_) => {
            return Ok(Json(SocialAuthResponse {
                success: false,
                user_info: None,
                access_token: None,
                error: Some("Social provider not configured".to_string()),
            }));
        }
    };

    // Parse provider type
    let _provider_type = match request.provider.as_str() {
        "google" => crate::spi::social::SocialProviderType::Google,
        "facebook" => crate::spi::social::SocialProviderType::Facebook,
        "twitter" => crate::spi::social::SocialProviderType::Twitter,
        "github" => crate::spi::social::SocialProviderType::GitHub,
        "linkedin" => crate::spi::social::SocialProviderType::LinkedIn,
        "microsoft" => crate::spi::social::SocialProviderType::Microsoft,
        "apple" => crate::spi::social::SocialProviderType::Apple,
        _ => {
            return Ok(Json(SocialAuthResponse {
                success: false,
                user_info: None,
                access_token: None,
                error: Some("Unknown provider".to_string()),
            }));
        }
    };

    // Exchange code for token
    match provider
        .exchange_code(&request.code, &request.redirect_uri)
        .await
    {
        Ok(token) => {
            // Get user profile
            match provider.get_user_profile(&token).await {
                Ok(profile) => {
                    let user_info = SocialUserInfo {
                        provider: request.provider,
                        provider_user_id: profile.provider_user_id,
                        email: profile.email,
                        name: profile.display_name,
                        avatar_url: profile.picture_url,
                    };

                    Ok(Json(SocialAuthResponse {
                        success: true,
                        user_info: Some(user_info),
                        access_token: Some(token.access_token),
                        error: None,
                    }))
                }
                Err(e) => Ok(Json(SocialAuthResponse {
                    success: false,
                    user_info: None,
                    access_token: None,
                    error: Some(format!("Failed to get user profile: {}", e)),
                })),
            }
        }
        Err(e) => Ok(Json(SocialAuthResponse {
            success: false,
            user_info: None,
            access_token: None,
            error: Some(format!("Failed to exchange code: {}", e)),
        })),
    }
}

/// Social OAuth callback handler using SPI
pub async fn social_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Json<SocialAuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    let code = match params.get("code") {
        Some(code) => code,
        None => {
            return Ok(Json(SocialAuthResponse {
                success: false,
                user_info: None,
                access_token: None,
                error: Some("No authorization code provided".to_string()),
            }));
        }
    };

    let state_param = match params.get("state") {
        Some(state) => state,
        None => {
            return Ok(Json(SocialAuthResponse {
                success: false,
                user_info: None,
                access_token: None,
                error: Some("No state parameter provided".to_string()),
            }));
        }
    };

    // Parse state to get provider info
    // In a real implementation, you'd decode the state parameter to get provider info
    // For now, assume it's passed as part of the state
    let provider_name = "google"; // This should be extracted from state

    // Construct redirect URI using the configured base URL
    // The path must match the mounted route path for the social callback
    let redirect_uri = construct_social_callback_uri(&state.config);

    let request = SocialAuthRequest {
        provider: provider_name.to_string(),
        code: code.clone(),
        state: state_param.clone(),
        redirect_uri,
    };

    social_authenticate(State(state), Json(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::User;
    use serde_json::json;
    use uuid::Uuid;

    fn create_test_user(attributes: Option<serde_json::Value>) -> User {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            None,
            Some(Uuid::new_v4()),
        );
        user.attributes = attributes;
        user
    }

    #[test]
    fn test_extract_groups_from_groups_attribute() {
        let attributes = json!({
            "groups": ["group1", "group2"]
        });
        let user = create_test_user(Some(attributes));
        let user_info = convert_to_ldap_user_info(user);

        assert_eq!(user_info.groups.len(), 2);
        assert!(user_info.groups.contains(&"group1".to_string()));
        assert!(user_info.groups.contains(&"group2".to_string()));
    }

    #[test]
    fn test_extract_groups_from_memberof_attribute() {
        let attributes = json!({
            "memberOf": ["group3", "group4"]
        });
        let user = create_test_user(Some(attributes));
        let user_info = convert_to_ldap_user_info(user);

        // This should currently fail or return empty if not implemented
        assert_eq!(user_info.groups.len(), 2);
        assert!(user_info.groups.contains(&"group3".to_string()));
        assert!(user_info.groups.contains(&"group4".to_string()));
    }

    #[test]
    fn test_extract_groups_combined() {
        let attributes = json!({
            "groups": ["group1"],
            "memberOf": ["group2"]
        });
        let user = create_test_user(Some(attributes));
        let user_info = convert_to_ldap_user_info(user);

        assert_eq!(user_info.groups.len(), 2);
        assert!(user_info.groups.contains(&"group1".to_string()));
        assert!(user_info.groups.contains(&"group2".to_string()));
    }

    #[test]
    fn test_extract_groups_single_string() {
        let attributes = json!({
            "groups": "group1",
            "memberOf": "group2"
        });
        let user = create_test_user(Some(attributes));
        let user_info = convert_to_ldap_user_info(user);

        assert_eq!(user_info.groups.len(), 2);
        assert!(user_info.groups.contains(&"group1".to_string()));
        assert!(user_info.groups.contains(&"group2".to_string()));
    }

    #[test]
    fn test_extract_groups_no_attributes() {
        let user = create_test_user(None);
        let user_info = convert_to_ldap_user_info(user);

        assert!(user_info.groups.is_empty());
    }

    #[test]
    fn test_extract_groups_missing_keys() {
        let attributes = json!({
            "someOtherKey": "someValue"
        });
        let user = create_test_user(Some(attributes));
        let user_info = convert_to_ldap_user_info(user);

        assert!(user_info.groups.is_empty());
    }

    #[test]
    fn test_social_callback_redirect_uri_construction() {
        use crate::config::AppConfig;

        let mut config = AppConfig::default();
        config.server.base_url = "https://auth.example.com".to_string();
        config.server.public_prefix = "/api/v1".to_string();

        let uri = construct_social_callback_uri(&config);
        assert_eq!(
            uri,
            "https://auth.example.com/api/v1/auth/federation/social/callback"
        );
    }

    #[test]
    fn test_social_callback_redirect_uri_construction_trailing_slashes() {
        use crate::config::AppConfig;

        let mut config = AppConfig::default();
        config.server.base_url = "https://auth.example.com/".to_string();
        config.server.public_prefix = "/api/v1/".to_string();

        let uri = construct_social_callback_uri(&config);
        assert_eq!(
            uri,
            "https://auth.example.com/api/v1/auth/federation/social/callback"
        );
    }
}
