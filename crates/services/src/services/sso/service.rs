//! SSO Service - Unified Single Sign-On orchestration
//!
//! Integrates multiple authentication protocols (OIDC, OAuth2, SAML, Social)
//! under a unified SSO experience.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use authenc_db::database::Database;
use authenc_api::error::{AuthencError, Result};
use authenc_api::models::realm::Realm;

use super::cookie::SsoCookieManager;
use super::session::{SsoSession, SsoSessionManager};

/// SSO Provider type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SsoProvider {
    /// OpenID Connect
    Oidc,
    /// OAuth 2.0
    OAuth2,
    /// SAML 2.0
    Saml,
    /// Social login (Google, Facebook, etc.)
    Social,
}

impl SsoProvider {
    /// Convert to string
    pub fn as_str(&self) -> &str {
        match self {
            SsoProvider::Oidc => "oidc",
            SsoProvider::OAuth2 => "oauth2",
            SsoProvider::Saml => "saml",
            SsoProvider::Social => "social",
        }
    }
}

/// SSO Initiation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoInitiateRequest {
    /// Realm identifier
    pub realm_id: String,
    /// Provider type
    pub provider: SsoProvider,
    /// Client identifier
    pub client_id: String,
    /// Redirect URI after authentication
    pub redirect_uri: String,
    /// Additional parameters
    pub parameters: HashMap<String, String>,
}

/// SSO Callback request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoCallbackRequest {
    /// Realm identifier
    pub realm_id: String,
    /// Provider type
    pub provider: SsoProvider,
    /// Authorization code or token
    pub code: String,
    /// State parameter
    pub state: String,
    /// Additional parameters
    pub parameters: HashMap<String, String>,
}

/// SSO Callback response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoCallbackResponse {
    /// SSO session created
    pub session: SsoSession,
    /// SSO cookie value
    pub cookie_value: String,
    /// Set-Cookie header value
    pub set_cookie_header: String,
    /// Redirect URI
    pub redirect_uri: String,
}

/// SSO Logout request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoLogoutRequest {
    /// SSO session identifier
    pub session_id: String,
    /// Post-logout redirect URI
    pub redirect_uri: Option<String>,
}

/// SSO Service trait
#[async_trait]
pub trait SsoService: Send + Sync {
    /// Initiate SSO login flow
    async fn initiate_login(&self, request: SsoInitiateRequest) -> Result<String>;

    /// Handle SSO callback
    async fn handle_callback(&self, request: SsoCallbackRequest) -> Result<SsoCallbackResponse>;

    /// Validate SSO session from cookie
    async fn validate_session(&self, cookie_value: &str) -> Result<SsoSession>;

    /// Logout from SSO session (Single Logout)
    async fn logout(&self, request: SsoLogoutRequest) -> Result<String>;

    /// Refresh SSO session
    async fn refresh_session(&self, session_id: &str) -> Result<SsoSession>;

    /// Get active sessions for user
    async fn get_user_sessions(&self, user_id: &str, realm_id: &str) -> Result<Vec<SsoSession>>;
}

/// Default SSO Service implementation
pub struct DefaultSsoService {
    session_manager: Arc<dyn SsoSessionManager>,
    cookie_manager: Arc<SsoCookieManager>,
    database: Arc<Database>,
}

impl DefaultSsoService {
    /// Create a new default SSO service
    pub fn new(
        session_manager: Arc<dyn SsoSessionManager>,
        cookie_manager: Arc<SsoCookieManager>,
        database: Arc<Database>,
    ) -> Self {
        Self {
            session_manager,
            cookie_manager,
            database,
        }
    }

    /// Get realm configuration
    async fn get_realm(&self, realm_id: &str) -> Result<Realm> {
        // Fetch realm from database
        let query = "SELECT * FROM realms WHERE id = $1 AND deleted_at IS NULL";
        let realm: Realm = self
            .database
            .query_one(query, &[&uuid::Uuid::parse_str(realm_id).unwrap()])
            .await
            .map_err(|e| AuthencError::internal(format!("Failed to fetch realm: {}", e)))?;

        Ok(realm)
    }

    /// Generate authorization URL for provider
    fn generate_auth_url(
        &self,
        provider: &SsoProvider,
        request: &SsoInitiateRequest,
    ) -> Result<String> {
        // This would integrate with actual protocol handlers
        // For now, return a placeholder URL
        let base_url = match provider {
            SsoProvider::Oidc => format!("/oidc/{}/authorize", request.realm_id),
            SsoProvider::OAuth2 => format!("/oauth2/{}/authorize", request.realm_id),
            SsoProvider::Saml => format!("/saml/{}/sso", request.realm_id),
            SsoProvider::Social => format!("/social/{}/login", request.realm_id),
        };

        let mut url = url::Url::parse(&format!("https://auth.example.com{}", base_url))
            .map_err(|e| AuthencError::internal(format!("Invalid URL: {}", e)))?;

        url.query_pairs_mut()
            .append_pair("client_id", &request.client_id)
            .append_pair("redirect_uri", &request.redirect_uri);

        for (key, value) in &request.parameters {
            url.query_pairs_mut().append_pair(key, value);
        }

        Ok(url.to_string())
    }
}

#[async_trait]
impl SsoService for DefaultSsoService {
    async fn initiate_login(&self, request: SsoInitiateRequest) -> Result<String> {
        // Validate realm exists
        let _realm = self.get_realm(&request.realm_id).await?;

        // Generate authorization URL for the requested provider
        let auth_url = self.generate_auth_url(&request.provider, &request)?;

        Ok(auth_url)
    }

    async fn handle_callback(&self, request: SsoCallbackRequest) -> Result<SsoCallbackResponse> {
        // Fetch realm configuration
        let realm = self.get_realm(&request.realm_id).await?;

        // In a real implementation, this would:
        // 1. Validate the authorization code with the provider
        // 2. Exchange code for tokens
        // 3. Fetch user information
        // 4. Create or update user in database
        // 5. Create SSO session

        // For now, simulate successful authentication
        let user_id = format!("user-{}", uuid::Uuid::new_v4());

        // Determine session timeouts based on realm configuration
        let idle_timeout = realm.sso_session_idle_timeout;
        let max_lifespan = realm.sso_session_max_lifespan;

        // Create SSO session
        let session = self
            .session_manager
            .create_session(
                &user_id,
                &request.realm_id,
                request.provider.as_str(),
                idle_timeout,
                max_lifespan,
                false, // remember_me would come from request
                None,  // ip_address would come from HTTP request
                None,  // user_agent would come from HTTP request
            )
            .await?;

        // Generate SSO cookie
        let cookie_value = self.cookie_manager.generate_cookie(
            &session.session_id,
            &user_id,
            &request.realm_id,
            max_lifespan as i64,
        )?;

        // Generate Set-Cookie header
        let set_cookie_header = self
            .cookie_manager
            .generate_set_cookie_header(&cookie_value, max_lifespan as i64);

        // Extract redirect URI from parameters or use default
        let redirect_uri = request
            .parameters
            .get("redirect_uri")
            .cloned()
            .unwrap_or_else(|| "/".to_string());

        Ok(SsoCallbackResponse {
            session,
            cookie_value,
            set_cookie_header,
            redirect_uri,
        })
    }

    async fn validate_session(&self, cookie_value: &str) -> Result<SsoSession> {
        // Validate and parse cookie
        let cookie_data = self.cookie_manager.validate_cookie(cookie_value)?;

        // Get session from session manager
        let session = self
            .session_manager
            .get_session(&cookie_data.session_id)
            .await?
            .ok_or_else(|| AuthencError::unauthorized("Session not found"))?;

        // Check if session is expired
        if self.session_manager.is_expired(&session.session_id).await? {
            return Err(AuthencError::unauthorized("Session expired"));
        }

        // Update last access time
        self.session_manager
            .update_access(&session.session_id)
            .await?;

        Ok(session)
    }

    async fn logout(&self, request: SsoLogoutRequest) -> Result<String> {
        // Invalidate SSO session
        self.session_manager
            .invalidate_session(&request.session_id)
            .await?;

        // Return redirect URI
        Ok(request.redirect_uri.unwrap_or_else(|| "/".to_string()))
    }

    async fn refresh_session(&self, session_id: &str) -> Result<SsoSession> {
        // Get current session
        let _session = self
            .session_manager
            .get_session(session_id)
            .await?
            .ok_or_else(|| AuthencError::unauthorized("Session not found"))?;

        // Check if expired
        if self.session_manager.is_expired(session_id).await? {
            return Err(AuthencError::unauthorized("Session expired"));
        }

        // Update last access
        self.session_manager.update_access(session_id).await?;

        // Return refreshed session
        self.session_manager
            .get_session(session_id)
            .await?
            .ok_or_else(|| AuthencError::internal("Session disappeared after refresh"))
    }

    async fn get_user_sessions(&self, user_id: &str, realm_id: &str) -> Result<Vec<SsoSession>> {
        self.session_manager
            .get_user_sessions(user_id, realm_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::sso::session::DefaultSsoSessionManager;

    #[tokio::test]
    async fn test_sso_cookie_integration() {
        let session_manager = Arc::new(DefaultSsoSessionManager::new());
        let secret = b"test-secret-key-at-least-32-bytes-long!!";
        let cookie_manager = Arc::new(SsoCookieManager::new(secret, "AUTHENC_SSO", None, true));

        // Create mock database (in real code, use actual database)
        // For testing, we'll skip database operations

        // This test demonstrates the flow without database dependency
        let session = session_manager
            .create_session(
                "user123", "realm456", "oidc", 1800, 36000, false, None, None,
            )
            .await
            .unwrap();

        let cookie_value = cookie_manager
            .generate_cookie(&session.session_id, "user123", "realm456", 36000)
            .unwrap();

        let cookie_data = cookie_manager.validate_cookie(&cookie_value).unwrap();

        assert_eq!(cookie_data.session_id, session.session_id);
        assert_eq!(cookie_data.user_id, "user123");
    }
}
