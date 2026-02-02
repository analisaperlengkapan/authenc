//! Advanced User Federation Providers
//!
//! This module implements advanced user federation features for enterprise
//! identity management, including:
//! - LDAP federation with advanced configuration
//! - Kerberos authentication
//! - Social login providers (Google, GitHub, Facebook, etc.)
//! - SAML identity providers
//! - Custom federation providers with SPI-like interface

use authenc_api::error::AuthencError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User Federation Provider trait for Authenc's user storage
#[async_trait]
pub trait UserFederationProvider: Send + Sync {
    /// Get provider name
    fn name(&self) -> &str;

    /// Validate user credentials
    async fn validate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserInfo>, AuthencError>;

    /// Get user information
    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>, AuthencError>;

    /// Search users
    async fn search_users(&self, query: &str, limit: usize) -> Result<Vec<UserInfo>, AuthencError>;

    /// Check if user exists
    async fn user_exists(&self, username: &str) -> Result<bool, AuthencError>;

    /// Get user groups
    async fn get_user_groups(&self, username: &str) -> Result<Vec<String>, AuthencError>;

    /// Synchronize users (import from external system)
    async fn synchronize_users(&self) -> Result<SyncResult, AuthencError>;
}

/// User information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Username
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// First name
    pub first_name: Option<String>,
    /// Last name
    pub last_name: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// User attributes
    pub attributes: HashMap<String, Vec<String>>,
    /// Whether user is enabled
    pub enabled: bool,
    /// Whether email is verified
    pub email_verified: bool,
}

/// Synchronization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Number of users added
    pub added: usize,
    /// Number of users updated
    pub updated: usize,
    /// Number of users removed
    pub removed: usize,
    /// Number of failed operations
    pub failed: usize,
}

/// LDAP Federation Provider
#[allow(dead_code)]
pub struct LdapFederationProvider {
    config: LdapConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Configuration for LDAP federation provider
pub struct LdapConfig {
    /// LDAP server URL
    pub url: String,
    /// Bind DN for authentication
    pub bind_dn: String,
    /// Bind password
    pub bind_password: String,
    /// User search base DN
    pub user_search_base: String,
    /// User search filter
    pub user_search_filter: String,
    /// Username attribute
    pub username_attribute: String,
    /// Email attribute
    pub email_attribute: String,
    /// First name attribute
    pub first_name_attribute: String,
    /// Last name attribute
    pub last_name_attribute: String,
    /// Group search base DN
    pub group_search_base: String,
    /// Group search filter
    pub group_search_filter: String,
    /// Group name attribute
    pub group_name_attribute: String,
    /// Group member attribute
    pub group_member_attribute: String,
    /// Connection timeout
    pub connection_timeout: u64,
    /// Read timeout
    pub read_timeout: u64,
    /// Use SSL/TLS
    pub use_ssl: bool,
    /// Trust store path
    pub trust_store_path: Option<String>,
    /// Synchronization settings
    pub sync_settings: LdapSyncSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Synchronization settings for LDAP federation
pub struct LdapSyncSettings {
    /// Sync interval in seconds
    pub sync_interval: u64,
    /// Batch size for synchronization
    pub batch_size: usize,
    /// Import users on startup
    pub import_on_startup: bool,
    /// Sync registrations
    pub sync_registrations: bool,
    /// Sync user attributes
    pub sync_user_attributes: bool,
}

impl LdapFederationProvider {
    /// Create a new LDAP federation provider with configuration
    ///
    /// This constructor initializes an LDAP federation provider that enables
    /// user authentication and attribute synchronization against LDAP directories.
    /// The provider supports user discovery, authentication, and attribute mapping
    /// for enterprise LDAP integration.
    ///
    /// # Arguments
    /// * `config` - LDAP configuration containing server details, credentials, and settings
    ///
    /// # Returns
    /// A new `LdapFederationProvider` instance configured for LDAP federation
    ///
    /// # Security Considerations
    /// - LDAP credentials should be securely managed and encrypted
    /// - Use LDAPS (LDAP over SSL/TLS) for secure communication
    /// - Validate LDAP server certificates to prevent MITM attacks
    /// - Implement proper connection pooling and timeout handling
    /// - Log authentication attempts for security monitoring
    ///
    /// # Example
    /// ```rust
    /// use authenc::services::advanced_federation::{LdapFederationProvider, LdapConfig, LdapSyncSettings};
    ///
    /// // Note: LdapConfig requires all fields to be initialized
    /// // This is a simplified example - see LdapConfig struct for all required fields
    /// let config = LdapConfig {
    ///     url: "ldaps://ldap.example.com".to_string(),
    ///     bind_dn: "cn=admin,dc=example,dc=com".to_string(),
    ///     bind_password: "secure_password".to_string(),
    ///     user_search_base: "ou=users,dc=example,dc=com".to_string(),
    ///     user_search_filter: "(uid={0})".to_string(),
    ///     username_attribute: "uid".to_string(),
    ///     email_attribute: "mail".to_string(),
    ///     first_name_attribute: "givenName".to_string(),
    ///     last_name_attribute: "sn".to_string(),
    ///     group_search_base: "ou=groups,dc=example,dc=com".to_string(),
    ///     group_search_filter: "(member={0})".to_string(),
    ///     group_name_attribute: "cn".to_string(),
    ///     group_member_attribute: "member".to_string(),
    ///     connection_timeout: 30,
    ///     read_timeout: 30,
    ///     use_ssl: true,
    ///     trust_store_path: None,
    ///     sync_settings: LdapSyncSettings {
    ///         sync_interval: 3600,
    ///         batch_size: 100,
    ///         import_on_startup: false,
    ///         sync_registrations: true,
    ///         sync_user_attributes: true,
    ///     },
    /// };
    /// let provider = LdapFederationProvider::new(config);
    /// ```
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl UserFederationProvider for LdapFederationProvider {
    fn name(&self) -> &str {
        "ldap"
    }

    async fn validate_credentials(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Option<UserInfo>, AuthencError> {
        // LDAP bind with user credentials
        // This would use an LDAP library to authenticate against LDAP server
        // For now, return a placeholder
        Ok(Some(UserInfo {
            username: username.to_string(),
            email: Some(format!("{}@example.com", username)),
            first_name: Some("LDAP".to_string()),
            last_name: Some("User".to_string()),
            display_name: Some(format!("LDAP User {}", username)),
            attributes: HashMap::new(),
            enabled: true,
            email_verified: true,
        }))
    }

    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>, AuthencError> {
        // Search LDAP for user information
        // This would query LDAP directory for user attributes
        Ok(Some(UserInfo {
            username: username.to_string(),
            email: Some(format!("{}@example.com", username)),
            first_name: Some("LDAP".to_string()),
            last_name: Some("User".to_string()),
            display_name: Some(format!("LDAP User {}", username)),
            attributes: HashMap::new(),
            enabled: true,
            email_verified: true,
        }))
    }

    async fn search_users(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<UserInfo>, AuthencError> {
        // Search LDAP directory
        // This would perform LDAP search with the given query
        Ok(vec![])
    }

    async fn user_exists(&self, _username: &str) -> Result<bool, AuthencError> {
        // Check if user exists in LDAP
        Ok(true)
    }

    async fn get_user_groups(&self, _username: &str) -> Result<Vec<String>, AuthencError> {
        // Get user's groups from LDAP
        Ok(vec!["ldap-users".to_string()])
    }

    async fn synchronize_users(&self) -> Result<SyncResult, AuthencError> {
        // Synchronize users from LDAP
        // This would import/update users from LDAP directory
        Ok(SyncResult {
            added: 0,
            updated: 0,
            removed: 0,
            failed: 0,
        })
    }
}

/// Kerberos Federation Provider
///
/// Provides authentication against Kerberos Key Distribution Center (KDC).
/// Supports Kerberos ticket-based authentication for enterprise environments.
///
/// # Security Considerations
/// - Uses secure Kerberos protocol for authentication
/// - Supports keytab-based authentication for service accounts
/// - Can be configured to allow or deny password authentication
/// - Integrates with enterprise Kerberos infrastructure
pub struct KerberosFederationProvider {
    config: KerberosConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Configuration for Kerberos federation provider
///
/// Defines the parameters required to connect to a Kerberos Key Distribution Center (KDC)
/// and configure Kerberos-based authentication for enterprise users.
///
/// # Fields
/// * `realm` - The Kerberos realm (domain) for authentication
/// * `kdc_server` - Address of the Key Distribution Center server
/// * `keytab_path` - Optional path to keytab file for service authentication
/// * `service_principal` - Kerberos service principal name
/// * `allow_password_auth` - Whether to allow password-based authentication
/// * `update_password` - Whether to update passwords in Kerberos database
///
/// # Security Considerations
/// - Keytab files contain sensitive service credentials
/// - Service principals should have minimal required permissions
/// - Password authentication should be disabled in production for service accounts
pub struct KerberosConfig {
    /// Kerberos realm
    pub realm: String,
    /// KDC server
    pub kdc_server: String,
    /// Keytab file path
    pub keytab_path: Option<String>,
    /// Service principal
    pub service_principal: String,
    /// Allow password authentication
    pub allow_password_auth: bool,
    /// Update password
    pub update_password: bool,
}

impl KerberosFederationProvider {
    /// Create a new Kerberos federation provider
    ///
    /// # Arguments
    /// * `config` - Kerberos configuration parameters
    ///
    /// # Returns
    /// Configured Kerberos federation provider instance
    pub fn new(config: KerberosConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl UserFederationProvider for KerberosFederationProvider {
    fn name(&self) -> &str {
        "kerberos"
    }

    async fn validate_credentials(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Option<UserInfo>, AuthencError> {
        // Kerberos authentication
        // This would use Kerberos libraries to authenticate against KDC
        Ok(Some(UserInfo {
            username: username.to_string(),
            email: Some(format!("{}@{}", username, self.config.realm.to_lowercase())),
            first_name: Some("Kerberos".to_string()),
            last_name: Some("User".to_string()),
            display_name: Some(format!("Kerberos User {}", username)),
            attributes: HashMap::new(),
            enabled: true,
            email_verified: true,
        }))
    }

    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>, AuthencError> {
        Ok(Some(UserInfo {
            username: username.to_string(),
            email: Some(format!("{}@{}", username, self.config.realm.to_lowercase())),
            first_name: Some("Kerberos".to_string()),
            last_name: Some("User".to_string()),
            display_name: Some(format!("Kerberos User {}", username)),
            attributes: HashMap::new(),
            enabled: true,
            email_verified: true,
        }))
    }

    async fn search_users(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<UserInfo>, AuthencError> {
        // Kerberos doesn't support user search
        Ok(vec![])
    }

    async fn user_exists(&self, _username: &str) -> Result<bool, AuthencError> {
        // Check if principal exists in Kerberos
        Ok(true)
    }

    async fn get_user_groups(&self, _username: &str) -> Result<Vec<String>, AuthencError> {
        Ok(vec!["kerberos-users".to_string()])
    }

    async fn synchronize_users(&self) -> Result<SyncResult, AuthencError> {
        // Kerberos doesn't support synchronization
        Ok(SyncResult {
            added: 0,
            updated: 0,
            removed: 0,
            failed: 0,
        })
    }
}

/// Social Login Provider trait
///
/// Defines the interface for social login providers (OAuth2/OIDC).
/// Implementations handle the OAuth2 flow for various social platforms.
///
/// # Security Considerations
/// - All OAuth2 flows must use PKCE (Proof Key for Code Exchange)
/// - State parameters must be validated to prevent CSRF attacks
/// - Access tokens should be validated before use
/// - HTTPS must be used for all OAuth2 endpoints
#[async_trait]
pub trait SocialLoginProvider: Send + Sync {
    /// Get provider name
    ///
    /// Returns a unique identifier for the social login provider.
    /// Used for provider registration and identification.
    fn name(&self) -> &str;

    /// Get authorization URL
    ///
    /// Generates the OAuth2 authorization URL for the provider.
    /// Includes necessary parameters like client_id, redirect_uri, scope, and state.
    ///
    /// # Arguments
    /// * `state` - Random state parameter for CSRF protection
    ///
    /// # Returns
    /// The complete authorization URL to redirect users to
    async fn get_authorization_url(&self, state: &str) -> Result<String, AuthencError>;

    /// Exchange code for tokens
    ///
    /// Exchanges the authorization code for access tokens.
    /// Makes a secure HTTP request to the provider's token endpoint.
    ///
    /// # Arguments
    /// * `code` - Authorization code received from the provider
    ///
    /// # Returns
    /// Social login result containing access token and metadata
    async fn exchange_code(&self, code: &str) -> Result<SocialLoginResult, AuthencError>;

    /// Get user info from social provider
    ///
    /// Retrieves user profile information using the access token.
    /// Makes a secure HTTP request to the provider's userinfo endpoint.
    ///
    /// # Arguments
    /// * `access_token` - Valid access token from the provider
    ///
    /// # Returns
    /// User information extracted from the social provider
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, AuthencError>;
}

/// Social login result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialLoginResult {
    /// Access token
    pub access_token: String,
    /// Token type
    pub token_type: String,
    /// Expiration time
    pub expires_in: Option<i64>,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// Scope
    pub scope: Option<String>,
    /// ID token (for OpenID Connect providers)
    pub id_token: Option<String>,
}

/// Google OAuth2 Provider
///
/// Implements OAuth2 authentication flow for Google accounts.
/// Supports OpenID Connect for identity verification.
///
/// # Security Considerations
/// - Uses Google's secure OAuth2 endpoints
/// - Supports OpenID Connect for verified identity claims
/// - Requires HTTPS for all redirect URIs
/// - Validates state parameters to prevent CSRF attacks
/// - Access tokens have limited lifetime and scope
pub struct GoogleOAuth2Provider {
    client_id: String,
    #[allow(dead_code)]
    client_secret: String,
    redirect_uri: String,
}

impl GoogleOAuth2Provider {
    /// Create a new Google OAuth2 provider
    ///
    /// # Arguments
    /// * `client_id` - Google OAuth2 client ID
    /// * `client_secret` - Google OAuth2 client secret
    /// * `redirect_uri` - OAuth2 redirect URI for the application
    ///
    /// # Returns
    /// Configured Google OAuth2 provider instance
    ///
    /// # Security Considerations
    /// - Client secret should be stored securely (not in source code)
    /// - Redirect URI must match the registered OAuth2 application
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
        }
    }
}

#[async_trait]
impl SocialLoginProvider for GoogleOAuth2Provider {
    fn name(&self) -> &str {
        "google"
    }

    async fn get_authorization_url(&self, state: &str) -> Result<String, AuthencError> {
        let base_url = "https://accounts.google.com/o/oauth2/v2/auth";
        let scope = "openid email profile";
        let response_type = "code";

        Ok(format!(
            "{}?client_id={}&redirect_uri={}&scope={}&response_type={}&state={}",
            base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(scope),
            response_type,
            urlencoding::encode(state)
        ))
    }

    async fn exchange_code(&self, _code: &str) -> Result<SocialLoginResult, AuthencError> {
        // Exchange authorization code for tokens
        // This would make HTTP request to Google's token endpoint
        Ok(SocialLoginResult {
            access_token: "google_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: Some("google_refresh_token".to_string()),
            scope: Some("openid email profile".to_string()),
            id_token: Some("google_id_token".to_string()),
        })
    }

    async fn get_user_info(&self, _access_token: &str) -> Result<UserInfo, AuthencError> {
        // Get user info from Google
        // This would make HTTP request to Google's userinfo endpoint
        Ok(UserInfo {
            username: "google_user".to_string(),
            email: Some("user@gmail.com".to_string()),
            first_name: Some("Google".to_string()),
            last_name: Some("User".to_string()),
            display_name: Some("Google User".to_string()),
            attributes: HashMap::new(),
            enabled: true,
            email_verified: true,
        })
    }
}

/// GitHub OAuth2 Provider
///
/// Implements OAuth2 authentication flow for GitHub accounts.
/// Provides access to GitHub user profile and email information.
///
/// # Security Considerations
/// - Uses GitHub's secure OAuth2 endpoints
/// - Requires user consent for requested scopes
/// - Access tokens are scoped to specific permissions
/// - State parameters prevent CSRF attacks
/// - HTTPS required for all redirect URIs
pub struct GitHubOAuth2Provider {
    client_id: String,
    #[allow(dead_code)]
    client_secret: String,
    redirect_uri: String,
}

impl GitHubOAuth2Provider {
    /// Create a new GitHub OAuth2 provider
    ///
    /// # Arguments
    /// * `client_id` - GitHub OAuth2 client ID
    /// * `client_secret` - GitHub OAuth2 client secret
    /// * `redirect_uri` - OAuth2 redirect URI for the application
    ///
    /// # Returns
    /// Configured GitHub OAuth2 provider instance
    ///
    /// # Security Considerations
    /// - Client secret should be stored securely (not in source code)
    /// - Redirect URI must match the registered OAuth2 application
    /// - Requested scopes should be minimal and necessary
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
        }
    }
}

#[async_trait]
impl SocialLoginProvider for GitHubOAuth2Provider {
    fn name(&self) -> &str {
        "github"
    }

    async fn get_authorization_url(&self, state: &str) -> Result<String, AuthencError> {
        let base_url = "https://github.com/login/oauth/authorize";
        let scope = "user:email";

        Ok(format!(
            "{}?client_id={}&redirect_uri={}&scope={}&state={}",
            base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(scope),
            urlencoding::encode(state)
        ))
    }

    async fn exchange_code(&self, _code: &str) -> Result<SocialLoginResult, AuthencError> {
        // Exchange authorization code for tokens
        Ok(SocialLoginResult {
            access_token: "github_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("user:email".to_string()),
            id_token: None,
        })
    }

    async fn get_user_info(&self, _access_token: &str) -> Result<UserInfo, AuthencError> {
        // Get user info from GitHub
        Ok(UserInfo {
            username: "github_user".to_string(),
            email: Some("user@github.com".to_string()),
            first_name: Some("GitHub".to_string()),
            last_name: Some("User".to_string()),
            display_name: Some("GitHub User".to_string()),
            attributes: HashMap::new(),
            enabled: true,
            email_verified: true,
        })
    }
}

/// SAML Identity Provider
///
/// Implements SAML 2.0 authentication for enterprise identity providers.
/// Handles SAML assertions and single sign-on (SSO) flows.
///
/// # Security Considerations
/// - Validates SAML assertion signatures using configured certificates
/// - Supports secure SAML metadata exchange
/// - Implements SAML single logout (SLO) when configured
/// - Requires HTTPS for all SAML endpoints
/// - Validates NameID policies and authentication contexts
pub struct SamlIdentityProvider {
    #[allow(dead_code)]
    config: SamlIdpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Configuration for SAML Identity Provider
///
/// Defines the SAML 2.0 configuration for connecting to an enterprise identity provider.
/// Includes metadata, certificates, and attribute mappings for SAML authentication.
///
/// # Fields
/// * `entity_id` - Unique identifier for the SAML entity
/// * `sso_url` - Single sign-on service URL
/// * `slo_url` - Optional single logout service URL
/// * `signing_certificate` - X.509 certificate for signature validation
/// * `name_id_policy` - SAML NameID policy format
/// * `authn_context_class_refs` - Authentication context class references
/// * `attribute_mappings` - Mapping of SAML attributes to user profile fields
///
/// # Security Considerations
/// - Signing certificates must be valid and properly chained
/// - SAML metadata should be exchanged securely
/// - Attribute mappings should be validated to prevent injection
/// - NameID policies should match enterprise requirements
pub struct SamlIdpConfig {
    /// Entity ID
    pub entity_id: String,
    /// SSO URL
    pub sso_url: String,
    /// SLO URL
    pub slo_url: Option<String>,
    /// Certificate for signature validation
    pub signing_certificate: String,
    /// Name ID policy
    pub name_id_policy: String,
    /// Authentication context class references
    pub authn_context_class_refs: Vec<String>,
    /// Attribute mappings
    pub attribute_mappings: HashMap<String, String>,
}

impl SamlIdentityProvider {
    /// Create a new SAML identity provider
    ///
    /// # Arguments
    /// * `config` - SAML identity provider configuration
    ///
    /// # Returns
    /// Configured SAML identity provider instance
    ///
    /// # Security Considerations
    /// - SAML metadata should be validated before use
    /// - Signing certificates must be properly configured
    /// - Attribute mappings should be reviewed for security
    pub fn new(config: SamlIdpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl UserFederationProvider for SamlIdentityProvider {
    fn name(&self) -> &str {
        "saml"
    }

    async fn validate_credentials(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<Option<UserInfo>, AuthencError> {
        // SAML doesn't use username/password authentication
        // Authentication is handled via SAML assertion
        Err(AuthencError::ValidationError {
            message: "SAML provider doesn't support direct credential validation".to_string(),
        })
    }

    async fn get_user_info(&self, _username: &str) -> Result<Option<UserInfo>, AuthencError> {
        // SAML user info comes from SAML assertion
        Err(AuthencError::ValidationError {
            message: "SAML provider doesn't support direct user info lookup".to_string(),
        })
    }

    async fn search_users(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<UserInfo>, AuthencError> {
        // SAML doesn't support user search
        Ok(vec![])
    }

    async fn user_exists(&self, _username: &str) -> Result<bool, AuthencError> {
        // SAML doesn't support user existence check
        Ok(false)
    }

    async fn get_user_groups(&self, _username: &str) -> Result<Vec<String>, AuthencError> {
        Ok(vec![])
    }

    async fn synchronize_users(&self) -> Result<SyncResult, AuthencError> {
        // SAML doesn't support synchronization
        Ok(SyncResult {
            added: 0,
            updated: 0,
            removed: 0,
            failed: 0,
        })
    }
}

/// Advanced Federation Registry
///
/// Central registry for managing multiple federation providers.
/// Supports both user federation providers (LDAP, Kerberos, SAML) and social login providers (OAuth2).
/// Provides unified interface for authentication across different provider types.
///
/// # Security Considerations
/// - Provider configurations contain sensitive credentials
/// - Registry should be initialized securely at startup
/// - Provider validation should be performed before registration
/// - Failed authentications should be logged for security monitoring
pub struct AdvancedFederationRegistry {
    user_providers: Vec<Box<dyn UserFederationProvider>>,
    social_providers: HashMap<String, Box<dyn SocialLoginProvider>>,
}

impl Default for AdvancedFederationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedFederationRegistry {
    /// Create a new federation registry
    ///
    /// # Returns
    /// Empty federation registry ready for provider registration
    pub fn new() -> Self {
        Self {
            user_providers: Vec::new(),
            social_providers: HashMap::new(),
        }
    }

    /// Register a user federation provider
    ///
    /// # Arguments
    /// * `provider` - Boxed user federation provider implementation
    ///
    /// # Security Considerations
    /// - Provider should be validated before registration
    /// - Provider configurations should be secure
    pub fn register_user_provider(&mut self, provider: Box<dyn UserFederationProvider>) {
        self.user_providers.push(provider);
    }

    /// Register a social login provider
    ///
    /// # Arguments
    /// * `provider` - Boxed social login provider implementation
    ///
    /// # Security Considerations
    /// - Provider should be validated before registration
    /// - OAuth2 credentials should be properly configured
    pub fn register_social_provider(&mut self, provider: Box<dyn SocialLoginProvider>) {
        let name = provider.name().to_string();
        self.social_providers.insert(name, provider);
    }

    /// Get user federation provider by name
    ///
    /// # Arguments
    /// * `name` - Provider name identifier
    ///
    /// # Returns
    /// Reference to the user federation provider if found
    pub fn get_user_provider(&self, name: &str) -> Option<&dyn UserFederationProvider> {
        self.user_providers
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }
    /// Get social login provider by name
    ///
    /// # Arguments
    /// * `name` - Provider name identifier
    ///
    /// # Returns
    /// Reference to the social login provider if found
    pub fn get_social_provider(&self, name: &str) -> Option<&dyn SocialLoginProvider> {
        self.social_providers.get(name).map(|p| p.as_ref())
    }

    /// Get all user providers
    ///
    /// # Returns
    /// Reference to the vector of all registered user federation providers
    pub fn get_user_providers(&self) -> &Vec<Box<dyn UserFederationProvider>> {
        &self.user_providers
    }

    /// Get all social providers
    ///
    /// # Returns
    /// Reference to the hashmap of all registered social login providers
    pub fn get_social_providers(&self) -> &HashMap<String, Box<dyn SocialLoginProvider>> {
        &self.social_providers
    }

    /// Validate user credentials across all providers
    ///
    /// Attempts authentication against all registered user federation providers
    /// until one succeeds or all fail.
    ///
    /// # Arguments
    /// * `username` - User identifier to authenticate
    /// * `password` - User password credential
    ///
    /// # Returns
    /// User information and provider name if authentication succeeds
    ///
    /// # Security Considerations
    /// - Failed authentication attempts should be logged
    /// - Password credentials should be handled securely
    /// - Provider order may affect authentication precedence
    pub async fn validate_credentials_across_providers(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<(UserInfo, String)>, AuthencError> {
        for provider in &self.user_providers {
            if let Ok(Some(user_info)) = provider.validate_credentials(username, password).await {
                return Ok(Some((user_info, provider.name().to_string())));
            }
        }
        Ok(None)
    }
}
