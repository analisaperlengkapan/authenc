use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::database::Database;

// SAML and OIDC provider implementations
/// OIDC identity provider implementation
pub mod oidc;
/// SAML identity provider implementation
pub mod saml;
/// SAML security utilities
pub mod saml_security;

use oidc::OidcIdentityProvider;
use saml::SamlIdentityProvider;

/// Identity provider types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityProviderType {
    /// SAML 2.0 identity provider
    SAML,
    /// OpenID Connect identity provider
    OIDC,
    /// OAuth 2.0 identity provider
    OAuth2,
    /// LDAP directory server
    LDAP,
    /// Kerberos authentication
    Kerberos,
    /// Social login providers
    SocialLogin,
    /// Custom identity provider
    Custom,
}

/// Identity provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    /// Unique identifier for the identity provider
    pub id: Uuid,
    /// Internal name of the provider
    pub name: String,
    /// Display name shown to users
    pub display_name: String,
    /// Type of identity provider
    pub provider_type: IdentityProviderType,
    /// Whether the provider is enabled
    pub enabled: bool,
    /// Configuration parameters specific to the provider
    pub config: HashMap<String, String>,
    /// ID of the realm this provider belongs to
    pub realm_id: Uuid,
    /// Path to truststore for SSL/TLS certificates
    pub truststore_path: Option<String>,
    /// Path to keystore for client certificates
    pub keystore_path: Option<String>,
}

/// Identity provider interface
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Authenticate a user with the identity provider
    async fn authenticate(&self, request: &AuthRequest) -> Result<AuthResponse>;
    /// Get user information from the provider
    async fn get_user_info(&self, token: &str) -> Result<UserInfo>;
    /// Validate an authentication token
    async fn validate_token(&self, token: &str) -> Result<bool>;
    /// Logout user from the provider
    async fn logout(&self, token: &str) -> Result<()>;
}

/// Authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Username for authentication
    pub username: Option<String>,
    /// Password for authentication
    pub password: Option<String>,
    /// SAML assertion for SAML authentication
    pub saml_assertion: Option<String>,
    /// OIDC authorization code
    pub oidc_code: Option<String>,
    /// OAuth access token
    pub oauth_token: Option<String>,
    /// Kerberos ticket for authentication
    pub kerberos_ticket: Option<String>,
    /// Social login provider name
    pub social_provider: Option<String>,
    /// Social login access token
    pub social_token: Option<String>,
    /// Relay state for SAML/OIDC flows
    pub relay_state: Option<String>,
    /// Additional authentication parameters
    pub parameters: HashMap<String, String>,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Whether authentication was successful
    pub success: bool,
    /// User ID if authentication succeeded
    pub user_id: Option<String>,
    /// Username if authentication succeeded
    pub username: Option<String>,
    /// Email address of the user
    pub email: Option<String>,
    /// Groups the user belongs to
    pub groups: Vec<String>,
    /// Roles assigned to the user
    pub roles: Vec<String>,
    /// User attributes from the identity provider
    pub attributes: HashMap<String, String>,
    /// Authentication token for the user
    pub token: Option<String>,
    /// Refresh token if applicable
    pub refresh_token: Option<String>,
    /// Token expiration time
    pub expires_at: Option<u64>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// User information from identity provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Unique identifier from the identity provider
    pub id: String,
    /// Username from the identity provider
    pub username: Option<String>,
    /// Email address from the identity provider
    pub email: Option<String>,
    /// First name from the identity provider
    pub first_name: Option<String>,
    /// Last name from the identity provider
    pub last_name: Option<String>,
    /// Groups the user belongs to
    pub groups: Vec<String>,
    /// Roles assigned to the user
    pub roles: Vec<String>,
    /// Additional user attributes
    pub attributes: HashMap<String, String>,
}

/// JIT User Provisioning Service
/// Handles Just-In-Time user provisioning from external identity providers
pub mod jit_provisioning {
    use crate::{
        database::Database,
        error::Result,
        models::user::{
            CreateFederatedIdentityRequest, FederatedIdentity, JITUserProvisioningRequest,
            JITUserProvisioningResponse, User,
        },
        services::admin::AdminService,
    };
    use async_trait::async_trait;
    use std::sync::Arc;
    use uuid::Uuid;

    /// JIT Provisioning Service trait
    #[async_trait]
    pub trait JITProvisioningService: Send + Sync {
        /// Provision or find user based on external identity provider data
        async fn provision_user(
            &self,
            request: JITUserProvisioningRequest,
        ) -> Result<JITUserProvisioningResponse>;

        /// Link existing user to external identity provider
        async fn link_user(
            &self,
            user_id: Uuid,
            identity_provider_id: Uuid,
            external_id: String,
            external_attributes: Option<serde_json::Value>,
        ) -> Result<FederatedIdentity>;

        /// Unlink user from external identity provider
        async fn unlink_user(&self, user_id: Uuid, identity_provider_id: Uuid) -> Result<()>;
    }

    /// Default implementation of JIT Provisioning Service
    pub struct DefaultJITProvisioningService {
        db: Arc<Database>,
        _admin_service: Arc<dyn AdminService>,
    }

    impl DefaultJITProvisioningService {
        /// Create a new JIT provisioning service
        pub fn new(db: Arc<Database>, admin_service: Arc<dyn AdminService>) -> Self {
            Self {
                db,
                _admin_service: admin_service,
            }
        }
    }

    #[async_trait]
    impl JITProvisioningService for DefaultJITProvisioningService {
        async fn provision_user(
            &self,
            request: JITUserProvisioningRequest,
        ) -> Result<JITUserProvisioningResponse> {
            use crate::database::operations::{federated_identities, users};

            // First, check if a federated identity already exists
            if let Some(existing_federated) =
                federated_identities::get_federated_identity_by_external_id(
                    &self.db,
                    request.identity_provider_id,
                    &request.external_id,
                )
                .await?
            {
                // User already exists, get the user details
                let user = users::get_user_by_id(&self.db, existing_federated.user_id)
                    .await?
                    .ok_or(crate::error::AuthencError::AuthenticationFailed)?;

                // Update last login time
                federated_identities::update_last_login(&self.db, existing_federated.id).await?;

                return Ok(JITUserProvisioningResponse {
                    user,
                    created: false,
                    federated_identity: existing_federated,
                });
            }

            // Check if user exists by email (for account linking)
            let existing_user = if let Some(email) = &request.external_email {
                users::get_user_by_email(&self.db, email).await?
            } else {
                None
            };

            let (user, created) = if let Some(existing_user) = existing_user {
                // Use existing user
                (existing_user, false)
            } else {
                // Create new user
                (self.create_federated_user(&request).await?, true)
            };

            // Create federated identity link
            let federated_identity = self.create_federated_identity_link(&user, &request).await?;

            Ok(JITUserProvisioningResponse {
                user,
                created,
                federated_identity,
            })
        }

        async fn link_user(
            &self,
            user_id: Uuid,
            identity_provider_id: Uuid,
            external_id: String,
            external_attributes: Option<serde_json::Value>,
        ) -> Result<FederatedIdentity> {
            use crate::database::operations::federated_identities;

            // Check if link already exists
            if let Some(existing) = federated_identities::get_federated_identity_by_external_id(
                &self.db,
                identity_provider_id,
                &external_id,
            )
            .await?
            {
                return Ok(existing);
            }

            // Create new federated identity link
            let request = CreateFederatedIdentityRequest {
                user_id,
                identity_provider_id,
                external_id,
                external_username: None,
                external_email: None,
                external_attributes,
            };

            federated_identities::create_federated_identity(&self.db, &request).await
        }

        async fn unlink_user(&self, user_id: Uuid, identity_provider_id: Uuid) -> Result<()> {
            use crate::database::operations::federated_identities;

            // Find the federated identity
            let identities =
                federated_identities::get_federated_identities_by_user(&self.db, user_id).await?;
            for identity in identities {
                if identity.identity_provider_id == identity_provider_id {
                    federated_identities::delete_federated_identity(&self.db, identity.id).await?;
                    break;
                }
            }

            Ok(())
        }
    }

    impl DefaultJITProvisioningService {
        /// Create a new user from federated identity provider data
        async fn create_federated_user(
            &self,
            request: &JITUserProvisioningRequest,
        ) -> Result<User> {
            use crate::database::operations::users;
            use crate::models::user::CreateUserRequest;

            // Generate username from external data
            let username = self.generate_username(request).await?;

            // Create user request
            let create_request = CreateUserRequest {
                username: username.clone(),
                email: request
                    .external_email
                    .clone()
                    .unwrap_or_else(|| format!("{}@federated.local", username)),
                password: None, // No password for federated users
                first_name: request.first_name.clone(),
                last_name: request.last_name.clone(),
                phone_number: None,
                attributes: request.external_attributes.clone(),
                realm_id: Some(request.realm_id),
                organization_id: None,
            };

            users::create_user(&self.db, &create_request).await
        }

        /// Create federated identity link
        async fn create_federated_identity_link(
            &self,
            user: &User,
            request: &JITUserProvisioningRequest,
        ) -> Result<FederatedIdentity> {
            use crate::database::operations::federated_identities;

            let create_request = CreateFederatedIdentityRequest {
                user_id: user.id,
                identity_provider_id: request.identity_provider_id,
                external_id: request.external_id.clone(),
                external_username: request.external_username.clone(),
                external_email: request.external_email.clone(),
                external_attributes: request.external_attributes.clone(),
            };

            federated_identities::create_federated_identity(&self.db, &create_request).await
        }

        /// Generate a unique username for federated user
        async fn generate_username(&self, request: &JITUserProvisioningRequest) -> Result<String> {
            use crate::database::operations::users;

            // Try external username first
            if let Some(username) = &request.external_username {
                if users::get_user_by_username(&self.db, username)
                    .await?
                    .is_none()
                {
                    return Ok(username.clone());
                }
            }

            // Try email prefix
            if let Some(email) = &request.external_email {
                let email_prefix = email.split('@').next().unwrap_or("user");
                let mut candidate = email_prefix.to_string();
                let mut counter = 1;

                while users::get_user_by_username(&self.db, &candidate)
                    .await?
                    .is_some()
                {
                    candidate = format!("{}{}", email_prefix, counter);
                    counter += 1;
                }

                return Ok(candidate);
            }

            // Fallback to external ID
            let mut candidate = format!(
                "fed_{}",
                &request.external_id[..8.min(request.external_id.len())]
            );
            let mut counter = 1;

            while users::get_user_by_username(&self.db, &candidate)
                .await?
                .is_some()
            {
                candidate = format!(
                    "fed_{}_{}",
                    &request.external_id[..8.min(request.external_id.len())],
                    counter
                );
                counter += 1;
            }

            Ok(candidate)
        }
    }
}

// SAML and OIDC implementations moved to separate modules (saml.rs and oidc.rs)

/// Federation service - main service
pub struct FederationService {
    /// Registered identity providers
    providers: HashMap<Uuid, Box<dyn IdentityProvider>>,
    /// Provider configurations
    provider_configs: HashMap<Uuid, IdentityProviderConfig>,
    /// Database connection for SAML assertion cache
    db: Arc<Database>,
}

impl FederationService {
    /// Create new federation service
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            providers: HashMap::new(),
            provider_configs: HashMap::new(),
            db,
        }
    }

    /// Register identity provider
    pub async fn register_provider(&mut self, config: IdentityProviderConfig) -> Result<()> {
        let provider: Box<dyn IdentityProvider> = match config.provider_type {
            IdentityProviderType::SAML => Box::new(SamlIdentityProvider::new(
                config.clone(),
                Arc::clone(&self.db),
            )?),
            IdentityProviderType::OIDC => {
                Box::new(OidcIdentityProvider::new(config.clone()).await?)
            }
            _ => return Err(anyhow::anyhow!("Unsupported provider type")),
        };

        self.providers.insert(config.id, provider);
        self.provider_configs.insert(config.id, config);
        Ok(())
    }

    /// Authenticate user with specific provider
    pub async fn authenticate(
        &self,
        provider_id: &Uuid,
        request: &AuthRequest,
    ) -> Result<AuthResponse> {
        if let Some(provider) = self.providers.get(provider_id) {
            provider.authenticate(request).await
        } else {
            Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("Identity provider not found".to_string()),
            })
        }
    }

    /// Get all registered providers
    pub fn get_providers(&self) -> Vec<&IdentityProviderConfig> {
        self.provider_configs.values().collect()
    }
}

/// Federation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Whether federation is enabled
    pub enabled: bool,
    /// List of configured identity providers
    pub providers: Vec<IdentityProviderConfig>,
    /// Default identity provider ID
    pub default_provider: Option<Uuid>,
    /// Allow multiple providers per user
    pub allow_multiple_providers: bool,
    /// Enable automatic provider discovery
    pub auto_discovery: bool,
}
