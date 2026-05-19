use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User event types - comprehensive set for enterprise identity management
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    // Authentication events
    /// Successful user login event
    Login,
    /// Failed user login attempt
    LoginError,
    /// Successful user logout event
    Logout,
    /// Failed user logout attempt
    LogoutError,
    /// Successful code to token exchange
    CodeToToken,
    /// Failed code to token exchange
    CodeToTokenError,
    /// Successful client login event
    ClientLogin,
    /// Failed client login attempt
    ClientLoginError,
    /// Successful token refresh
    RefreshToken,
    /// Failed token refresh attempt
    RefreshTokenError,
    /// Successful token introspection
    IntrospectToken,
    /// Failed token introspection attempt
    IntrospectTokenError,

    // User management events
    /// Successful user registration
    Register,
    /// Failed user registration attempt
    RegisterError,
    /// Successful profile update
    UpdateProfile,
    /// Failed profile update attempt
    UpdateProfileError,
    /// Successful email update
    UpdateEmail,
    /// Failed email update attempt
    UpdateEmailError,
    /// Successful email verification
    VerifyEmail,
    /// Failed email verification attempt
    VerifyEmailError,
    /// Successful profile verification
    VerifyProfile,
    /// Failed profile verification attempt
    VerifyProfileError,
    /// Successful verification email sent
    SendVerifyEmail,
    /// Failed to send verification email
    SendVerifyEmailError,
    /// Successful reset password email sent
    SendResetPassword,
    /// Failed to send reset password email
    SendResetPasswordError,
    /// Successful password reset
    ResetPassword,
    /// Failed password reset attempt
    ResetPasswordError,

    // Credential events
    /// Successful credential update
    UpdateCredential,
    /// Failed credential update attempt
    UpdateCredentialError,
    /// Successful credential removal
    RemoveCredential,
    /// Failed credential removal attempt
    RemoveCredentialError,

    // Federation events
    /// Successful federated identity link
    FederatedIdentityLink,
    /// Failed federated identity link attempt
    FederatedIdentityLinkError,
    /// Successful federated identity removal
    RemoveFederatedIdentity,
    /// Failed federated identity removal attempt
    RemoveFederatedIdentityError,
    /// Successful federated identity override link
    FederatedIdentityOverrideLink,
    /// Failed federated identity override link attempt
    FederatedIdentityOverrideLinkError,

    // Consent events
    /// Successful consent grant
    GrantConsent,
    /// Failed consent grant attempt
    GrantConsentError,
    /// Successful consent update
    UpdateConsent,
    /// Failed consent update attempt
    UpdateConsentError,
    /// Successful grant revocation
    RevokeGrant,
    /// Failed grant revocation attempt
    RevokeGrantError,

    // OAuth2 extension events
    /// Successful OAuth2 extension grant
    Oauth2ExtensionGrant,
    /// Failed OAuth2 extension grant attempt
    Oauth2ExtensionGrantError,

    // Security events
    /// User disabled by permanent lockout
    UserDisabledByPermanentLockout,
    /// Error in disabling user by permanent lockout
    UserDisabledByPermanentLockoutError,
    /// User disabled by temporary lockout
    UserDisabledByTemporaryLockout,
    /// Error in disabling user by temporary lockout
    UserDisabledByTemporaryLockoutError,

    // Organization events
    /// Successful organization invitation
    InviteOrg,
    /// Failed organization invitation attempt
    InviteOrgError,
}

impl EventType {
    /// Check if this event should be saved by default
    pub fn is_save_by_default(&self) -> bool {
        match self {
            // Authentication events - save by default
            EventType::Login
            | EventType::Logout
            | EventType::Register
            | EventType::UpdateProfile
            | EventType::UpdateEmail
            | EventType::VerifyEmail
            | EventType::VerifyProfile
            | EventType::ResetPassword
            | EventType::GrantConsent
            | EventType::RevokeGrant
            | EventType::FederatedIdentityLink
            | EventType::RemoveFederatedIdentity
            | EventType::UpdateCredential
            | EventType::RemoveCredential
            | EventType::UserDisabledByPermanentLockout
            | EventType::UserDisabledByTemporaryLockout
            | EventType::InviteOrg => true,

            // Error events - don't save by default to reduce noise
            _ => false,
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Login => "LOGIN",
            EventType::LoginError => "LOGIN_ERROR",
            EventType::Logout => "LOGOUT",
            EventType::LogoutError => "LOGOUT_ERROR",
            EventType::CodeToToken => "CODE_TO_TOKEN",
            EventType::CodeToTokenError => "CODE_TO_TOKEN_ERROR",
            EventType::ClientLogin => "CLIENT_LOGIN",
            EventType::ClientLoginError => "CLIENT_LOGIN_ERROR",
            EventType::RefreshToken => "REFRESH_TOKEN",
            EventType::RefreshTokenError => "REFRESH_TOKEN_ERROR",
            EventType::IntrospectToken => "INTROSPECT_TOKEN",
            EventType::IntrospectTokenError => "INTROSPECT_TOKEN_ERROR",
            EventType::Register => "REGISTER",
            EventType::RegisterError => "REGISTER_ERROR",
            EventType::UpdateProfile => "UPDATE_PROFILE",
            EventType::UpdateProfileError => "UPDATE_PROFILE_ERROR",
            EventType::UpdateEmail => "UPDATE_EMAIL",
            EventType::UpdateEmailError => "UPDATE_EMAIL_ERROR",
            EventType::VerifyEmail => "VERIFY_EMAIL",
            EventType::VerifyEmailError => "VERIFY_EMAIL_ERROR",
            EventType::VerifyProfile => "VERIFY_PROFILE",
            EventType::VerifyProfileError => "VERIFY_PROFILE_ERROR",
            EventType::SendVerifyEmail => "SEND_VERIFY_EMAIL",
            EventType::SendVerifyEmailError => "SEND_VERIFY_EMAIL_ERROR",
            EventType::SendResetPassword => "SEND_RESET_PASSWORD",
            EventType::SendResetPasswordError => "SEND_RESET_PASSWORD_ERROR",
            EventType::ResetPassword => "RESET_PASSWORD",
            EventType::ResetPasswordError => "RESET_PASSWORD_ERROR",
            EventType::UpdateCredential => "UPDATE_CREDENTIAL",
            EventType::UpdateCredentialError => "UPDATE_CREDENTIAL_ERROR",
            EventType::RemoveCredential => "REMOVE_CREDENTIAL",
            EventType::RemoveCredentialError => "REMOVE_CREDENTIAL_ERROR",
            EventType::FederatedIdentityLink => "FEDERATED_IDENTITY_LINK",
            EventType::FederatedIdentityLinkError => "FEDERATED_IDENTITY_LINK_ERROR",
            EventType::RemoveFederatedIdentity => "REMOVE_FEDERATED_IDENTITY",
            EventType::RemoveFederatedIdentityError => "REMOVE_FEDERATED_IDENTITY_ERROR",
            EventType::FederatedIdentityOverrideLink => "FEDERATED_IDENTITY_OVERRIDE_LINK",
            EventType::FederatedIdentityOverrideLinkError => {
                "FEDERATED_IDENTITY_OVERRIDE_LINK_ERROR"
            }
            EventType::GrantConsent => "GRANT_CONSENT",
            EventType::GrantConsentError => "GRANT_CONSENT_ERROR",
            EventType::UpdateConsent => "UPDATE_CONSENT",
            EventType::UpdateConsentError => "UPDATE_CONSENT_ERROR",
            EventType::RevokeGrant => "REVOKE_GRANT",
            EventType::RevokeGrantError => "REVOKE_GRANT_ERROR",
            EventType::Oauth2ExtensionGrant => "OAUTH2_EXTENSION_GRANT",
            EventType::Oauth2ExtensionGrantError => "OAUTH2_EXTENSION_GRANT_ERROR",
            EventType::UserDisabledByPermanentLockout => "USER_DISABLED_BY_PERMANENT_LOCKOUT",
            EventType::UserDisabledByPermanentLockoutError => {
                "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR"
            }
            EventType::UserDisabledByTemporaryLockout => "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
            EventType::UserDisabledByTemporaryLockoutError => {
                "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR"
            }
            EventType::InviteOrg => "INVITE_ORG",
            EventType::InviteOrgError => "INVITE_ORG_ERROR",
        }
    }

    /// Convert string to EventType
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "LOGIN" => Some(EventType::Login),
            "LOGIN_ERROR" => Some(EventType::LoginError),
            "LOGOUT" => Some(EventType::Logout),
            "LOGOUT_ERROR" => Some(EventType::LogoutError),
            "CODE_TO_TOKEN" => Some(EventType::CodeToToken),
            "CODE_TO_TOKEN_ERROR" => Some(EventType::CodeToTokenError),
            "CLIENT_LOGIN" => Some(EventType::ClientLogin),
            "CLIENT_LOGIN_ERROR" => Some(EventType::ClientLoginError),
            "REFRESH_TOKEN" => Some(EventType::RefreshToken),
            "REFRESH_TOKEN_ERROR" => Some(EventType::RefreshTokenError),
            "INTROSPECT_TOKEN" => Some(EventType::IntrospectToken),
            "INTROSPECT_TOKEN_ERROR" => Some(EventType::IntrospectTokenError),
            "REGISTER" => Some(EventType::Register),
            "REGISTER_ERROR" => Some(EventType::RegisterError),
            "UPDATE_PROFILE" => Some(EventType::UpdateProfile),
            "UPDATE_PROFILE_ERROR" => Some(EventType::UpdateProfileError),
            "UPDATE_EMAIL" => Some(EventType::UpdateEmail),
            "UPDATE_EMAIL_ERROR" => Some(EventType::UpdateEmailError),
            "VERIFY_EMAIL" => Some(EventType::VerifyEmail),
            "VERIFY_EMAIL_ERROR" => Some(EventType::VerifyEmailError),
            "VERIFY_PROFILE" => Some(EventType::VerifyProfile),
            "VERIFY_PROFILE_ERROR" => Some(EventType::VerifyProfileError),
            "SEND_VERIFY_EMAIL" => Some(EventType::SendVerifyEmail),
            "SEND_VERIFY_EMAIL_ERROR" => Some(EventType::SendVerifyEmailError),
            "SEND_RESET_PASSWORD" => Some(EventType::SendResetPassword),
            "SEND_RESET_PASSWORD_ERROR" => Some(EventType::SendResetPasswordError),
            "RESET_PASSWORD" => Some(EventType::ResetPassword),
            "RESET_PASSWORD_ERROR" => Some(EventType::ResetPasswordError),
            "UPDATE_CREDENTIAL" => Some(EventType::UpdateCredential),
            "UPDATE_CREDENTIAL_ERROR" => Some(EventType::UpdateCredentialError),
            "REMOVE_CREDENTIAL" => Some(EventType::RemoveCredential),
            "REMOVE_CREDENTIAL_ERROR" => Some(EventType::RemoveCredentialError),
            "FEDERATED_IDENTITY_LINK" => Some(EventType::FederatedIdentityLink),
            "FEDERATED_IDENTITY_LINK_ERROR" => Some(EventType::FederatedIdentityLinkError),
            "REMOVE_FEDERATED_IDENTITY" => Some(EventType::RemoveFederatedIdentity),
            "REMOVE_FEDERATED_IDENTITY_ERROR" => Some(EventType::RemoveFederatedIdentityError),
            "FEDERATED_IDENTITY_OVERRIDE_LINK" => Some(EventType::FederatedIdentityOverrideLink),
            "FEDERATED_IDENTITY_OVERRIDE_LINK_ERROR" => {
                Some(EventType::FederatedIdentityOverrideLinkError)
            }
            "GRANT_CONSENT" => Some(EventType::GrantConsent),
            "GRANT_CONSENT_ERROR" => Some(EventType::GrantConsentError),
            "UPDATE_CONSENT" => Some(EventType::UpdateConsent),
            "UPDATE_CONSENT_ERROR" => Some(EventType::UpdateConsentError),
            "REVOKE_GRANT" => Some(EventType::RevokeGrant),
            "REVOKE_GRANT_ERROR" => Some(EventType::RevokeGrantError),
            "OAUTH2_EXTENSION_GRANT" => Some(EventType::Oauth2ExtensionGrant),
            "OAUTH2_EXTENSION_GRANT_ERROR" => Some(EventType::Oauth2ExtensionGrantError),
            "USER_DISABLED_BY_PERMANENT_LOCKOUT" => Some(EventType::UserDisabledByPermanentLockout),
            "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR" => {
                Some(EventType::UserDisabledByPermanentLockoutError)
            }
            "USER_DISABLED_BY_TEMPORARY_LOCKOUT" => Some(EventType::UserDisabledByTemporaryLockout),
            "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR" => {
                Some(EventType::UserDisabledByTemporaryLockoutError)
            }
            "INVITE_ORG" => Some(EventType::InviteOrg),
            "INVITE_ORG_ERROR" => Some(EventType::InviteOrgError),
            _ => None,
        }
    }
}

/// User event model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier
    pub id: String,
    /// Timestamp when the event occurred
    pub time: DateTime<Utc>,
    /// Event type
    pub event_type: EventType,
    /// Realm ID where the event occurred
    pub realm_id: String,
    /// Realm name
    pub realm_name: Option<String>,
    /// Client ID involved in the event
    pub client_id: Option<String>,
    /// User ID involved in the event
    pub user_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// IP address of the client
    pub ip_address: Option<String>,
    /// Error message if the event represents an error
    pub error: Option<String>,
    /// Additional event details
    pub details: HashMap<String, String>,
}

impl Event {
    /// Create a new event
    pub fn new(event_type: EventType, realm_id: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            time: Utc::now(),
            event_type,
            realm_id,
            realm_name: None,
            client_id: None,
            user_id: None,
            session_id: None,
            ip_address: None,
            error: None,
            details: HashMap::new(),
        }
    }

    /// Set realm name
    pub fn realm_name(mut self, name: String) -> Self {
        self.realm_name = Some(name);
        self
    }

    /// Set client ID
    pub fn client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    /// Set user ID
    pub fn user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set session ID
    pub fn session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set IP address
    pub fn ip_address(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Set error message
    pub fn error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    /// Add a detail
    pub fn detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    /// Add multiple details
    pub fn details(mut self, details: HashMap<String, String>) -> Self {
        self.details.extend(details);
        self
    }
}

/// Admin operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationType {
    /// Create operation
    Create,
    /// Update operation
    Update,
    /// Delete operation
    Delete,
    /// Action operation
    Action,
}

impl OperationType {
    /// Convert the operation type to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::Create => "CREATE",
            OperationType::Update => "UPDATE",
            OperationType::Delete => "DELETE",
            OperationType::Action => "ACTION",
        }
    }

    /// Convert string to OperationType
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "CREATE" => Some(OperationType::Create),
            "UPDATE" => Some(OperationType::Update),
            "DELETE" => Some(OperationType::Delete),
            "ACTION" => Some(OperationType::Action),
            _ => None,
        }
    }
}

/// Admin resource types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResourceType {
    /// Realm resource
    Realm,
    /// Realm role resource
    RealmRole,
    /// Realm role mapping resource
    RealmRoleMapping,
    /// Realm scope mapping resource
    RealmScopeMapping,
    /// Authentication flow resource
    AuthFlow,
    /// Authentication execution flow resource
    AuthExecutionFlow,
    /// Authentication execution resource
    AuthExecution,
    /// Authenticator configuration resource
    AuthenticatorConfig,
    /// Required action configuration resource
    RequiredActionConfig,
    /// Required action resource
    RequiredAction,
    /// Identity provider resource
    IdentityProvider,
    /// Identity provider mapper resource
    IdentityProviderMapper,
    /// Protocol mapper resource
    ProtocolMapper,
    /// User resource
    User,
    /// User login failure resource
    UserLoginFailure,
    /// User session resource
    UserSession,
    /// User federation mapper resource
    UserFederationMapper,
    /// User federation provider resource
    UserFederationProvider,
    /// Group resource
    Group,
    /// Group membership resource
    GroupMembership,
    /// Client resource
    Client,
    /// Client scope resource
    ClientScope,
    /// Client scope mapping resource
    ClientScopeMapping,
    /// Client scope client mapping resource
    ClientScopeClientMapping,
    /// Client template resource
    ClientTemplate,
    /// Client template mapping resource
    ClientTemplateMapping,
    /// Cluster node resource
    ClusterNode,
    /// Component resource
    Component,
    /// Authorization resource server
    AuthorizationResourceServer,
    /// Authorization resource
    AuthorizationResource,
    /// Authorization scope
    AuthorizationScope,
    /// Authorization policy
    AuthorizationPolicy,
    /// Custom resource type
    Custom,
    /// User profile
    UserProfile,
    /// Organization
    Organization,
    /// Organization membership
    OrganizationMembership,
}

impl ResourceType {
    /// Convert the resource type to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::Realm => "REALM",
            ResourceType::RealmRole => "REALM_ROLE",
            ResourceType::RealmRoleMapping => "REALM_ROLE_MAPPING",
            ResourceType::RealmScopeMapping => "REALM_SCOPE_MAPPING",
            ResourceType::AuthFlow => "AUTH_FLOW",
            ResourceType::AuthExecutionFlow => "AUTH_EXECUTION_FLOW",
            ResourceType::AuthExecution => "AUTH_EXECUTION",
            ResourceType::AuthenticatorConfig => "AUTHENTICATOR_CONFIG",
            ResourceType::RequiredActionConfig => "REQUIRED_ACTION_CONFIG",
            ResourceType::RequiredAction => "REQUIRED_ACTION",
            ResourceType::IdentityProvider => "IDENTITY_PROVIDER",
            ResourceType::IdentityProviderMapper => "IDENTITY_PROVIDER_MAPPER",
            ResourceType::ProtocolMapper => "PROTOCOL_MAPPER",
            ResourceType::User => "USER",
            ResourceType::UserLoginFailure => "USER_LOGIN_FAILURE",
            ResourceType::UserSession => "USER_SESSION",
            ResourceType::UserFederationMapper => "USER_FEDERATION_MAPPER",
            ResourceType::UserFederationProvider => "USER_FEDERATION_PROVIDER",
            ResourceType::Group => "GROUP",
            ResourceType::GroupMembership => "GROUP_MEMBERSHIP",
            ResourceType::Client => "CLIENT",
            ResourceType::ClientScope => "CLIENT_SCOPE",
            ResourceType::ClientScopeMapping => "CLIENT_SCOPE_MAPPING",
            ResourceType::ClientScopeClientMapping => "CLIENT_SCOPE_CLIENT_MAPPING",
            ResourceType::ClientTemplate => "CLIENT_TEMPLATE",
            ResourceType::ClientTemplateMapping => "CLIENT_TEMPLATE_MAPPING",
            ResourceType::ClusterNode => "CLUSTER_NODE",
            ResourceType::Component => "COMPONENT",
            ResourceType::AuthorizationResourceServer => "AUTHORIZATION_RESOURCE_SERVER",
            ResourceType::AuthorizationResource => "AUTHORIZATION_RESOURCE",
            ResourceType::AuthorizationScope => "AUTHORIZATION_SCOPE",
            ResourceType::AuthorizationPolicy => "AUTHORIZATION_POLICY",
            ResourceType::Custom => "CUSTOM",
            ResourceType::UserProfile => "USER_PROFILE",
            ResourceType::Organization => "ORGANIZATION",
            ResourceType::OrganizationMembership => "ORGANIZATION_MEMBERSHIP",
        }
    }

    /// Convert string to ResourceType
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "REALM" => Some(ResourceType::Realm),
            "REALM_ROLE" => Some(ResourceType::RealmRole),
            "REALM_ROLE_MAPPING" => Some(ResourceType::RealmRoleMapping),
            "REALM_SCOPE_MAPPING" => Some(ResourceType::RealmScopeMapping),
            "AUTH_FLOW" => Some(ResourceType::AuthFlow),
            "AUTH_EXECUTION_FLOW" => Some(ResourceType::AuthExecutionFlow),
            "AUTH_EXECUTION" => Some(ResourceType::AuthExecution),
            "AUTHENTICATOR_CONFIG" => Some(ResourceType::AuthenticatorConfig),
            "REQUIRED_ACTION_CONFIG" => Some(ResourceType::RequiredActionConfig),
            "REQUIRED_ACTION" => Some(ResourceType::RequiredAction),
            "IDENTITY_PROVIDER" => Some(ResourceType::IdentityProvider),
            "IDENTITY_PROVIDER_MAPPER" => Some(ResourceType::IdentityProviderMapper),
            "PROTOCOL_MAPPER" => Some(ResourceType::ProtocolMapper),
            "USER" => Some(ResourceType::User),
            "USER_LOGIN_FAILURE" => Some(ResourceType::UserLoginFailure),
            "USER_SESSION" => Some(ResourceType::UserSession),
            "USER_FEDERATION_MAPPER" => Some(ResourceType::UserFederationMapper),
            "USER_FEDERATION_PROVIDER" => Some(ResourceType::UserFederationProvider),
            "GROUP" => Some(ResourceType::Group),
            "GROUP_MEMBERSHIP" => Some(ResourceType::GroupMembership),
            "CLIENT" => Some(ResourceType::Client),
            "CLIENT_SCOPE" => Some(ResourceType::ClientScope),
            "CLIENT_SCOPE_MAPPING" => Some(ResourceType::ClientScopeMapping),
            "CLIENT_SCOPE_CLIENT_MAPPING" => Some(ResourceType::ClientScopeClientMapping),
            "CLIENT_TEMPLATE" => Some(ResourceType::ClientTemplate),
            "CLIENT_TEMPLATE_MAPPING" => Some(ResourceType::ClientTemplateMapping),
            "CLUSTER_NODE" => Some(ResourceType::ClusterNode),
            "COMPONENT" => Some(ResourceType::Component),
            "AUTHORIZATION_RESOURCE_SERVER" => Some(ResourceType::AuthorizationResourceServer),
            "AUTHORIZATION_RESOURCE" => Some(ResourceType::AuthorizationResource),
            "AUTHORIZATION_SCOPE" => Some(ResourceType::AuthorizationScope),
            "AUTHORIZATION_POLICY" => Some(ResourceType::AuthorizationPolicy),
            "CUSTOM" => Some(ResourceType::Custom),
            "USER_PROFILE" => Some(ResourceType::UserProfile),
            "ORGANIZATION" => Some(ResourceType::Organization),
            "ORGANIZATION_MEMBERSHIP" => Some(ResourceType::OrganizationMembership),
            _ => None,
        }
    }
}

/// Authentication details for admin events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDetails {
    /// User ID of the admin performing the action
    pub user_id: String,
    /// Username of the admin
    pub username: Option<String>,
    /// IP address of the admin
    pub ip_address: Option<String>,
    /// User agent of the admin client
    pub user_agent: Option<String>,
}

/// Admin event model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEvent {
    /// Unique event identifier
    pub id: String,
    /// Timestamp when the event occurred
    pub time: DateTime<Utc>,
    /// Realm ID where the admin action occurred
    pub realm_id: String,
    /// Realm name
    pub realm_name: Option<String>,
    /// Authentication details of the admin user
    pub auth_details: AuthDetails,
    /// Resource type being operated on
    pub resource_type: ResourceType,
    /// Operation type
    pub operation_type: OperationType,
    /// Resource path/identifier
    pub resource_path: String,
    /// JSON representation of the resource (for create/update operations)
    pub representation: Option<String>,
    /// Error message if the operation failed
    pub error: Option<String>,
}

impl AdminEvent {
    /// Create a new admin event
    pub fn new(
        realm_id: String,
        auth_details: AuthDetails,
        resource_type: ResourceType,
        operation_type: OperationType,
        resource_path: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            time: Utc::now(),
            realm_id,
            realm_name: None,
            auth_details,
            resource_type,
            operation_type,
            resource_path,
            representation: None,
            error: None,
        }
    }

    /// Set realm name
    pub fn realm_name(mut self, name: String) -> Self {
        self.realm_name = Some(name);
        self
    }

    /// Set representation
    pub fn representation(mut self, representation: String) -> Self {
        self.representation = Some(representation);
        self
    }

    /// Set error message
    pub fn error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }
}
