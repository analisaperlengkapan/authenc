use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// User event types - comprehensive set similar to Keycloak
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    // Authentication events
    Login,
    LoginError,
    Logout,
    LogoutError,
    CodeToToken,
    CodeToTokenError,
    ClientLogin,
    ClientLoginError,
    RefreshToken,
    RefreshTokenError,
    IntrospectToken,
    IntrospectTokenError,

    // User management events
    Register,
    RegisterError,
    UpdateProfile,
    UpdateProfileError,
    UpdateEmail,
    UpdateEmailError,
    VerifyEmail,
    VerifyEmailError,
    VerifyProfile,
    VerifyProfileError,
    SendVerifyEmail,
    SendVerifyEmailError,
    SendResetPassword,
    SendResetPasswordError,
    ResetPassword,
    ResetPasswordError,

    // Credential events
    UpdateCredential,
    UpdateCredentialError,
    RemoveCredential,
    RemoveCredentialError,

    // Federation events
    FederatedIdentityLink,
    FederatedIdentityLinkError,
    RemoveFederatedIdentity,
    RemoveFederatedIdentityError,
    FederatedIdentityOverrideLink,
    FederatedIdentityOverrideLinkError,

    // Consent events
    GrantConsent,
    GrantConsentError,
    UpdateConsent,
    UpdateConsentError,
    RevokeGrant,
    RevokeGrantError,

    // OAuth2 extension events
    Oauth2ExtensionGrant,
    Oauth2ExtensionGrantError,

    // Security events
    UserDisabledByPermanentLockout,
    UserDisabledByPermanentLockoutError,
    UserDisabledByTemporaryLockout,
    UserDisabledByTemporaryLockoutError,

    // Organization events
    InviteOrg,
    InviteOrgError,
}

impl EventType {
    /// Check if this event should be saved by default
    pub fn is_save_by_default(&self) -> bool {
        match self {
            // Authentication events - save by default
            EventType::Login | EventType::Logout | EventType::Register |
            EventType::UpdateProfile | EventType::UpdateEmail | EventType::VerifyEmail |
            EventType::VerifyProfile | EventType::ResetPassword | EventType::GrantConsent |
            EventType::RevokeGrant | EventType::FederatedIdentityLink |
            EventType::RemoveFederatedIdentity | EventType::UpdateCredential |
            EventType::RemoveCredential | EventType::UserDisabledByPermanentLockout |
            EventType::UserDisabledByTemporaryLockout | EventType::InviteOrg => true,

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
            EventType::FederatedIdentityOverrideLinkError => "FEDERATED_IDENTITY_OVERRIDE_LINK_ERROR",
            EventType::GrantConsent => "GRANT_CONSENT",
            EventType::GrantConsentError => "GRANT_CONSENT_ERROR",
            EventType::UpdateConsent => "UPDATE_CONSENT",
            EventType::UpdateConsentError => "UPDATE_CONSENT_ERROR",
            EventType::RevokeGrant => "REVOKE_GRANT",
            EventType::RevokeGrantError => "REVOKE_GRANT_ERROR",
            EventType::Oauth2ExtensionGrant => "OAUTH2_EXTENSION_GRANT",
            EventType::Oauth2ExtensionGrantError => "OAUTH2_EXTENSION_GRANT_ERROR",
            EventType::UserDisabledByPermanentLockout => "USER_DISABLED_BY_PERMANENT_LOCKOUT",
            EventType::UserDisabledByPermanentLockoutError => "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR",
            EventType::UserDisabledByTemporaryLockout => "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
            EventType::UserDisabledByTemporaryLockoutError => "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR",
            EventType::InviteOrg => "INVITE_ORG",
            EventType::InviteOrgError => "INVITE_ORG_ERROR",
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
    Create,
    Update,
    Delete,
    Action,
}

impl OperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::Create => "CREATE",
            OperationType::Update => "UPDATE",
            OperationType::Delete => "DELETE",
            OperationType::Action => "ACTION",
        }
    }
}

/// Admin resource types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResourceType {
    Realm,
    RealmRole,
    RealmRoleMapping,
    RealmScopeMapping,
    AuthFlow,
    AuthExecutionFlow,
    AuthExecution,
    AuthenticatorConfig,
    RequiredActionConfig,
    RequiredAction,
    IdentityProvider,
    IdentityProviderMapper,
    ProtocolMapper,
    User,
    UserLoginFailure,
    UserSession,
    UserFederationMapper,
    UserFederationProvider,
    Group,
    GroupMembership,
    Client,
    ClientScope,
    ClientScopeMapping,
    ClientScopeClientMapping,
    ClientTemplate,
    ClientTemplateMapping,
    ClusterNode,
    Component,
    AuthorizationResourceServer,
    AuthorizationResource,
    AuthorizationScope,
    AuthorizationPolicy,
    Custom,
    UserProfile,
    Organization,
    OrganizationMembership,
}

impl ResourceType {
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
