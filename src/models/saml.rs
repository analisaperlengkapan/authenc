use crate::error::{AuthencError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use uuid::Uuid;

/// SAML service provider model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProvider {
    /// Unique identifier for the service provider
    pub id: Uuid,
    /// SAML entity ID of the service provider
    pub entity_id: String,
    /// URL to fetch SAML metadata from
    pub metadata_url: Option<String>,
    /// SAML metadata XML content
    pub metadata_xml: Option<String>,
    /// Certificate for verifying SAML signatures
    pub signing_certificate: Option<String>,
    /// Certificate for SAML encryption
    pub encryption_certificate: Option<String>,
    /// URL where SAML assertions should be sent
    pub assertion_consumer_service_url: String,
    /// URL for SAML single logout service
    pub single_logout_service_url: Option<String>,
    /// SAML name ID format expected by the service provider
    pub name_id_format: String,
    /// ID of the realm this service provider belongs to
    pub realm_id: Option<Uuid>,
    /// Whether this service provider is enabled
    pub enabled: bool,
    /// Timestamp when the service provider was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the service provider was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the service provider was soft deleted
    pub deleted_at: Option<DateTime<Utc>>,
}

/// SAML identity provider model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdentityProvider {
    /// Unique identifier for the identity provider
    pub id: Uuid,
    /// SAML entity ID of the identity provider
    pub entity_id: String,
    /// URL to fetch SAML metadata from
    pub metadata_url: Option<String>,
    /// SAML metadata XML content
    pub metadata_xml: Option<String>,
    /// URL for SAML single sign-on service
    pub sso_url: String,
    /// URL for SAML single logout service
    pub slo_url: Option<String>,
    /// Certificate for signing SAML messages
    pub signing_certificate: String,
    /// Certificate for SAML encryption
    pub encryption_certificate: Option<String>,
    /// SAML name ID format used by the identity provider
    pub name_id_format: String,
    /// ID of the realm this identity provider belongs to
    pub realm_id: Option<Uuid>,
    /// Whether this identity provider is enabled
    pub enabled: bool,
    /// Timestamp when the identity provider was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the identity provider was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the identity provider was soft deleted
    pub deleted_at: Option<DateTime<Utc>>,
}

/// SAML session model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSession {
    /// Unique identifier for the SAML session
    pub id: Uuid,
    /// SAML session identifier
    pub session_id: String,
    /// ID of the user this session belongs to
    pub user_id: Uuid,
    /// ID of the SAML identity provider
    pub identity_provider_id: Uuid,
    /// ID of the SAML service provider
    pub service_provider_id: Option<Uuid>,
    /// SAML name identifier for the user
    pub name_id: String,
    /// Format of the SAML name identifier
    pub name_id_format: String,
    /// SAML session index
    pub session_index: Option<String>,
    /// Timestamp when authentication occurred
    pub authn_instant: DateTime<Utc>,
    /// Timestamp when the session expires
    pub expires_at: DateTime<Utc>,
    /// Timestamp when the session was created
    pub created_at: DateTime<Utc>,
}

/// SAML authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnRequest {
    /// Unique identifier for the authentication request
    pub id: String,
    /// SAML entity ID of the requesting service provider
    pub issuer: String,
    /// URL where the SAML response should be sent
    pub assertion_consumer_service_url: String,
    /// SAML protocol binding to use
    pub protocol_binding: String,
    /// SAML name ID policy
    pub name_id_policy: Option<SamlNameIdPolicy>,
    /// Requested authentication context
    pub requested_authn_context: Option<SamlRequestedAuthnContext>,
    /// Whether to force re-authentication
    pub force_authn: bool,
    /// Whether this is a passive authentication request
    pub is_passive: bool,
}

/// SAML name ID policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlNameIdPolicy {
    /// Format of the name identifier
    pub format: String,
    /// Whether creation of new name identifiers is allowed
    pub allow_create: bool,
}

/// SAML requested authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlRequestedAuthnContext {
    /// Comparison method for authentication context
    pub comparison: String,
    /// List of acceptable authentication context class references
    pub authn_context_class_refs: Vec<String>,
}

/// SAML response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    /// Unique identifier for the SAML response
    pub id: String,
    /// ID of the request this response is in response to
    pub in_response_to: String,
    /// SAML entity ID of the responding identity provider
    pub issuer: String,
    /// SAML status of the response
    pub status: SamlStatus,
    /// SAML assertion containing authentication information
    pub assertion: Option<SamlAssertion>,
    /// Destination URL for the response
    pub destination: String,
}

/// SAML status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStatus {
    /// SAML status code
    pub status_code: SamlStatusCode,
    /// Human-readable status message
    pub status_message: Option<String>,
    /// Additional status details
    pub status_detail: Option<String>,
}

/// SAML status code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStatusCode {
    /// Status code value
    pub value: String,
    /// Nested status code for additional information
    pub status_code: Option<Box<SamlStatusCode>>,
}

/// SAML assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Unique identifier for the SAML assertion
    pub id: String,
    /// Timestamp when the assertion was issued
    pub issue_instant: DateTime<Utc>,
    /// SAML entity ID of the issuing identity provider
    pub issuer: String,
    /// SAML subject containing user information
    pub subject: Option<SamlSubject>,
    /// SAML conditions for the assertion validity
    pub conditions: Option<SamlConditions>,
    /// SAML authentication statement
    pub authn_statement: Option<SamlAuthnStatement>,
    /// SAML attribute statement
    pub attribute_statement: Option<SamlAttributeStatement>,
}

/// SAML subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubject {
    /// SAML name identifier
    pub name_id: SamlNameId,
    /// List of subject confirmations
    pub subject_confirmations: Vec<SamlSubjectConfirmation>,
}

/// SAML name ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlNameId {
    /// Format of the name identifier
    pub format: String,
    /// Value of the name identifier
    pub value: String,
    /// Name qualifier for the identifier
    pub name_qualifier: Option<String>,
    /// Service provider name qualifier
    pub sp_name_qualifier: Option<String>,
}

/// SAML subject confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmation {
    /// Confirmation method
    pub method: String,
    /// Subject confirmation data
    pub subject_confirmation_data: Option<SamlSubjectConfirmationData>,
}

/// SAML subject confirmation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmationData {
    /// Timestamp after which the confirmation is invalid
    pub not_on_or_after: DateTime<Utc>,
    /// Recipient of the SAML response
    pub recipient: String,
    /// ID of the request this confirmation is for
    pub in_response_to: String,
}

/// SAML conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConditions {
    /// Timestamp before which the assertion is not valid
    pub not_before: Option<DateTime<Utc>>,
    /// Timestamp after which the assertion is not valid
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// List of audience restrictions
    pub audience_restrictions: Vec<SamlAudienceRestriction>,
}

/// SAML audience restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAudienceRestriction {
    /// List of acceptable audiences for the assertion
    pub audiences: Vec<String>,
}

/// SAML authentication statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnStatement {
    /// Timestamp when authentication occurred
    pub authn_instant: DateTime<Utc>,
    /// SAML session index
    pub session_index: Option<String>,
    /// Timestamp when the session expires
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    /// SAML authentication context
    pub authn_context: SamlAuthnContext,
}

/// SAML authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnContext {
    /// Authentication context class reference
    pub authn_context_class_ref: String,
    /// List of authenticating authorities
    pub authenticating_authorities: Vec<String>,
}

/// SAML attribute statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeStatement {
    /// List of SAML attributes
    pub attributes: Vec<SamlAttribute>,
}

/// SAML attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttribute {
    /// Name of the attribute
    pub name: String,
    /// Format of the attribute name
    pub name_format: Option<String>,
    /// Human-readable name of the attribute
    pub friendly_name: Option<String>,
    /// List of attribute values
    pub values: Vec<String>,
}

impl TryFrom<tokio_postgres::Row> for SamlServiceProvider {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            entity_id: row.try_get("entity_id")?,
            metadata_url: row.try_get("metadata_url")?,
            metadata_xml: row.try_get("metadata_xml")?,
            signing_certificate: row.try_get("signing_certificate")?,
            encryption_certificate: row.try_get("encryption_certificate")?,
            assertion_consumer_service_url: row.try_get("assertion_consumer_service_url")?,
            single_logout_service_url: row.try_get("single_logout_service_url")?,
            name_id_format: row.try_get("name_id_format")?,
            realm_id: row.try_get("realm_id")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

impl TryFrom<tokio_postgres::Row> for SamlIdentityProvider {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            entity_id: row.try_get("entity_id")?,
            metadata_url: row.try_get("metadata_url")?,
            metadata_xml: row.try_get("metadata_xml")?,
            sso_url: row.try_get("sso_url")?,
            slo_url: row.try_get("slo_url")?,
            signing_certificate: row.try_get("signing_certificate")?,
            encryption_certificate: row.try_get("encryption_certificate")?,
            name_id_format: row.try_get("name_id_format")?,
            realm_id: row.try_get("realm_id")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

impl TryFrom<tokio_postgres::Row> for SamlSession {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            session_id: row.try_get("session_id")?,
            user_id: row.try_get("user_id")?,
            identity_provider_id: row.try_get("identity_provider_id")?,
            service_provider_id: row.try_get("service_provider_id")?,
            name_id: row.try_get("name_id")?,
            name_id_format: row.try_get("name_id_format")?,
            session_index: row.try_get("session_index")?,
            authn_instant: row.try_get("authn_instant")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
