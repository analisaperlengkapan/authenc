use crate::error::{AuthencError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use uuid::Uuid;

/// SAML service provider model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProvider {
    pub id: Uuid,
    pub entity_id: String,
    pub metadata_url: Option<String>,
    pub metadata_xml: Option<String>,
    pub signing_certificate: Option<String>,
    pub encryption_certificate: Option<String>,
    pub assertion_consumer_service_url: String,
    pub single_logout_service_url: Option<String>,
    pub name_id_format: String,
    pub realm_id: Option<Uuid>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// SAML identity provider model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdentityProvider {
    pub id: Uuid,
    pub entity_id: String,
    pub metadata_url: Option<String>,
    pub metadata_xml: Option<String>,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub signing_certificate: String,
    pub encryption_certificate: Option<String>,
    pub name_id_format: String,
    pub realm_id: Option<Uuid>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// SAML session model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSession {
    pub id: Uuid,
    pub session_id: String,
    pub user_id: Uuid,
    pub identity_provider_id: Uuid,
    pub service_provider_id: Option<Uuid>,
    pub name_id: String,
    pub name_id_format: String,
    pub session_index: Option<String>,
    pub authn_instant: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// SAML authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub assertion_consumer_service_url: String,
    pub protocol_binding: String,
    pub name_id_policy: Option<SamlNameIdPolicy>,
    pub requested_authn_context: Option<SamlRequestedAuthnContext>,
    pub force_authn: bool,
    pub is_passive: bool,
}

/// SAML name ID policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlNameIdPolicy {
    pub format: String,
    pub allow_create: bool,
}

/// SAML requested authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlRequestedAuthnContext {
    pub comparison: String,
    pub authn_context_class_refs: Vec<String>,
}

/// SAML response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    pub id: String,
    pub in_response_to: String,
    pub issuer: String,
    pub status: SamlStatus,
    pub assertion: Option<SamlAssertion>,
    pub destination: String,
}

/// SAML status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStatus {
    pub status_code: SamlStatusCode,
    pub status_message: Option<String>,
    pub status_detail: Option<String>,
}

/// SAML status code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStatusCode {
    pub value: String,
    pub status_code: Option<Box<SamlStatusCode>>,
}

/// SAML assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub subject: Option<SamlSubject>,
    pub conditions: Option<SamlConditions>,
    pub authn_statement: Option<SamlAuthnStatement>,
    pub attribute_statement: Option<SamlAttributeStatement>,
}

/// SAML subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubject {
    pub name_id: SamlNameId,
    pub subject_confirmations: Vec<SamlSubjectConfirmation>,
}

/// SAML name ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlNameId {
    pub format: String,
    pub value: String,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
}

/// SAML subject confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmation {
    pub method: String,
    pub subject_confirmation_data: Option<SamlSubjectConfirmationData>,
}

/// SAML subject confirmation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmationData {
    pub not_on_or_after: DateTime<Utc>,
    pub recipient: String,
    pub in_response_to: String,
}

/// SAML conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConditions {
    pub not_before: Option<DateTime<Utc>>,
    pub not_on_or_after: Option<DateTime<Utc>>,
    pub audience_restrictions: Vec<SamlAudienceRestriction>,
}

/// SAML audience restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAudienceRestriction {
    pub audiences: Vec<String>,
}

/// SAML authentication statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnStatement {
    pub authn_instant: DateTime<Utc>,
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    pub authn_context: SamlAuthnContext,
}

/// SAML authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnContext {
    pub authn_context_class_ref: String,
    pub authenticating_authorities: Vec<String>,
}

/// SAML attribute statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeStatement {
    pub attributes: Vec<SamlAttribute>,
}

/// SAML attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttribute {
    pub name: String,
    pub name_format: Option<String>,
    pub friendly_name: Option<String>,
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
