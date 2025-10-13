// SAML Signature and Storage Implementation
// Provides XML digital signature support and database storage for SAML requests/responses.

use crate::{
    database::Database,
    error::{AuthencError, Result},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SAML request/response storage model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlMessage {
    pub id: Uuid,
    pub saml_id: String,
    pub message_type: String,
    pub issuer: String,
    pub destination: String,
    pub xml_content: String,
    pub signature: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_id: Option<String>,
    pub relay_state: Option<String>,
}

/// Database operations for SAML message storage
pub mod saml_storage {
    use super::*;

    /// Store SAML request in database
    pub async fn store_saml_request(
        db: &Database,
        saml_id: &str,
        message_type: &str,
        issuer: &str,
        destination: &str,
        xml_content: &str,
        signature: Option<&str>,
        relay_state: Option<&str>,
        ttl_seconds: i64,
    ) -> Result<SamlMessage> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);

        let query = r#"
            INSERT INTO saml_messages (
                id, saml_id, message_type, issuer, destination,
                xml_content, signature, created_at, expires_at,
                relay_state
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, saml_id, message_type, issuer, destination,
                      xml_content, signature, created_at, expires_at,
                      session_id, relay_state
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &id,
                    &saml_id,
                    &message_type,
                    &issuer,
                    &destination,
                    &xml_content,
                    &signature,
                    &now,
                    &expires_at,
                    &relay_state,
                ],
            )
            .await?;

        Ok(SamlMessage {
            id: row.get("id"),
            saml_id: row.get("saml_id"),
            message_type: row.get("message_type"),
            issuer: row.get("issuer"),
            destination: row.get("destination"),
            xml_content: row.get("xml_content"),
            signature: row.get("signature"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            session_id: row.get("session_id"),
            relay_state: row.get("relay_state"),
        })
    }

    /// Retrieve SAML request from database
    pub async fn get_saml_request(db: &Database, saml_id: &str) -> Result<Option<SamlMessage>> {
        let query = r#"
            SELECT id, saml_id, message_type, issuer, destination,
                   xml_content, signature, created_at, expires_at,
                   session_id, relay_state
            FROM saml_messages
            WHERE saml_id = $1
            AND expires_at > NOW()
        "#;

        let row = db.query_opt(query, &[&saml_id]).await?;

        Ok(row.map(|row: tokio_postgres::Row| SamlMessage {
            id: row.get("id"),
            saml_id: row.get("saml_id"),
            message_type: row.get("message_type"),
            issuer: row.get("issuer"),
            destination: row.get("destination"),
            xml_content: row.get("xml_content"),
            signature: row.get("signature"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            session_id: row.get("session_id"),
            relay_state: row.get("relay_state"),
        }))
    }

    /// Delete SAML request from database
    pub async fn delete_saml_request(db: &Database, saml_id: &str) -> Result<()> {
        let query = "DELETE FROM saml_messages WHERE saml_id = $1";
        db.execute(query, &[&saml_id]).await?;
        Ok(())
    }

    /// Cleanup expired SAML messages
    pub async fn cleanup_expired_saml_messages(db: &Database) -> Result<i64> {
        let query = "DELETE FROM saml_messages WHERE expires_at < NOW()";
        let rows_affected = db.execute(query, &[]).await?;
        Ok(rows_affected as i64)
    }
}
