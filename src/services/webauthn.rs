use crate::database::Database;
use crate::error::{AuthencError, Result};
use crate::models::webauthn::*;
use crate::utils::crypto_monitor::CryptoMonitor;
use axum::response::Json;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use getrandom;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// WebAuthn service for FIDO2 authentication
pub struct WebAuthnService {
    db: Arc<Database>,
    relying_party_id: String,
    relying_party_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationRequest {
    pub username: String,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(db: Arc<Database>, rp_id: String, rp_name: String) -> Self {
        Self {
            db,
            relying_party_id: rp_id,
            relying_party_name: rp_name,
        }
    }

    /// Generate WebAuthn registration challenge
    pub async fn generate_registration_challenge(
        &self,
        request: WebAuthnRegistrationRequest,
    ) -> Result<Json<serde_json::Value>> {
        // Generate cryptographically secure challenge
        let challenge_bytes =
            CryptoMonitor::monitor_rsa_operation("webauthn_challenge_gen", || {
                let mut challenge = [0u8; 32];
                getrandom::getrandom(&mut challenge).expect("Failed to generate random challenge");
                challenge
            });

        let challenge_b64 = Base64UrlUnpadded::encode_string(&challenge_bytes);

        // Create user ID
        let user_id = Uuid::new_v4().as_bytes().to_vec();

        let registration_challenge = WebauthnRegistrationChallenge {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(), // Would be looked up from username
            challenge: challenge_bytes.to_vec(),
            relying_party_id: self.relying_party_id.clone(),
            relying_party_name: self.relying_party_name.clone(),
            user_name: request.username.clone(),
            user_display_name: Some(request.display_name.clone()),
            user_id_bytes: user_id,
            public_key_credential_parameters: vec![
                WebauthnPublicKeyCredentialParameter {
                    ty: "public-key".to_string(),
                    alg: -7, // ES256
                },
                WebauthnPublicKeyCredentialParameter {
                    ty: "public-key".to_string(),
                    alg: -257, // RS256
                },
                WebauthnPublicKeyCredentialParameter {
                    ty: "public-key".to_string(),
                    alg: -8, // EdDSA
                },
            ],
            authenticator_selection: Some(WebauthnAuthenticatorSelection {
                authenticator_attachment: Some("cross-platform".to_string()),
                require_resident_key: false,
                user_verification: "preferred".to_string(),
            }),
            attestation: Some("direct".to_string()),
            timeout: Some(60000), // 60 seconds
            exclude_credentials: vec![],
            extensions: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300), // 5 minutes
        };

        // Store challenge in database for verification
        self.store_challenge(&request.username, &challenge_bytes)
            .await?;

        Ok(Json(serde_json::to_value(registration_challenge).unwrap()))
    }

    /// Verify WebAuthn registration response
    pub async fn verify_registration(
        &self,
        username: &str,
        response: WebauthnRegistrationResponse,
    ) -> Result<Json<serde_json::Value>> {
        // Retrieve stored challenge
        let stored_challenge = self
            .get_challenge(username)
            .await?
            .ok_or_else(|| AuthencError::unauthorized("No challenge found for user"))?;

        // Decode client data JSON
        let client_data_json: serde_json::Value =
            serde_json::from_slice(&response.response.client_data_json)
                .map_err(|_| AuthencError::unauthorized("Invalid client data JSON"))?;

        // Verify challenge
        let challenge_b64 = client_data_json["challenge"]
            .as_str()
            .ok_or_else(|| AuthencError::unauthorized("Missing challenge in client data"))?;

        if challenge_b64 != Base64UrlUnpadded::encode_string(&stored_challenge) {
            return Err(AuthencError::unauthorized("Challenge mismatch"));
        }

        // Verify origin
        let origin = client_data_json["origin"]
            .as_str()
            .ok_or_else(|| AuthencError::unauthorized("Missing origin in client data"))?;

        if !self.verify_origin(origin) {
            return Err(AuthencError::unauthorized("Origin verification failed"));
        }

        // Parse attestation object (simplified - in production would need full CBOR parsing)
        // For now, we'll create a mock credential
        let credential = WebauthnCredential {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(), // Would be looked up from username
            credential_id: response.raw_id,
            public_key: vec![],       // Would be extracted from attestation object
            public_key_algorithm: -7, // ES256
            signature_counter: 0,
            attestation_object: Some(response.response.attestation_object),
            authenticator_data: None, // Not available in registration response
            user_handle: Some(vec![]),
            credential_type: "public-key".to_string(),
            transports: Some(vec![]),
            aaguid: None,
            attestation_format: Some("none".to_string()),
            created_at: Utc::now(),
            last_used_at: None,
            enabled: true,
        };

        // Store credential
        self.store_credential(username, &credential).await?;

        // Remove used challenge
        self.delete_challenge(username).await?;

        Ok(Json(serde_json::json!({
            "success": true,
            "message": "WebAuthn registration successful",
            "credential_id": credential.id
        })))
    }

    /// Generate WebAuthn authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        request: WebAuthnAuthenticationRequest,
    ) -> Result<Json<serde_json::Value>> {
        // Get user's credentials
        let credentials = self.get_user_credentials(&request.username).await?;

        if credentials.is_empty() {
            return Err(AuthencError::unauthorized(
                "No WebAuthn credentials found for user",
            ));
        }

        // Generate challenge
        let challenge_bytes =
            CryptoMonitor::monitor_rsa_operation("webauthn_auth_challenge", || {
                let mut challenge = [0u8; 32];
                getrandom::getrandom(&mut challenge).expect("Failed to generate random challenge");
                challenge
            });

        let challenge_b64 = Base64UrlUnpadded::encode_string(&challenge_bytes);

        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = credentials
            .iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                id: cred.credential_id.clone(),
                typ: "public-key".to_string(),
                transports: Some(vec![
                    "usb".to_string(),
                    "nfc".to_string(),
                    "ble".to_string(),
                ]),
            })
            .collect();

        let auth_challenge = WebauthnAuthenticationChallenge {
            id: Uuid::new_v4(),
            user_id: None,
            challenge: challenge_bytes.to_vec(),
            relying_party_id: self.relying_party_id.clone(),
            allow_credentials: allow_credentials
                .into_iter()
                .map(|desc| WebauthnCredentialDescriptor {
                    ty: desc.typ,
                    id: desc.id,
                    transports: desc.transports,
                })
                .collect(),
            user_verification: Some("preferred".to_string()),
            timeout: None,
            extensions: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };

        // Store challenge
        self.store_challenge(&request.username, &challenge_bytes)
            .await?;

        Ok(Json(serde_json::to_value(auth_challenge).unwrap()))
    }

    /// Verify WebAuthn authentication response
    pub async fn verify_authentication(
        &self,
        username: &str,
        response: WebauthnAuthenticationResponse,
    ) -> Result<Json<serde_json::Value>> {
        // Retrieve stored challenge
        let stored_challenge = self
            .get_challenge(username)
            .await?
            .ok_or_else(|| AuthencError::unauthorized("No challenge found for user"))?;

        // Decode client data JSON
        let client_data_json: serde_json::Value =
            serde_json::from_slice(&response.response.client_data_json)
                .map_err(|_| AuthencError::unauthorized("Invalid client data JSON"))?;

        // Verify challenge
        let challenge_b64 = client_data_json["challenge"]
            .as_str()
            .ok_or_else(|| AuthencError::unauthorized("Missing challenge in client data"))?;

        if challenge_b64 != Base64UrlUnpadded::encode_string(&stored_challenge) {
            return Err(AuthencError::unauthorized("Challenge mismatch"));
        }

        // Get credential
        let credential = self
            .get_credential(username, &response.id)
            .await?
            .ok_or_else(|| AuthencError::unauthorized("Credential not found"))?;

        // Verify signature (simplified - in production would verify against public key)
        // This is where you'd implement the actual cryptographic verification

        // Update sign count
        self.update_credential_sign_count(
            username,
            &response.id,
            response.response.authenticator_data.len() as u32,
        )
        .await?;

        // Remove used challenge
        self.delete_challenge(username).await?;

        Ok(Json(serde_json::json!({
            "success": true,
            "message": "WebAuthn authentication successful",
            "user": username
        })))
    }

    // Database operations
    async fn store_challenge(&self, username: &str, challenge: &[u8]) -> Result<()> {
        use crate::database::operations::users;

        // Get user ID from username
        let user = users::get_user_by_username(&self.db, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        // For now, store challenge in memory or Redis
        // TODO: Implement challenge storage in database
        unimplemented!("Challenge storage in database not yet implemented")
    }

    async fn get_challenge(&self, username: &str) -> Result<Option<Vec<u8>>> {
        // TODO: Implement challenge retrieval from database
        unimplemented!("Challenge retrieval from database not yet implemented")
    }

    async fn delete_challenge(&self, username: &str) -> Result<()> {
        // TODO: Implement challenge deletion from database
        unimplemented!("Challenge deletion from database not yet implemented")
    }

    async fn store_credential(
        &self,
        username: &str,
        credential: &WebauthnCredential,
    ) -> Result<()> {
        use crate::database::operations::users;
        use crate::database::operations::webauthn as webauthn_db;

        // Get user ID from username
        let user = users::get_user_by_username(&self.db, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        // Convert service credential to model credential
        let model_credential = crate::models::WebauthnCredential {
            id: credential.id,
            user_id: user.id,
            credential_id: credential.credential_id.clone(),
            public_key: credential.public_key.clone(),
            public_key_algorithm: credential.public_key_algorithm,
            signature_counter: credential.signature_counter,
            attestation_object: credential.attestation_object.clone(),
            authenticator_data: credential.authenticator_data.clone(),
            user_handle: credential.user_handle.clone(),
            credential_type: credential.credential_type.clone(),
            transports: credential.transports.clone(),
            aaguid: credential.aaguid.clone(),
            attestation_format: credential.attestation_format.clone(),
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            enabled: credential.enabled,
        };

        webauthn_db::store_credential(&self.db, user.id, &model_credential).await?;
        Ok(())
    }

    async fn get_user_credentials(&self, username: &str) -> Result<Vec<WebauthnCredential>> {
        use crate::database::operations::users;
        use crate::database::operations::webauthn as webauthn_db;

        // Get user ID from username
        let user = users::get_user_by_username(&self.db, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let model_credentials = webauthn_db::get_user_credentials(&self.db, user.id).await?;

        // Convert model credentials to service credentials
        let service_credentials = model_credentials
            .into_iter()
            .map(|mc| WebauthnCredential {
                id: mc.id,
                user_id: mc.user_id,
                credential_id: mc.credential_id,
                public_key: mc.public_key,
                public_key_algorithm: mc.public_key_algorithm,
                signature_counter: mc.signature_counter,
                attestation_object: mc.attestation_object,
                authenticator_data: mc.authenticator_data,
                user_handle: mc.user_handle,
                credential_type: mc.credential_type,
                transports: mc.transports,
                aaguid: mc.aaguid,
                attestation_format: mc.attestation_format,
                created_at: mc.created_at,
                last_used_at: mc.last_used_at,
                enabled: mc.enabled,
            })
            .collect();

        Ok(service_credentials)
    }

    async fn get_credential(
        &self,
        username: &str,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>> {
        use crate::database::operations::webauthn as webauthn_db;

        let model_credential = webauthn_db::get_credential_by_id(&self.db, credential_id).await?;

        Ok(model_credential.map(|mc| WebauthnCredential {
            id: mc.id,
            user_id: mc.user_id,
            credential_id: mc.credential_id,
            public_key: mc.public_key,
            public_key_algorithm: mc.public_key_algorithm,
            signature_counter: mc.signature_counter,
            attestation_object: mc.attestation_object,
            authenticator_data: mc.authenticator_data,
            user_handle: mc.user_handle,
            credential_type: mc.credential_type,
            transports: mc.transports,
            aaguid: mc.aaguid,
            attestation_format: mc.attestation_format,
            created_at: mc.created_at,
            last_used_at: mc.last_used_at,
            enabled: mc.enabled,
        }))
    }

    async fn update_credential_sign_count(
        &self,
        username: &str,
        credential_id: &str,
        sign_count: u32,
    ) -> Result<()> {
        use crate::database::operations::webauthn as webauthn_db;

        webauthn_db::update_signature_count(&self.db, credential_id, sign_count as i64).await?;
        Ok(())
    }

    fn verify_origin(&self, origin: &str) -> bool {
        // In production, verify against allowed origins
        origin.starts_with("https://") || origin.starts_with("http://localhost")
    }
}
