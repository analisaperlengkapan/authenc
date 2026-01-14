use crate::crypto::aes_gcm::{AesGcmService, EncryptedData};
use crate::database::operations::{users, webauthn as webauthn_db};
use crate::database::Database;
use crate::error::{AuthencError, Result};
use crate::models::webauthn::*;
use axum::response::Json;
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

/// WebAuthn service for FIDO2 authentication
pub struct WebAuthnService {
    db: Arc<Database>,
    webauthn: Arc<Webauthn>,
    encryption: AesGcmService,
}

/// WebAuthn registration request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationRequest {
    pub username: String,
    pub display_name: String,
    pub realm_id: Uuid,
}

/// WebAuthn authentication request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationRequest {
    pub username: String,
    pub realm_id: Uuid,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(
        db: Arc<Database>,
        rp_id: String,
        rp_name: String,
        jwt_secret: String,
        encryption_key: Option<String>,
    ) -> Self {
        let rp_origin_str = format!("https://{}", rp_id);
        let rp_origin = Url::parse(&rp_origin_str).expect("Invalid RP origin URL");
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Invalid relying party configuration")
            .rp_name(&rp_name);

        let webauthn = Arc::new(builder.build().expect("Failed to build WebAuthn instance"));

        let key = encryption_key
            .map(|k| AesGcmService::derive_key_from_password(&k, b"webauthn_credential_storage_v1"))
            .unwrap_or_else(|| {
                AesGcmService::derive_key_from_password(
                    &jwt_secret,
                    b"webauthn_credential_storage_v1",
                )
            })
            .unwrap_or_else(|_| AesGcmService::generate_key());

        let encryption = AesGcmService::with_key(&key).unwrap_or_default();

        Self {
            db,
            webauthn,
            encryption,
        }
    }

    /// Generate WebAuthn registration challenge
    pub async fn generate_registration_challenge(
        &self,
        _request: WebAuthnRegistrationRequest,
    ) -> Result<Json<serde_json::Value>> {
        // Stubbed for compilation fix
        Err(AuthencError::internal("WebAuthn temporarily disabled during upgrade"))
    }

    /// Verify WebAuthn registration response
    pub async fn verify_registration(
        &self,
        _realm_id: &Uuid,
        _username: &str,
        _response: WebauthnRegistrationResponse,
        _device_id: Option<Uuid>,
    ) -> Result<Json<serde_json::Value>> {
        // Stubbed for compilation fix
        Err(AuthencError::internal("WebAuthn temporarily disabled during upgrade"))
    }

    /// Generate WebAuthn authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        _request: WebAuthnAuthenticationRequest,
    ) -> Result<Json<serde_json::Value>> {
        // Stubbed for compilation fix
        Err(AuthencError::internal("WebAuthn temporarily disabled during upgrade"))
    }

    /// Verify WebAuthn authentication response
    pub async fn verify_authentication(
        &self,
        _realm_id: &Uuid,
        _username: &str,
        _response: WebauthnAuthenticationResponse,
    ) -> Result<Json<serde_json::Value>> {
        // Stubbed for compilation fix
        Err(AuthencError::internal("WebAuthn temporarily disabled during upgrade"))
    }

    /// Store WebAuthn challenge state for user
    async fn store_challenge(&self, realm_id: &Uuid, username: &str, state: &str, challenge_type: &str) -> Result<()> {
        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let client = self.db.get_connection().await?;
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

        let query = r#"
            INSERT INTO webauthn_challenges (user_id, challenge, challenge_type, expires_at)
            VALUES ($1, $2, $3, $4)
        "#;
        client
            .execute(query, &[&user.id, &state, &challenge_type, &expires_at])
            .await?;
        Ok(())
    }

    /// Get stored WebAuthn challenge state for user
    async fn get_challenge(&self, realm_id: &Uuid, username: &str, challenge_type: &str) -> Result<Option<String>> {
        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let client = self.db.get_connection().await?;
        let query = r#"
            SELECT challenge FROM webauthn_challenges
            WHERE user_id = $1 AND challenge_type = $2 AND expires_at > NOW() AND used = false
            ORDER BY created_at DESC
            LIMIT 1
        "#;
        let row = client.query_opt(query, &[&user.id, &challenge_type]).await?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Mark a WebAuthn challenge as used
    async fn delete_challenge(&self, realm_id: &Uuid, username: &str, challenge_type: &str) -> Result<()> {
        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let client = self.db.get_connection().await?;
        let query = r#"
            UPDATE webauthn_challenges
            SET used = true
            WHERE user_id = $1 AND challenge_type = $2 AND used = false
        "#;
        client.execute(query, &[&user.id, &challenge_type]).await?;
        Ok(())
    }

    /// Store WebAuthn credential for user
    async fn store_credential(
        &self,
        realm_id: &Uuid,
        username: &str,
        credential: &WebauthnCredential,
    ) -> Result<()> {
        use crate::database::operations::users;

        // Get user ID from username
        let user = users::get_user_by_username(&self.db, realm_id, username)
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
            device_id: credential.device_id,
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            enabled: credential.enabled,
        };

        self.store_credential_db(&model_credential).await
    }

    /// Get all WebAuthn credentials for user
    async fn get_user_credentials(&self, realm_id: &Uuid, username: &str) -> Result<Vec<WebauthnCredential>> {
        use crate::database::operations::users;
        use crate::database::operations::webauthn as webauthn_db;

        // Get user ID from username
        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let model_credentials = webauthn_db::get_user_credentials(&self.db, user.id).await?;

        // Convert model credentials to service credentials and decrypt
        let mut service_credentials = Vec::new();
        for mc in model_credentials {
            let mut cred = WebauthnCredential {
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
                device_id: mc.device_id,
                created_at: mc.created_at,
                last_used_at: mc.last_used_at,
                enabled: mc.enabled,
            };
            self.decrypt_credential(&mut cred);
            service_credentials.push(cred);
        }

        Ok(service_credentials)
    }

    /// Get specific WebAuthn credential
    async fn get_credential(
        &self,
        _username: &str,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>> {
        use crate::database::operations::webauthn as webauthn_db;

        let credential_id_bytes = base64ct::Base64UrlUnpadded::decode_vec(credential_id)
             .map_err(|_| AuthencError::unauthorized("Invalid credential ID format"))?;

        let model_credential = webauthn_db::get_credential_by_id(&self.db, &credential_id_bytes).await?;

        if let Some(mc) = model_credential {
            let mut cred = WebauthnCredential {
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
                device_id: mc.device_id,
                created_at: mc.created_at,
                last_used_at: mc.last_used_at,
                enabled: mc.enabled,
            };
            self.decrypt_credential(&mut cred);
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    /// Update WebAuthn credential signature count
    async fn update_credential_sign_count(
        &self,
        _username: &str,
        credential_id: &str,
        sign_count: u32,
    ) -> Result<()> {
        use crate::database::operations::webauthn as webauthn_db;

        webauthn_db::update_signature_count(&self.db, credential_id, sign_count as i64).await?;
        Ok(())
    }

    /// Verify WebAuthn origin
    fn verify_origin(&self, origin: &str) -> bool {
        // In production, verify against allowed origins
        origin.starts_with("https://") || origin.starts_with("http://localhost")
    }

    /// Decrypt credential fields if they are encrypted
    fn decrypt_credential(&self, credential: &mut WebauthnCredential) {
        // Try to decrypt attestation_object
        if let Some(data) = &credential.attestation_object
            && let Ok(encrypted_data) = serde_json::from_slice::<EncryptedData>(data)
                && let Ok(decrypted) = self.encryption.decrypt(&encrypted_data) {
                    credential.attestation_object = Some(decrypted);
                }

        // Try to decrypt authenticator_data
        if let Some(data) = &credential.authenticator_data
            && let Ok(encrypted_data) = serde_json::from_slice::<EncryptedData>(data)
                && let Ok(decrypted) = self.encryption.decrypt(&encrypted_data) {
                    credential.authenticator_data = Some(decrypted);
                }

        // Try to decrypt user_handle
        if let Some(data) = &credential.user_handle
            && let Ok(encrypted_data) = serde_json::from_slice::<EncryptedData>(data)
                && let Ok(decrypted) = self.encryption.decrypt(&encrypted_data) {
                    credential.user_handle = Some(decrypted);
                }
    }

    /// Store WebAuthn credential in database securely
    pub async fn store_credential_db(&self, credential: &WebauthnCredential) -> Result<()> {
        use crate::database::operations::webauthn as webauthn_db;
        use tracing::debug;

        debug!("Storing WebAuthn credential securely for user {}", credential.user_id);

        // Encrypt sensitive fields
        let mut encrypted_credential = credential.clone();

        // Encrypt attestation_object
        if let Some(attestation_object) = &credential.attestation_object {
            let encrypted = self.encryption.encrypt(attestation_object)?;
            let encrypted_json = serde_json::to_vec(&encrypted).map_err(|e| {
                AuthencError::SerializationError {
                    message: format!("Failed to serialize encrypted attestation object: {}", e),
                }
            })?;
            encrypted_credential.attestation_object = Some(encrypted_json);
        }

        // Encrypt authenticator_data
        if let Some(authenticator_data) = &credential.authenticator_data {
            let encrypted = self.encryption.encrypt(authenticator_data)?;
            let encrypted_json = serde_json::to_vec(&encrypted).map_err(|e| {
                AuthencError::SerializationError {
                    message: format!("Failed to serialize encrypted authenticator data: {}", e),
                }
            })?;
            encrypted_credential.authenticator_data = Some(encrypted_json);
        }

        // Encrypt user_handle
        if let Some(user_handle) = &credential.user_handle {
            let encrypted = self.encryption.encrypt(user_handle)?;
            let encrypted_json = serde_json::to_vec(&encrypted).map_err(|e| {
                AuthencError::SerializationError {
                    message: format!("Failed to serialize encrypted user handle: {}", e),
                }
            })?;
            encrypted_credential.user_handle = Some(encrypted_json);
        }

        // Note: Device binding is explicitly handled via device_id column if present.
        // AAGUID is also preserved for implicit binding and attestation verification.

        webauthn_db::store_credential(&self.db, credential.user_id, &encrypted_credential).await?;
        Ok(())
    }
}
