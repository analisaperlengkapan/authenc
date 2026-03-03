use authenc_crypto::crypto::aes_gcm::{AesGcmService, EncryptedData};
use authenc_database::database::operations::users;
use authenc_database::database::Database;
use authenc_core::error::{AuthencError, Result};
use authenc_models::models::webauthn::{WebauthnCredential, WebauthnAuthenticationResponse, WebauthnRegistrationResponse};
use axum::response::Json;
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CredentialID, Passkey, RegisterPublicKeyCredential, PublicKeyCredential,
    PasskeyAuthentication, PasskeyRegistration
};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use dashmap::DashMap;
use chrono::{DateTime, Duration, Utc};

// Import proto types if not in prelude
// use webauthn_rs_proto::{AuthenticatorAttestationResponse, AuthenticatorAssertionResponse};

/// WebAuthn service for FIDO2 authentication
pub struct WebAuthnService {
    db: Arc<Database>,
    webauthn: Arc<Webauthn>,
    encryption: AesGcmService,
    // In-memory cache for states because serialization is problematic in current environment
    auth_states: Arc<DashMap<String, (PasskeyAuthentication, DateTime<Utc>)>>,
    reg_states: Arc<DashMap<String, (PasskeyRegistration, DateTime<Utc>)>>,
}

/// WebAuthn registration request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationRequest {
    pub username: String,
    pub display_name: String,
    pub realm_id: String,
}

/// WebAuthn authentication request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationRequest {
    pub username: String,
    pub realm_id: String,
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
            auth_states: Arc::new(DashMap::new()),
            reg_states: Arc::new(DashMap::new()),
        }
    }

    /// Generate WebAuthn registration challenge
    pub async fn generate_registration_challenge(
        &self,
        request: WebAuthnRegistrationRequest,
    ) -> Result<Json<serde_json::Value>> {
        let parsed_realm = if request.realm_id == "master" {
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
        } else {
            Uuid::parse_str(&request.realm_id).map_err(|_| AuthencError::validation("Invalid realm_id"))?
        };

        let user = users::get_user_by_username(&self.db, &parsed_realm, &request.username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let exclude_credentials: Option<Vec<CredentialID>> = None;

        let (challenge, state) = self.webauthn
            .start_passkey_registration(
                user.id,
                &request.username,
                &request.display_name,
                exclude_credentials,
            )
            .map_err(|e| AuthencError::internal(format!("Failed to start registration: {}", e)))?;

        let key = format!("reg:{}:{}", parsed_realm, request.username);
        self.reg_states.insert(key.clone(), (state, Utc::now()));

        // Cleanup expired states lazily (probabilistic: 1 in 100)
        if rand::random::<u8>() % 100 == 0 {
            self.cleanup_expired_states();
        }

        Ok(Json(serde_json::to_value(challenge).unwrap()))
    }

    /// Cleanup expired authentication/registration states
    fn cleanup_expired_states(&self) {
        let now = Utc::now();
        let ttl = Duration::minutes(5);

        // Remove items older than TTL
        self.auth_states.retain(|_, (_, timestamp)| *timestamp + ttl > now);
        self.reg_states.retain(|_, (_, timestamp)| *timestamp + ttl > now);
    }

    /// Verify WebAuthn registration response
    pub async fn verify_registration(
        &self,
        realm_id: &Uuid,
        username: &str,
        response: WebauthnRegistrationResponse,
        device_id: Option<Uuid>,
    ) -> Result<Json<serde_json::Value>> {
        let key = format!("reg:{}:{}", realm_id, username);
        // DashMap remove returns Option<(K, V)>
        let (_, (state, _)) = self.reg_states.remove(&key)
            .ok_or_else(|| AuthencError::validation("Challenge not found or expired"))?;

        // Convert our response model to webauthn-rs model via JSON round-trip
        // This avoids needing to access private/unexported types from webauthn-rs
        let response_value = serde_json::to_value(&response)
            .map_err(|e| AuthencError::validation(format!("Invalid response format: {}", e)))?;

        let reg_response: RegisterPublicKeyCredential = serde_json::from_value(response_value)
            .map_err(|e| AuthencError::validation(format!("Invalid WebAuthn response structure: {}", e)))?;

        // finish_passkey_registration is sync in 0.5
        let passkey = self.webauthn
            .finish_passkey_registration(&reg_response, &state)
            .map_err(|e| AuthencError::validation(format!("Registration verification failed: {}", e)))?;

        // Serialize the passkey to JSON for storage
        let passkey_json = serde_json::to_string(&passkey)
             .map_err(|e| AuthencError::internal(format!("Failed to serialize passkey: {}", e)))?;

        let cred_model = WebauthnCredential {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(), // Placeholder, updated in store_credential
            credential_id: Into::<Vec<u8>>::into(passkey.cred_id().clone()),
            public_key: Vec::new(),
            public_key_algorithm: -7,
            signature_counter: 0,
            attestation_object: Some(passkey_json.into_bytes()), // Store JSON here!
            authenticator_data: None,
            user_handle: None,
            credential_type: "public-key".to_string(),
            transports: None,
            aaguid: None,
            attestation_format: Some("packed".to_string()),
            device_id,
            created_at: chrono::Utc::now(),
            last_used_at: Some(chrono::Utc::now()),
            enabled: true,
        };

        self.store_credential(realm_id, username, &cred_model).await?;

        info!("WebAuthn registration successful for user: {}", username);
        Ok(Json(serde_json::json!({"status": "registered"})))
    }

    /// Generate WebAuthn authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        request: WebAuthnAuthenticationRequest,
    ) -> Result<Json<serde_json::Value>> {
        let parsed_realm = if request.realm_id == "master" {
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
        } else {
            Uuid::parse_str(&request.realm_id).map_err(|_| AuthencError::validation("Invalid realm_id"))?
        };

        let credentials = self.get_user_credentials(&parsed_realm, &request.username).await?;

        if credentials.is_empty() {
            return Err(AuthencError::resource_not_found("No credentials found for user"));
        }

        let mut allow_credentials = Vec::new();
        for c in credentials {
            if let Some(json_bytes) = c.attestation_object {
                 if let Ok(passkey) = serde_json::from_slice::<Passkey>(&json_bytes) {
                     allow_credentials.push(passkey);
                 }
            }
        }

        if allow_credentials.is_empty() {
             return Err(AuthencError::internal("No valid WebAuthn credentials found (migration required?)"));
        }

        let (challenge, state) = self.webauthn
            .start_passkey_authentication(&allow_credentials)
            .map_err(|e| AuthencError::internal(format!("Failed to start authentication: {}", e)))?;

        // Store state in memory
        let key = format!("auth:{}:{}", parsed_realm, request.username);
        self.auth_states.insert(key, (state, Utc::now()));

        // Cleanup expired states lazily (probabilistic: 1 in 100)
        if rand::random::<u8>() % 100 == 0 {
            self.cleanup_expired_states();
        }

        Ok(Json(serde_json::to_value(challenge).unwrap()))
    }

    /// Verify WebAuthn authentication response
    pub async fn verify_authentication(
        &self,
        realm_id: &Uuid,
        username: &str,
        response: WebauthnAuthenticationResponse,
    ) -> Result<Json<serde_json::Value>> {
        let key = format!("auth:{}:{}", realm_id, username);
        let (_, (state, _)) = self.auth_states.remove(&key)
            .ok_or_else(|| AuthencError::validation("Challenge not found or expired"))?;

        // Convert our response model to webauthn-rs model via JSON round-trip
        let response_value = serde_json::to_value(&response)
            .map_err(|e| AuthencError::validation(format!("Invalid response format: {}", e)))?;

        let auth_response: PublicKeyCredential = serde_json::from_value(response_value)
            .map_err(|e| AuthencError::validation(format!("Invalid WebAuthn response structure: {}", e)))?;

        // finish_passkey_authentication is sync in 0.5
        let auth_result = self.webauthn
            .finish_passkey_authentication(&auth_response, &state)
            .map_err(|e| AuthencError::validation(format!("Authentication verification failed: {}", e)))?;

        // Update signature counter
        let cred_id_bytes: Vec<u8> = auth_result.cred_id().clone().into();
        // Note: auth_result.counter() might be needed if field is private, but checking docs showed it's usually accessible or method.
        // Assuming .counter() method exists based on previous errors.
        self.update_credential_sign_count(username, &cred_id_bytes, auth_result.counter()).await?;

        info!("WebAuthn authentication successful for user: {}", username);
        Ok(Json(serde_json::json!({"status": "authenticated"})))
    }

    /// Store WebAuthn credential for user
    async fn store_credential(
        &self,
        realm_id: &Uuid,
        username: &str,
        credential: &WebauthnCredential,
    ) -> Result<()> {
        use authenc_database::database::operations::users;

        // Get user ID from username
        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        // Convert service credential to model credential
        let model_credential = authenc_models::models::webauthn::WebauthnCredential {
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
        use authenc_database::database::operations::users;
        use authenc_database::database::operations::webauthn as webauthn_db;

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
        use authenc_database::database::operations::webauthn as webauthn_db;

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
        credential_id: &[u8],
        sign_count: u32,
    ) -> Result<()> {
        use authenc_database::database::operations::webauthn as webauthn_db;

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
        use authenc_database::database::operations::webauthn as webauthn_db;
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

    /// Delete all WebAuthn credentials for a user
    pub async fn delete_user_credentials(&self, user_id: Uuid) -> Result<()> {
        use authenc_database::database::operations::webauthn as webauthn_db;
        webauthn_db::delete_user_credentials(&self.db, user_id).await?;
        Ok(())
    }
}
