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

/// WebAuthn service for FIDO2 authentication
pub struct WebAuthnService {
    db: Arc<Database>,
    webauthn: Arc<Webauthn>,
    encryption: AesGcmService,
    // In-memory cache for states
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
            Uuid::nil()
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

        let key = format!("reg:{}:{}", request.realm_id, request.username);
        self.reg_states.insert(key.clone(), (state, Utc::now()));

        Ok(Json(serde_json::to_value(challenge).unwrap()))
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
        let (_, (state, _)) = self.reg_states.remove(&key)
            .ok_or_else(|| AuthencError::validation("Challenge not found or expired"))?;

        let response_value = serde_json::to_value(&response)
            .map_err(|e| AuthencError::validation(format!("Invalid response format: {}", e)))?;

        let reg_response: RegisterPublicKeyCredential = serde_json::from_value(response_value)
            .map_err(|e| AuthencError::validation(format!("Invalid WebAuthn response structure: {}", e)))?;

        let passkey = self.webauthn
            .finish_passkey_registration(&reg_response, &state)
            .map_err(|e| AuthencError::validation(format!("Registration verification failed: {}", e)))?;

        let passkey_json = serde_json::to_string(&passkey)
             .map_err(|e| AuthencError::internal(format!("Failed to serialize passkey: {}", e)))?;

        let cred_model = WebauthnCredential {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            credential_id: Into::<Vec<u8>>::into(passkey.cred_id().clone()),
            public_key: Vec::new(),
            public_key_algorithm: -7,
            signature_counter: 0,
            attestation_object: Some(passkey_json.into_bytes()),
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
            name: None,
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
            Uuid::nil()
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
             return Err(AuthencError::internal("No valid WebAuthn credentials found"));
        }

        let (challenge, state) = self.webauthn
            .start_passkey_authentication(&allow_credentials)
            .map_err(|e| AuthencError::internal(format!("Failed to start authentication: {}", e)))?;

        let key = format!("auth:{}:{}", request.realm_id, request.username);
        self.auth_states.insert(key, (state, Utc::now()));

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

        let response_value = serde_json::to_value(&response)
            .map_err(|e| AuthencError::validation(format!("Invalid response format: {}", e)))?;

        let auth_response: PublicKeyCredential = serde_json::from_value(response_value)
            .map_err(|e| AuthencError::validation(format!("Invalid WebAuthn response structure: {}", e)))?;

        let auth_result = self.webauthn
            .finish_passkey_authentication(&auth_response, &state)
            .map_err(|e| AuthencError::validation(format!("Authentication verification failed: {}", e)))?;

        let cred_id_bytes: Vec<u8> = auth_result.cred_id().clone().into();
        self.update_credential_sign_count(username, &cred_id_bytes, auth_result.counter()).await?;

        info!("WebAuthn authentication successful for user: {}", username);
        Ok(Json(serde_json::json!({"status": "authenticated"})))
    }

    async fn store_credential(
        &self,
        realm_id: &Uuid,
        username: &str,
        credential: &WebauthnCredential,
    ) -> Result<()> {
        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let mut model_credential = credential.clone();
        model_credential.user_id = user.id;

        self.store_credential_db(&model_credential).await
    }

    pub async fn get_user_credentials(&self, realm_id: &Uuid, username: &str) -> Result<Vec<WebauthnCredential>> {
        use authenc_database::database::operations::webauthn as webauthn_db;

        let user = users::get_user_by_username(&self.db, realm_id, username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

        let model_credentials = webauthn_db::get_user_credentials(&self.db, user.id).await?;

        let mut service_credentials = Vec::new();
        for mut mc in model_credentials {
            self.decrypt_credential(&mut mc);
            service_credentials.push(mc);
        }

        Ok(service_credentials)
    }

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

    fn decrypt_credential(&self, credential: &mut WebauthnCredential) {
        if let Some(data) = &credential.attestation_object {
            if let Ok(encrypted_data) = serde_json::from_slice::<EncryptedData>(data) {
                if let Ok(decrypted) = self.encryption.decrypt(&encrypted_data) {
                    credential.attestation_object = Some(decrypted);
                }
            }
        }
    }

    pub async fn store_credential_db(&self, credential: &WebauthnCredential) -> Result<()> {
        use authenc_database::database::operations::webauthn as webauthn_db;
        let mut encrypted_credential = credential.clone();

        if let Some(attestation_object) = &credential.attestation_object {
            let encrypted = self.encryption.encrypt(attestation_object)?;
            let encrypted_json = serde_json::to_vec(&encrypted).map_err(|e| {
                AuthencError::internal(format!("Failed to serialize encrypted attestation object: {}", e))
            })?;
            encrypted_credential.attestation_object = Some(encrypted_json);
        }

        webauthn_db::store_credential(&self.db, credential.user_id, &encrypted_credential).await?;
        Ok(())
    }

    pub async fn delete_user_credentials(&self, user_id: Uuid) -> Result<()> {
        use authenc_database::database::operations::webauthn as webauthn_db;
        webauthn_db::delete_user_credentials(&self.db, user_id).await?;
        Ok(())
    }

    pub async fn list_user_credentials(
        &self,
        _realm_id: &Uuid,
        user_id: &Uuid,
    ) -> Result<Vec<WebauthnCredential>> {
        use authenc_database::database::operations::webauthn as webauthn_db;
        let model_credentials = webauthn_db::get_user_credentials(&self.db, *user_id).await?;

        let mut service_credentials = Vec::new();
        for mut mc in model_credentials {
            self.decrypt_credential(&mut mc);
            service_credentials.push(mc);
        }
        Ok(service_credentials)
    }

    pub async fn delete_credential(
        &self,
        _realm_id: &Uuid,
        user_id: &Uuid,
        credential_id: &Uuid,
    ) -> Result<()> {
        use authenc_database::database::operations::webauthn as webauthn_db;
        webauthn_db::delete_credential(&self.db, credential_id, user_id).await
    }

    pub async fn update_credential_name(
        &self,
        _realm_id: &Uuid,
        user_id: &Uuid,
        credential_id: &Uuid,
        name: &str,
    ) -> Result<()> {
        use authenc_database::database::operations::webauthn as webauthn_db;
        webauthn_db::update_credential_name(&self.db, credential_id, user_id, name).await
    }
}
