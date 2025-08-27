use crate::database::Database;
use crate::error::{AuthencError, Result};
use crate::models::webauthn::*;
use crate::utils::crypto_monitor::CryptoMonitor;
use axum::response::Json;
use base64ct::{Base64UrlUnpadded, Encoding};
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
        let challenge_bytes = CryptoMonitor::monitor_rsa_operation("webauthn_challenge_gen", || {
            let mut challenge = [0u8; 32];
            getrandom::getrandom(&mut challenge).expect("Failed to generate random challenge");
            challenge
        });

        let challenge_b64 = Base64UrlUnpadded::encode_string(&challenge_bytes);

        // Create user ID
        let user_id = Uuid::new_v4().as_bytes().to_vec();

        let registration_challenge = WebAuthnRegistrationChallenge {
            challenge: challenge_b64,
            rp: RelyingParty {
                id: self.relying_party_id.clone(),
                name: self.relying_party_name.clone(),
            },
            user: WebAuthnUser {
                id: user_id,
                name: request.username.clone(),
                display_name: request.display_name,
            },
            pub_key_cred_params: vec![
                PubKeyCredParam {
                    alg: -7, // ES256
                    typ: "public-key".to_string(),
                },
                PubKeyCredParam {
                    alg: -257, // RS256
                    typ: "public-key".to_string(),
                },
                PubKeyCredParam {
                    alg: -8, // EdDSA
                    typ: "public-key".to_string(),
                },
            ],
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some("cross-platform".to_string()),
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
            extensions: None,
        };

        // Store challenge in database for verification
        self.store_challenge(&request.username, &challenge_bytes).await?;

        Ok(Json(serde_json::to_value(registration_challenge).unwrap()))
    }

    /// Verify WebAuthn registration response
    pub async fn verify_registration(
        &self,
        username: &str,
        response: WebAuthnRegistrationResponse,
    ) -> Result<Json<serde_json::Value>> {
        // Retrieve stored challenge
        let stored_challenge = self.get_challenge(username).await?
            .ok_or_else(|| AuthencError::unauthorized("No challenge found for user"))?;

        // Decode client data JSON
        let client_data_json: serde_json::Value = serde_json::from_slice(&response.response.client_data_json)
            .map_err(|_| AuthencError::unauthorized("Invalid client data JSON"))?;

        // Verify challenge
        let challenge_b64 = client_data_json["challenge"].as_str()
            .ok_or_else(|| AuthencError::unauthorized("Missing challenge in client data"))?;

        if challenge_b64 != Base64UrlUnpadded::encode_string(&stored_challenge) {
            return Err(AuthencError::unauthorized("Challenge mismatch"));
        }

        // Verify origin
        let origin = client_data_json["origin"].as_str()
            .ok_or_else(|| AuthencError::unauthorized("Missing origin in client data"))?;

        if !self.verify_origin(origin) {
            return Err(AuthencError::unauthorized("Origin verification failed"));
        }

        // Parse attestation object (simplified - in production would need full CBOR parsing)
        // For now, we'll create a mock credential
        let credential = WebAuthnCredential {
            id: response.id,
            public_key: vec![], // Would be extracted from attestation object
            sign_count: 0,
            user_handle: vec![],
            credential_type: "public-key".to_string(),
            transports: vec![],
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
            return Err(AuthencError::unauthorized("No WebAuthn credentials found for user"));
        }

        // Generate challenge
        let challenge_bytes = CryptoMonitor::monitor_rsa_operation("webauthn_auth_challenge", || {
            let mut challenge = [0u8; 32];
            getrandom::getrandom(&mut challenge).expect("Failed to generate random challenge");
            challenge
        });

        let challenge_b64 = Base64UrlUnpadded::encode_string(&challenge_bytes);

        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = credentials
            .iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                id: Base64UrlUnpadded::decode_vec(&cred.id).unwrap_or_default(),
                typ: "public-key".to_string(),
                transports: Some(vec!["usb".to_string(), "nfc".to_string(), "ble".to_string()]),
            })
            .collect();

        let auth_challenge = WebAuthnAuthenticationChallenge {
            challenge: challenge_b64,
            allow_credentials,
            user_verification: Some("preferred".to_string()),
            extensions: None,
        };

        // Store challenge
        self.store_challenge(&request.username, &challenge_bytes).await?;

        Ok(Json(serde_json::to_value(auth_challenge).unwrap()))
    }

    /// Verify WebAuthn authentication response
    pub async fn verify_authentication(
        &self,
        username: &str,
        response: WebAuthnAuthenticationResponse,
    ) -> Result<Json<serde_json::Value>> {
        // Retrieve stored challenge
        let stored_challenge = self.get_challenge(username).await?
            .ok_or_else(|| AuthencError::unauthorized("No challenge found for user"))?;

        // Decode client data JSON
        let client_data_json: serde_json::Value = serde_json::from_slice(&response.response.client_data_json)
            .map_err(|_| AuthencError::unauthorized("Invalid client data JSON"))?;

        // Verify challenge
        let challenge_b64 = client_data_json["challenge"].as_str()
            .ok_or_else(|| AuthencError::unauthorized("Missing challenge in client data"))?;

        if challenge_b64 != Base64UrlUnpadded::encode_string(&stored_challenge) {
            return Err(AuthencError::unauthorized("Challenge mismatch"));
        }

        // Get credential
        let credential = self.get_credential(username, &response.id).await?
            .ok_or_else(|| AuthencError::unauthorized("Credential not found"))?;

        // Verify signature (simplified - in production would verify against public key)
        // This is where you'd implement the actual cryptographic verification

        // Update sign count
        self.update_credential_sign_count(username, &response.id, response.response.authenticator_data.len() as u32).await?;

        // Remove used challenge
        self.delete_challenge(username).await?;

        Ok(Json(serde_json::json!({
            "success": true,
            "message": "WebAuthn authentication successful",
            "user": username
        })))
    }

    // Database operations (simplified - would need proper implementation)
    async fn store_challenge(&self, username: &str, challenge: &[u8]) -> Result<()> {
        // In production, store in database with expiration
        Ok(())
    }

    async fn get_challenge(&self, username: &str) -> Result<Option<Vec<u8>>> {
        // In production, retrieve from database
        Ok(Some(vec![]))
    }

    async fn delete_challenge(&self, username: &str) -> Result<()> {
        // In production, delete from database
        Ok(())
    }

    async fn store_credential(&self, username: &str, credential: &WebAuthnCredential) -> Result<()> {
        // In production, store in database
        Ok(())
    }

    async fn get_user_credentials(&self, username: &str) -> Result<Vec<WebAuthnCredential>> {
        // In production, retrieve from database
        Ok(vec![])
    }

    async fn get_credential(&self, username: &str, credential_id: &str) -> Result<Option<WebAuthnCredential>> {
        // In production, retrieve from database
        Ok(None)
    }

    async fn update_credential_sign_count(&self, username: &str, credential_id: &str, sign_count: u32) -> Result<()> {
        // In production, update in database
        Ok(())
    }

    fn verify_origin(&self, origin: &str) -> bool {
        // In production, verify against allowed origins
        origin.starts_with("https://") || origin.starts_with("http://localhost")
    }
}
