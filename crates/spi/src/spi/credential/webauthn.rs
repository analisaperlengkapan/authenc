//! WebAuthn Credential Provider Implementation
//!
//! Provides passwordless authentication using FIDO2/WebAuthn standards.

use super::{
    CredentialInput, CredentialInputUpdater, CredentialInputValidator, CredentialModel,
    CredentialTypeCategory, CredentialTypeMetadata,
};
use authenc_core::error::{AuthencError as Error, Result};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// WebAuthn credential type identifier
pub const WEBAUTHN_CREDENTIAL_TYPE: &str = "webauthn";

/// WebAuthn credential data stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredentialData {
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// Public key in COSE format (base64url encoded)
    pub public_key: String,
    /// Signature counter (for replay detection)
    pub counter: u32,
    /// Authenticator AAGUID (Authenticator Attestation GUID)
    pub aaguid: Option<String>,
    /// Authenticator attestation format
    pub attestation_format: Option<String>,
    /// Transports supported (usb, nfc, ble, internal)
    pub transports: Vec<String>,
    /// Credential creation timestamp
    pub created_at: i64,
    /// Last used timestamp
    pub last_used_at: Option<i64>,
}

/// WebAuthn registration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationOptions {
    /// Relying Party ID (typically the domain)
    pub rp_id: String,
    /// Relying Party name
    pub rp_name: String,
    /// User ID (opaque identifier)
    pub user_id: String,
    /// User display name
    pub user_name: String,
    /// User email or username
    pub user_display_name: String,
    /// Challenge (base64url encoded random bytes)
    pub challenge: String,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// Attestation preference (none, indirect, direct)
    pub attestation: String,
    /// Authenticator attachment (platform, cross-platform, null)
    pub authenticator_attachment: Option<String>,
    /// Require resident key
    pub require_resident_key: bool,
    /// User verification requirement (required, preferred, discouraged)
    pub user_verification: String,
    /// Existing credentials to exclude
    pub excluded_credentials: Vec<String>,
}

/// WebAuthn authentication options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationOptions {
    /// Relying Party ID
    pub rp_id: String,
    /// Challenge (base64url encoded random bytes)
    pub challenge: String,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// User verification requirement
    pub user_verification: String,
    /// Allowed credentials
    pub allowed_credentials: Vec<WebAuthnAllowedCredential>,
}

/// Allowed credential for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAllowedCredential {
    /// Credential ID (base64url encoded)
    pub id: String,
    /// Transports (usb, nfc, ble, internal)
    pub transports: Vec<String>,
}

/// Input data for WebAuthn authentication verification
#[derive(Debug)]
pub struct WebAuthnVerificationInput<'a> {
    /// Challenge (base64url encoded random bytes)
    pub challenge: &'a str,
    /// Credential ID (base64url encoded)
    pub credential_id: &'a str,
    /// Public key in COSE format (base64url encoded)
    pub public_key: &'a str,
    /// Signature counter (for replay detection)
    pub counter: u32,
    /// Client data JSON (base64url encoded)
    pub client_data_json: &'a str,
    /// Authenticator data (base64url encoded)
    pub authenticator_data: &'a str,
    /// Signature (base64url encoded)
    pub signature: &'a str,
}

/// WebAuthn credential provider
pub struct WebAuthnCredentialProvider {
    /// Relying party ID (domain)
    rp_id: String,
    /// Relying party name
    rp_name: String,
    /// Require user verification
    require_user_verification: bool,
}

impl WebAuthnCredentialProvider {
    /// Create a new WebAuthn credential provider
    pub fn new(rp_id: String, rp_name: String) -> Self {
        Self {
            rp_id,
            rp_name,
            require_user_verification: true,
        }
    }

    /// Generate a new challenge for registration or authentication
    pub fn generate_challenge(&self) -> Result<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let challenge_bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        Ok(URL_SAFE_NO_PAD.encode(&challenge_bytes))
    }

    /// Create registration options for a user
    pub fn create_registration_options(
        &self,
        user_id: &str,
        user_name: &str,
        user_display_name: &str,
        existing_credentials: Vec<String>,
    ) -> Result<WebAuthnRegistrationOptions> {
        Ok(WebAuthnRegistrationOptions {
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            user_id: user_id.to_string(),
            user_name: user_name.to_string(),
            user_display_name: user_display_name.to_string(),
            challenge: self.generate_challenge()?,
            timeout: 60000,                  // 60 seconds
            attestation: "none".to_string(), // "none", "indirect", or "direct"
            authenticator_attachment: None,  // Allow both platform and cross-platform
            require_resident_key: false,
            user_verification: if self.require_user_verification {
                "required"
            } else {
                "preferred"
            }
            .to_string(),
            excluded_credentials: existing_credentials,
        })
    }

    /// Create authentication options for a user
    pub fn create_authentication_options(
        &self,
        allowed_credentials: Vec<WebAuthnAllowedCredential>,
    ) -> Result<WebAuthnAuthenticationOptions> {
        Ok(WebAuthnAuthenticationOptions {
            rp_id: self.rp_id.clone(),
            challenge: self.generate_challenge()?,
            timeout: 60000,
            user_verification: if self.require_user_verification {
                "required"
            } else {
                "preferred"
            }
            .to_string(),
            allowed_credentials,
        })
    }

    /// Verify WebAuthn registration response
    pub async fn verify_registration(
        &self,
        _challenge: &str,
        _credential_data: &WebAuthnCredentialData,
        _client_data_json: &str,
        _attestation_object: &str,
    ) -> Result<bool> {
        // In a full implementation, this would:
        // 1. Verify the challenge matches
        // 2. Verify the origin matches the RP ID
        // 3. Verify the attestation signature
        // 4. Extract and validate the public key
        // 5. Store the credential in the database

        // For now, return success placeholder
        // Real implementation would use webauthn-rs or similar library
        Ok(true)
    }

    /// Verify WebAuthn authentication response
    pub async fn verify_authentication(
        &self,
        _input: WebAuthnVerificationInput<'_>,
    ) -> Result<bool> {
        // In a full implementation, this would:
        // 1. Verify the challenge matches
        // 2. Verify the origin and RP ID hash
        // 3. Verify the user present flag
        // 4. Verify the user verification flag if required
        // 5. Verify the signature using the stored public key
        // 6. Verify and update the signature counter (replay protection)

        // For now, return success placeholder
        // Real implementation would use webauthn-rs or similar library
        Ok(true)
    }

    /// Get authenticator metadata by AAGUID
    pub fn get_authenticator_metadata(&self, aaguid: &str) -> Option<AuthenticatorMetadata> {
        // In a full implementation, this would look up the AAGUID in the
        // FIDO Metadata Service (MDS) to get authenticator details
        // For now, return a placeholder
        Some(AuthenticatorMetadata {
            aaguid: aaguid.to_string(),
            description: "Unknown Authenticator".to_string(),
            icon: None,
        })
    }

    /// Get credential type metadata
    pub fn get_metadata(&self) -> CredentialTypeMetadata {
        CredentialTypeMetadata {
            credential_type: WEBAUTHN_CREDENTIAL_TYPE.to_string(),
            display_name: "Security Key".to_string(),
            help_text: Some("Use a FIDO2 security key, fingerprint, face recognition, or other biometric authentication.".to_string()),
            create_help_text: Some("Follow your browser's instructions to register your security key or biometric authenticator.".to_string()),
            category: CredentialTypeCategory::Passwordless,
            display_icon_classes: Some("fa fa-key".to_string()),
            properties: vec![],
        }
    }
}

/// Authenticator metadata from FIDO MDS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorMetadata {
    /// AAGUID
    pub aaguid: String,
    /// Human-readable description
    pub description: String,
    /// Icon URL
    pub icon: Option<String>,
}

#[async_trait]
impl CredentialInputValidator for WebAuthnCredentialProvider {
    fn supports_credential_type(&self, credential_type: &str) -> bool {
        credential_type == WEBAUTHN_CREDENTIAL_TYPE
    }

    async fn is_configured_for(
        &self,
        _realm_id: &str,
        _user_id: &str,
        credential_type: &str,
    ) -> Result<bool> {
        Ok(credential_type == WEBAUTHN_CREDENTIAL_TYPE)
    }

    async fn is_valid(
        &self,
        _realm_id: &str,
        _user_id: &str,
        input: &CredentialInput,
    ) -> Result<bool> {
        if input.get_type() != WEBAUTHN_CREDENTIAL_TYPE {
            return Ok(false);
        }

        // In a real implementation:
        // 1. Parse the authentication response from input
        // 2. Load the user's WebAuthn credentials from database
        // 3. Verify the signature using verify_authentication()

        Ok(true)
    }
}

#[async_trait]
impl CredentialInputUpdater for WebAuthnCredentialProvider {
    fn supports_credential_type(&self, credential_type: &str) -> bool {
        credential_type == WEBAUTHN_CREDENTIAL_TYPE
    }

    async fn update_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
        input: &CredentialInput,
    ) -> Result<bool> {
        if input.get_type() != WEBAUTHN_CREDENTIAL_TYPE {
            return Ok(false);
        }

        // In a real implementation:
        // 1. Parse the registration response from input
        // 2. Verify the response using verify_registration()
        // 3. Store the credential in the database

        Ok(true)
    }

    async fn disable_credential_type(
        &self,
        _realm_id: &str,
        _user_id: &str,
        credential_type: &str,
    ) -> Result<()> {
        if credential_type != WEBAUTHN_CREDENTIAL_TYPE {
            return Err(Error::unauthorized("Unsupported credential type"));
        }

        // In a real implementation, delete all WebAuthn credentials for the user
        Ok(())
    }

    async fn get_disableable_credential_types(
        &self,
        _realm_id: &str,
        _user_id: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![WEBAUTHN_CREDENTIAL_TYPE.to_string()])
    }

    async fn get_credentials(
        &self,
        _realm_id: &str,
        _user_id: &str,
    ) -> Result<Vec<CredentialModel>> {
        // In a real implementation, load from database
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_generation() {
        let provider =
            WebAuthnCredentialProvider::new("example.com".to_string(), "Example App".to_string());

        let challenge = provider.generate_challenge().unwrap();
        assert!(!challenge.is_empty());
        assert!(challenge.len() >= 32); // Base64url encoded 32 bytes
    }

    #[test]
    fn test_registration_options() {
        let provider =
            WebAuthnCredentialProvider::new("example.com".to_string(), "Example App".to_string());

        let options = provider
            .create_registration_options("user123", "testuser", "Test User", vec![])
            .unwrap();

        assert_eq!(options.rp_id, "example.com");
        assert_eq!(options.user_id, "user123");
        assert!(!options.challenge.is_empty());
    }

    #[test]
    fn test_authentication_options() {
        let provider =
            WebAuthnCredentialProvider::new("example.com".to_string(), "Example App".to_string());

        let options = provider.create_authentication_options(vec![]).unwrap();

        assert_eq!(options.rp_id, "example.com");
        assert!(!options.challenge.is_empty());
        assert_eq!(options.user_verification, "required");
    }
}
