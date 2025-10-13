//! OTP/TOTP Credential Provider Implementation
//!
//! Provides time-based one-time password (TOTP) and HMAC-based one-time password (HOTP) support.

use super::{
    CredentialInput, CredentialInputUpdater, CredentialInputValidator, CredentialModel,
    CredentialTypeCategory, CredentialTypeMetadata,
};
use crate::error::{AuthencError as Error, Result};
use async_trait::async_trait;
use base32;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;

/// OTP credential type identifier
pub const OTP_CREDENTIAL_TYPE: &str = "otp";

/// TOTP algorithm options
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OtpAlgorithm {
    /// SHA-1 algorithm (most common, RFC 6238)
    HmacSha1,
    /// SHA-256 algorithm
    HmacSha256,
    /// SHA-512 algorithm
    HmacSha512,
}

impl OtpAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpAlgorithm::HmacSha1 => "HmacSHA1",
            OtpAlgorithm::HmacSha256 => "HmacSHA256",
            OtpAlgorithm::HmacSha512 => "HmacSHA512",
        }
    }
}

/// OTP configuration data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpCredentialData {
    /// Base32-encoded secret key
    pub secret: String,
    /// Number of digits in OTP code (typically 6 or 8)
    pub digits: u32,
    /// Time period in seconds (typically 30)
    pub period: u32,
    /// Algorithm used for OTP generation
    pub algorithm: OtpAlgorithm,
    /// Device name/label
    pub device_name: Option<String>,
}

/// OTP credential provider
pub struct OtpCredentialProvider {
    /// Default algorithm for new OTP credentials
    default_algorithm: OtpAlgorithm,
    /// Default number of digits
    default_digits: u32,
    /// Default time period
    default_period: u32,
}

impl OtpCredentialProvider {
    /// Create a new OTP credential provider with default settings
    pub fn new() -> Self {
        Self {
            default_algorithm: OtpAlgorithm::HmacSha1,
            default_digits: 6,
            default_period: 30,
        }
    }

    /// Generate a new OTP secret
    pub fn generate_secret(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.r#gen()).collect();
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes)
    }

    /// Generate OTP provisioning URI for QR code
    pub fn generate_provisioning_uri(
        &self,
        secret: &str,
        account_name: &str,
        issuer: &str,
        algorithm: OtpAlgorithm,
        digits: u32,
        period: u32,
    ) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            urlencoding::encode(issuer),
            urlencoding::encode(account_name),
            secret,
            urlencoding::encode(issuer),
            algorithm.as_str(),
            digits,
            period
        )
    }

    /// Verify TOTP code
    pub fn verify_totp(
        &self,
        secret: &str,
        code: &str,
        algorithm: OtpAlgorithm,
        digits: u32,
        period: u32,
    ) -> Result<bool> {
        // Decode secret
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
            .ok_or_else(|| Error::unauthorized("Invalid OTP secret format"))?;

        // Get current time step
        let current_time = Utc::now().timestamp() as u64;
        let time_step = current_time / period as u64;

        // Allow for time drift: check current, previous, and next time step
        for step_offset in [-1i64, 0, 1] {
            let check_step = (time_step as i64 + step_offset) as u64;
            let expected_code =
                self.generate_totp_for_step(&secret_bytes, check_step, algorithm, digits)?;

            if expected_code == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Generate TOTP for a specific time step
    fn generate_totp_for_step(
        &self,
        secret: &[u8],
        time_step: u64,
        algorithm: OtpAlgorithm,
        digits: u32,
    ) -> Result<String> {
        let time_bytes = time_step.to_be_bytes();

        let hash = match algorithm {
            OtpAlgorithm::HmacSha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(secret)
                    .map_err(|_| Error::unauthorized("Invalid HMAC key"))?;
                mac.update(&time_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| Error::unauthorized("Invalid HMAC key"))?;
                mac.update(&time_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::HmacSha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(secret)
                    .map_err(|_| Error::unauthorized("Invalid HMAC key"))?;
                mac.update(&time_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let code = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);

        // Format with leading zeros
        let code_str = format!(
            "{:0width$}",
            code % 10u32.pow(digits),
            width = digits as usize
        );
        Ok(code_str)
    }

    /// Get credential type metadata
    pub fn get_metadata(&self) -> CredentialTypeMetadata {
        CredentialTypeMetadata {
            credential_type: OTP_CREDENTIAL_TYPE.to_string(),
            display_name: "Authenticator Application".to_string(),
            help_text: Some("Use an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.) to generate one-time codes.".to_string()),
            create_help_text: Some("Scan the QR code with your authenticator app or enter the secret manually.".to_string()),
            category: CredentialTypeCategory::TwoFactor,
            display_icon_classes: Some("fa fa-mobile".to_string()),
            properties: vec![],
        }
    }
}

impl Default for OtpCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialInputValidator for OtpCredentialProvider {
    fn supports_credential_type(&self, credential_type: &str) -> bool {
        credential_type == OTP_CREDENTIAL_TYPE
    }

    async fn is_configured_for(
        &self,
        _realm_id: &str,
        _user_id: &str,
        credential_type: &str,
    ) -> Result<bool> {
        Ok(credential_type == OTP_CREDENTIAL_TYPE)
    }

    async fn is_valid(
        &self,
        _realm_id: &str,
        _user_id: &str,
        input: &CredentialInput,
    ) -> Result<bool> {
        if input.get_type() != OTP_CREDENTIAL_TYPE {
            return Ok(false);
        }

        // In a real implementation, we would:
        // 1. Load the user's OTP credential from database
        // 2. Extract the secret and configuration
        // 3. Verify the code using verify_totp()

        // For now, return a placeholder validation
        Ok(input.get_challenge_response().len() == 6)
    }
}

#[async_trait]
impl CredentialInputUpdater for OtpCredentialProvider {
    fn supports_credential_type(&self, credential_type: &str) -> bool {
        credential_type == OTP_CREDENTIAL_TYPE
    }

    async fn update_credential(
        &self,
        _realm_id: &str,
        _user_id: &str,
        input: &CredentialInput,
    ) -> Result<bool> {
        if input.get_type() != OTP_CREDENTIAL_TYPE {
            return Ok(false);
        }

        // In a real implementation, we would:
        // 1. Generate a new secret
        // 2. Store it in the database
        // 3. Return provisioning URI for QR code

        Ok(true)
    }

    async fn disable_credential_type(
        &self,
        _realm_id: &str,
        _user_id: &str,
        credential_type: &str,
    ) -> Result<()> {
        if credential_type != OTP_CREDENTIAL_TYPE {
            return Err(Error::unauthorized("Unsupported credential type"));
        }

        // In a real implementation, we would delete the OTP credential from database
        Ok(())
    }

    async fn get_disableable_credential_types(
        &self,
        _realm_id: &str,
        _user_id: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![OTP_CREDENTIAL_TYPE.to_string()])
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
    fn test_totp_generation_and_verification() {
        let provider = OtpCredentialProvider::new();

        // Generate a test secret
        let secret = provider.generate_secret();
        assert!(!secret.is_empty());

        // Generate a code for current time
        let secret_bytes =
            base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret).unwrap();
        let time_step = Utc::now().timestamp() as u64 / 30;
        let code = provider
            .generate_totp_for_step(&secret_bytes, time_step, OtpAlgorithm::HmacSha1, 6)
            .unwrap();

        // Verify the code
        assert_eq!(code.len(), 6);
        assert!(
            provider
                .verify_totp(&secret, &code, OtpAlgorithm::HmacSha1, 6, 30)
                .unwrap()
        );
    }

    #[test]
    fn test_provisioning_uri() {
        let provider = OtpCredentialProvider::new();
        let secret = "JBSWY3DPEHPK3PXP";
        let uri = provider.generate_provisioning_uri(
            secret,
            "user@example.com",
            "MyApp",
            OtpAlgorithm::HmacSha1,
            6,
            30,
        );

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=MyApp"));
    }
}
