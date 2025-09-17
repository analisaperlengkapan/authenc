use crate::error::{AuthencError, Result};
use crate::utils::crypto_monitor::CryptoMonitor;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AES-GCM encryption service for enhanced security
pub struct AesGcmService {
    /// AES-256-GCM encryption key
    key: Key<Aes256Gcm>,
}

/// Encrypted data structure containing ciphertext, nonce, and authentication tag
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded nonce used for encryption
    pub nonce: String,
    /// Base64-encoded authentication tag
    pub tag: String,
}

/// Encryption key metadata and data
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKey {
    /// Unique identifier for the encryption key
    pub key_id: String,
    /// Raw key data bytes
    pub key_data: Vec<u8>,
    /// Encryption algorithm identifier
    pub algorithm: String,
    /// Timestamp when the key was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional expiration timestamp for the key
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for AesGcmService {
    fn default() -> Self {
        Self::new()
    }
}

impl AesGcmService {
    /// Create new AES-GCM service with a random key
    pub fn new() -> Self {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let key = *Key::<Aes256Gcm>::from_slice(&key_bytes);

        Self { key }
    }

    /// Create AES-GCM service with specific key
    pub fn with_key(key_data: &[u8]) -> Result<Self> {
        if key_data.len() != 32 {
            return Err(AuthencError::ValidationError {
                message: "AES key must be 32 bytes".to_string(),
            });
        }

        let key = *Key::<Aes256Gcm>::from_slice(key_data);
        Ok(Self { key })
    }

    /// Encrypt data using AES-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        CryptoMonitor::monitor_rsa_operation("aes_gcm_encrypt", || {
            let cipher = Aes256Gcm::new(&self.key);

            // Generate random nonce
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Encrypt the data
            let ciphertext = cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| AuthencError::CryptographicError)?;

            // Split ciphertext and tag (last 16 bytes)
            let tag_start = ciphertext.len().saturating_sub(16);
            let (encrypted_data, tag) = ciphertext.split_at(tag_start);

            Ok(EncryptedData {
                ciphertext: Base64UrlUnpadded::encode_string(encrypted_data),
                nonce: Base64UrlUnpadded::encode_string(&nonce_bytes),
                tag: Base64UrlUnpadded::encode_string(tag),
            })
        })
    }

    /// Decrypt data using AES-GCM
    pub fn decrypt(&self, encrypted_data: &EncryptedData) -> Result<Vec<u8>> {
        CryptoMonitor::monitor_rsa_operation("aes_gcm_decrypt", || {
            let cipher = Aes256Gcm::new(&self.key);

            // Decode components
            let ciphertext =
                Base64UrlUnpadded::decode_vec(&encrypted_data.ciphertext).map_err(|_| {
                    AuthencError::ValidationError {
                        message: "Invalid ciphertext encoding".to_string(),
                    }
                })?;

            let nonce_bytes =
                Base64UrlUnpadded::decode_vec(&encrypted_data.nonce).map_err(|_| {
                    AuthencError::ValidationError {
                        message: "Invalid nonce encoding".to_string(),
                    }
                })?;

            let tag = Base64UrlUnpadded::decode_vec(&encrypted_data.tag).map_err(|_| {
                AuthencError::ValidationError {
                    message: "Invalid tag encoding".to_string(),
                }
            })?;

            if nonce_bytes.len() != 12 {
                return Err(AuthencError::ValidationError {
                    message: "Invalid nonce length".to_string(),
                });
            }

            if tag.len() != 16 {
                return Err(AuthencError::ValidationError {
                    message: "Invalid tag length".to_string(),
                });
            }

            // Reconstruct full ciphertext with tag
            let mut full_ciphertext = ciphertext.clone();
            full_ciphertext.extend_from_slice(&tag);

            let nonce = Nonce::from_slice(&nonce_bytes);

            // Decrypt
            let plaintext = cipher
                .decrypt(nonce, full_ciphertext.as_ref())
                .map_err(|_| AuthencError::CryptographicError)?;

            Ok(plaintext)
        })
    }

    /// Encrypt JSON data
    pub fn encrypt_json<T: Serialize>(&self, data: &T) -> Result<EncryptedData> {
        let json_string =
            serde_json::to_string(data).map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize data".to_string(),
            })?;
        self.encrypt(json_string.as_bytes())
    }

    /// Decrypt JSON data
    pub fn decrypt_json<T: for<'de> Deserialize<'de>>(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<T> {
        let plaintext = self.decrypt(encrypted_data)?;
        let json_string =
            String::from_utf8(plaintext).map_err(|_| AuthencError::SerializationError {
                message: "Invalid UTF-8 in decrypted data".to_string(),
            })?;
        serde_json::from_str(&json_string).map_err(|_| AuthencError::SerializationError {
            message: "Failed to deserialize data".to_string(),
        })
    }

    /// Generate a new encryption key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Derive key from password using Argon2
    pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        use argon2::{Argon2, Params};

        let mut key = [0u8; 32];
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 3, 4, Some(32)).unwrap(),
        );

        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|_| AuthencError::CryptographicError)?;

        Ok(key)
    }

    /// Encrypt large data with streaming
    pub fn encrypt_stream(&self, data: &[u8], chunk_size: usize) -> Result<Vec<EncryptedData>> {
        data.chunks(chunk_size)
            .map(|chunk| self.encrypt(chunk))
            .collect()
    }

    /// Decrypt streaming data
    pub fn decrypt_stream(&self, encrypted_chunks: &[EncryptedData]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for chunk in encrypted_chunks {
            let decrypted = self.decrypt(chunk)?;
            result.extend(decrypted);
        }
        Ok(result)
    }

    /// Create encryption context for specific data type
    pub fn create_encryption_context(&self, context_id: &str) -> EncryptionContext<'_> {
        EncryptionContext {
            service: self,
            context_id: context_id.to_string(),
        }
    }
}

/// Encryption context for type-safe encryption operations
pub struct EncryptionContext<'a> {
    service: &'a AesGcmService,
    context_id: String,
}

impl<'a> EncryptionContext<'a> {
    /// Encrypt with context
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedData> {
        self.service.encrypt(data)
    }

    /// Decrypt with context
    pub fn decrypt(&self, encrypted_data: &EncryptedData) -> Result<Vec<u8>> {
        self.service.decrypt(encrypted_data)
    }

    /// Get context ID
    pub fn context_id(&self) -> &str {
        &self.context_id
    }
}

/// Key rotation service for enhanced security
pub struct KeyRotationService {
    current_key: AesGcmService,
    previous_keys: HashMap<String, AesGcmService>,
}

impl Default for KeyRotationService {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyRotationService {
    /// Create new key rotation service
    pub fn new() -> Self {
        Self {
            current_key: AesGcmService::new(),
            previous_keys: HashMap::new(),
        }
    }

    /// Rotate to new key
    pub fn rotate_key(&mut self) -> String {
        let old_key = std::mem::take(&mut self.current_key);
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());

        self.previous_keys.insert(key_id.clone(), old_key);
        key_id
    }

    /// Encrypt with current key
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedData> {
        self.current_key.encrypt(data)
    }

    /// Decrypt with key rotation support
    pub fn decrypt(&self, encrypted_data: &EncryptedData, key_id: Option<&str>) -> Result<Vec<u8>> {
        // Try current key first
        match self.current_key.decrypt(encrypted_data) {
            Ok(data) => Ok(data),
            Err(_) => {
                // If key_id provided, try that key
                if let Some(key_id) = key_id {
                    if let Some(key_service) = self.previous_keys.get(key_id) {
                        return key_service.decrypt(encrypted_data);
                    }
                }

                // Try all previous keys
                for key_service in self.previous_keys.values() {
                    if let Ok(data) = key_service.decrypt(encrypted_data) {
                        return Ok(data);
                    }
                }

                Err(AuthencError::CryptographicError)
            }
        }
    }

    /// Get current key ID
    pub fn current_key_id(&self) -> String {
        "current".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let service = AesGcmService::new();
        let plaintext = b"Hello, World!";

        let encrypted = service.encrypt(plaintext).unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_gcm_json_encrypt_decrypt() {
        let service = AesGcmService::new();
        let data = serde_json::json!({"message": "test", "value": 123});

        let encrypted = service.encrypt_json(&data).unwrap();
        let decrypted: serde_json::Value = service.decrypt_json(&encrypted).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_key_rotation() {
        let mut rotation_service = KeyRotationService::new();
        let plaintext = b"Test data";

        // Encrypt with current key
        let encrypted = rotation_service.encrypt(plaintext).unwrap();

        // Rotate key
        let _old_key_id = rotation_service.rotate_key();

        // Should still be able to decrypt with current key
        let decrypted = rotation_service.decrypt(&encrypted, None).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
