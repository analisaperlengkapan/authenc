use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

use crate::error::{Result, AuthencError as Error};
use crate::spi::{Provider, ProviderFactory, Spi, ProviderConfig, SpiError};

/// Key status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Passive,
    Disabled,
}

impl KeyStatus {
    pub fn from(active: bool, enabled: bool) -> Self {
        if !enabled {
            KeyStatus::Disabled
        } else if active {
            KeyStatus::Active
        } else {
            KeyStatus::Passive
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, KeyStatus::Active | KeyStatus::Passive)
    }
}

/// Abstract key metadata base class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub provider_id: String,
    pub provider_priority: i64,
    pub kid: String,
    pub status: KeyStatus,
}

impl KeyMetadata {
    pub fn new(provider_id: String, kid: String) -> Self {
        Self {
            provider_id,
            provider_priority: 0,
            kid,
            status: KeyStatus::Active,
        }
    }

    pub fn get_provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn set_provider_id(&mut self, provider_id: String) {
        self.provider_id = provider_id;
    }

    pub fn get_provider_priority(&self) -> i64 {
        self.provider_priority
    }

    pub fn set_provider_priority(&mut self, provider_priority: i64) {
        self.provider_priority = provider_priority;
    }

    pub fn get_kid(&self) -> &str {
        &self.kid
    }

    pub fn set_kid(&mut self, kid: String) {
        self.kid = kid;
    }

    pub fn get_status(&self) -> KeyStatus {
        self.status
    }

    pub fn set_status(&mut self, status: KeyStatus) {
        self.status = status;
    }
}

/// RSA key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaKeyMetadata {
    #[serde(flatten)]
    pub key_metadata: KeyMetadata,
    pub public_key_pem: String,
    pub certificate_pem: Option<String>,
}

impl RsaKeyMetadata {
    pub fn new(provider_id: String, kid: String, public_key_pem: String) -> Self {
        Self {
            key_metadata: KeyMetadata::new(provider_id, kid),
            public_key_pem,
            certificate_pem: None,
        }
    }

    pub fn get_public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    pub fn set_public_key_pem(&mut self, public_key_pem: String) {
        self.public_key_pem = public_key_pem;
    }

    pub fn get_certificate_pem(&self) -> Option<&str> {
        self.certificate_pem.as_deref()
    }

    pub fn set_certificate_pem(&mut self, certificate_pem: Option<String>) {
        self.certificate_pem = certificate_pem;
    }
}

impl std::ops::Deref for RsaKeyMetadata {
    type Target = KeyMetadata;

    fn deref(&self) -> &Self::Target {
        &self.key_metadata
    }
}

impl std::ops::DerefMut for RsaKeyMetadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key_metadata
    }
}

/// Secret key metadata for symmetric keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyMetadata {
    #[serde(flatten)]
    pub key_metadata: KeyMetadata,
    pub algorithm: String,
    pub secret: String, // Base64 encoded
}

impl SecretKeyMetadata {
    pub fn new(provider_id: String, kid: String, algorithm: String, secret: String) -> Self {
        Self {
            key_metadata: KeyMetadata::new(provider_id, kid),
            algorithm,
            secret,
        }
    }

    pub fn get_algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn set_algorithm(&mut self, algorithm: String) {
        self.algorithm = algorithm;
    }

    pub fn get_secret(&self) -> &str {
        &self.secret
    }

    pub fn set_secret(&mut self, secret: String) {
        self.secret = secret;
    }
}

impl std::ops::Deref for SecretKeyMetadata {
    type Target = KeyMetadata;

    fn deref(&self) -> &Self::Target {
        &self.key_metadata
    }
}

impl std::ops::DerefMut for SecretKeyMetadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key_metadata
    }
}

/// Key provider trait for managing cryptographic keys
#[async_trait]
pub trait KeyProvider: Provider + Send + Sync {
    /// Get the key type this provider handles
    fn get_key_type(&self) -> &str;

    /// Get all keys managed by this provider
    async fn get_keys(&self) -> Result<Vec<Box<dyn KeyMetadataTrait>>>;

    /// Get a specific key by kid
    async fn get_key(&self, kid: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get the active key for signing
    async fn get_active_key(&self) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get the passive key (for rotation)
    async fn get_passive_key(&self) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Check if this provider supports the given algorithm
    fn supports_algorithm(&self, algorithm: &str) -> bool;
}

/// Trait for key metadata objects
pub trait KeyMetadataTrait: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn get_provider_id(&self) -> &str;
    fn get_provider_priority(&self) -> i64;
    fn get_kid(&self) -> &str;
    fn get_status(&self) -> KeyStatus;
    fn set_status(&mut self, status: KeyStatus);
}

impl KeyMetadataTrait for RsaKeyMetadata {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn get_provider_id(&self) -> &str {
        self.key_metadata.get_provider_id()
    }

    fn get_provider_priority(&self) -> i64 {
        self.key_metadata.get_provider_priority()
    }

    fn get_kid(&self) -> &str {
        self.key_metadata.get_kid()
    }

    fn get_status(&self) -> KeyStatus {
        self.key_metadata.get_status()
    }

    fn set_status(&mut self, status: KeyStatus) {
        self.key_metadata.set_status(status);
    }
}

impl KeyMetadataTrait for SecretKeyMetadata {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn get_provider_id(&self) -> &str {
        self.key_metadata.get_provider_id()
    }

    fn get_provider_priority(&self) -> i64 {
        self.key_metadata.get_provider_priority()
    }

    fn get_kid(&self) -> &str {
        self.key_metadata.get_kid()
    }

    fn get_status(&self) -> KeyStatus {
        self.key_metadata.get_status()
    }

    fn set_status(&mut self, status: KeyStatus) {
        self.key_metadata.set_status(status);
    }
}

/// Key manager for coordinating multiple key providers
#[async_trait]
pub trait KeyManager: Provider + Send + Sync {
    /// Get the active key for signing with the specified algorithm
    async fn get_active_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get a key by kid
    async fn get_key(&self, kid: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get all keys
    async fn get_keys(&self, algorithm: &str) -> Result<Vec<Box<dyn KeyMetadataTrait>>>;

    /// Get the default key for an algorithm
    async fn get_default_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;
}

/// Default key manager implementation
pub struct DefaultKeyManager {
    providers: Vec<Box<dyn KeyProvider>>,
}

impl DefaultKeyManager {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn add_provider(&mut self, provider: Box<dyn KeyProvider>) {
        self.providers.push(provider);
    }
}

#[async_trait]
impl KeyManager for DefaultKeyManager {
    async fn get_active_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>> {
        for provider in &self.providers {
            if provider.supports_algorithm(algorithm) {
                if let Some(key) = provider.get_active_key().await? {
                    return Ok(Some(key));
                }
            }
        }
        Ok(None)
    }

    async fn get_key(&self, kid: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>> {
        for provider in &self.providers {
            if let Some(key) = provider.get_key(kid).await? {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    async fn get_keys(&self, algorithm: &str) -> Result<Vec<Box<dyn KeyMetadataTrait>>> {
        let mut keys = Vec::new();
        for provider in &self.providers {
            if provider.supports_algorithm(algorithm) {
                keys.extend(provider.get_keys().await?);
            }
        }
        Ok(keys)
    }

    async fn get_default_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>> {
        self.get_active_key(algorithm).await
    }
}

impl Provider for DefaultKeyManager {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Key manager factory
pub struct DefaultKeyManagerFactory;

impl DefaultKeyManagerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderFactory<dyn KeyManager> for DefaultKeyManagerFactory {
    async fn create(&self, _config: &ProviderConfig) -> std::result::Result<Box<dyn KeyManager>, SpiError> {
        Ok(Box::new(DefaultKeyManager::new()))
    }

    async fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-key-manager"
    }
}

/// Keys SPI implementation
pub struct KeysSpi;

impl Spi for KeysSpi {
    fn get_name(&self) -> &'static str {
        "keys"
    }

    fn is_internal(&self) -> bool {
        true
    }

    fn get_provider_class(&self) -> &'static str {
        "KeyManager"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "KeyManagerFactory"
    }
}
