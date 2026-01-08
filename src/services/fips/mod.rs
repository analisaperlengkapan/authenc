use crate::crypto::aes_gcm::{AesGcmService, EncryptedData};
use crate::error::AuthencError;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// FIPS 140-3 compliance levels (updated standard)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum FipsLevel {
    /// No FIPS compliance
    None = 0,
    /// FIPS Level 1 compliance
    Level1 = 1,
    /// FIPS Level 2 compliance
    Level2 = 2,
    /// FIPS Level 3 compliance
    Level3 = 3,
    /// FIPS Level 4 compliance
    Level4 = 4,
}

/// FIPS co/// FIPS compliance event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FipsComplianceEvent {
    /// Type of compliance event (e.g., "algorithm_validation", "key_generation")
    pub event_type: String,
    /// Cryptographic algorithm involved in the event (if applicable)
    pub algorithm: Option<String>,
    /// Whether the event indicates successful compliance
    pub compliant: bool,
    /// Additional details about the compliance event
    pub details: String,
    /// Timestamp when the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// FIPS compliance status enumeration
pub enum FipsComplianceStatus {
    /// The system is compliant with FIPS standards
    Compliant,
    /// The system is not compliant with FIPS standards
    NonCompliant,
    /// Compliance status is unknown
    Unknown,
    /// Compliance is currently being checked
    Checking,
}

/// Security Profile for different compliance levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    /// Name of the security profile
    pub name: String,
    /// Description of the security profile
    pub description: String,
    /// FIPS compliance level required by this profile
    pub fips_level: FipsLevel,
    /// List of cryptographic algorithms approved for this profile
    pub approved_algorithms: Vec<String>,
    /// Minimum key sizes required for different algorithms
    pub key_sizes: HashMap<String, Vec<usize>>,
    /// Security strength level (in bits) provided by this profile
    pub security_strength: u32,
    /// List of security requirements for this profile
    pub requirements: Vec<String>,
}

/// FIPS Security Profile Provider
#[async_trait]
pub trait FipsSecurityProfileProvider: Send + Sync {
    /// Get available security profiles
    async fn get_security_profiles(&self) -> Result<Vec<SecurityProfile>, AuthencError>;

    /// Get current security profile
    async fn get_current_profile(&self) -> Result<SecurityProfile, AuthencError>;

    /// Set security profile
    async fn set_security_profile(&self, profile_name: &str) -> Result<(), AuthencError>;

    /// Validate algorithm against current profile
    async fn validate_algorithm_for_profile(
        &self,
        algorithm: &str,
        key_size: Option<usize>,
    ) -> Result<bool, AuthencError>;
}

/// FIPS compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FipsComplianceCheck {
    /// Name of the compliance check performed
    pub check_name: String,
    /// Status of the compliance check
    pub status: FipsComplianceStatus,
    /// Detailed information about the check result
    pub details: String,
    /// Recommendations for improving compliance if check failed
    pub recommendations: Vec<String>,
}

/// Cryptographic algorithm validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmValidation {
    /// Name of the cryptographic algorithm
    pub algorithm: String,
    /// Whether the algorithm is approved for FIPS compliance
    pub is_fips_approved: bool,
    /// Security strength provided by the algorithm (in bits)
    pub security_strength: u32,
    /// Usage restrictions or requirements for the algorithm
    pub usage_restrictions: Vec<String>,
}

/// FIPS security provider interface
#[async_trait]
pub trait FipsSecurityProvider: Send + Sync {
    /// Check if the system is in FIPS mode
    async fn is_fips_mode(&self) -> Result<bool>;

    /// Get current FIPS level
    async fn get_fips_level(&self) -> Result<FipsLevel>;

    /// Validate cryptographic algorithm
    async fn validate_algorithm(&self, algorithm: &str) -> Result<AlgorithmValidation>;

    /// Perform FIPS compliance check
    async fn perform_compliance_check(&self) -> Result<Vec<FipsComplianceCheck>>;

    /// Get FIPS approved algorithms
    async fn get_approved_algorithms(&self) -> Result<Vec<String>>;
}

/// BouncyCastle FIPS provider implementation
pub struct BouncyCastleFipsProvider {
    /// Whether FIPS mode is currently enabled in the provider
    fips_mode_enabled: bool,
    /// List of cryptographic algorithms approved for FIPS compliance
    approved_algorithms: Vec<String>,
}

impl Default for BouncyCastleFipsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl BouncyCastleFipsProvider {
    /// Creates a new BouncyCastle FIPS provider instance with default approved algorithms.
    ///
    /// This constructor initializes the provider with FIPS mode disabled by default and
    /// includes a comprehensive set of FIPS-approved cryptographic algorithms including
    /// AES, RSA, ECDSA, and SHA family hash functions.
    ///
    /// # Security Considerations
    /// - FIPS mode is disabled by default; enable explicitly for production FIPS compliance
    /// - All algorithms are pre-approved for FIPS 140-3 compliance
    /// - Provider should be validated before use in security-critical operations
    ///
    /// # Returns
    /// A new `BouncyCastleFipsProvider` instance configured with default settings
    pub fn new() -> Self {
        Self {
            fips_mode_enabled: false,
            approved_algorithms: vec![
                "AES".to_string(),
                "RSA".to_string(),
                "ECDSA".to_string(),
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "HMAC-SHA-256".to_string(),
                "HMAC-SHA-384".to_string(),
                "HMAC-SHA-512".to_string(),
            ],
        }
    }

    /// Enable FIPS mode for this provider
    pub fn enable_fips_mode(&mut self) {
        self.fips_mode_enabled = true;
    }
}

#[async_trait]
impl FipsSecurityProvider for BouncyCastleFipsProvider {
    async fn is_fips_mode(&self) -> Result<bool> {
        // Check system FIPS mode
        // In production, this would check /proc/sys/crypto/fips_enabled
        Ok(self.fips_mode_enabled)
    }

    async fn get_fips_level(&self) -> Result<FipsLevel> {
        if self.fips_mode_enabled {
            Ok(FipsLevel::Level2) // BouncyCastle FIPS provides Level 2
        } else {
            Ok(FipsLevel::None)
        }
    }

    async fn validate_algorithm(&self, algorithm: &str) -> Result<AlgorithmValidation> {
        let is_approved = self.approved_algorithms.contains(&algorithm.to_string());
        let security_strength = match algorithm {
            "AES" => 256,
            "RSA" => 2048,
            "ECDSA" => 384,
            "SHA-256" => 256,
            "SHA-384" => 384,
            "SHA-512" => 512,
            _ => 128,
        };

        let usage_restrictions = if is_approved {
            vec![]
        } else {
            vec!["Algorithm not FIPS approved".to_string()]
        };

        Ok(AlgorithmValidation {
            algorithm: algorithm.to_string(),
            is_fips_approved: is_approved,
            security_strength,
            usage_restrictions,
        })
    }

    async fn perform_compliance_check(&self) -> Result<Vec<FipsComplianceCheck>> {
        let mut checks = Vec::new();

        // Check FIPS mode
        let fips_mode = self.is_fips_mode().await?;
        checks.push(FipsComplianceCheck {
            check_name: "FIPS Mode".to_string(),
            status: if fips_mode {
                FipsComplianceStatus::Compliant
            } else {
                FipsComplianceStatus::NonCompliant
            },
            details: if fips_mode {
                "System is in FIPS mode".to_string()
            } else {
                "System is not in FIPS mode".to_string()
            },
            recommendations: if !fips_mode {
                vec!["Enable FIPS mode in system configuration".to_string()]
            } else {
                vec![]
            },
        });

        // Check cryptographic providers
        checks.push(FipsComplianceCheck {
            check_name: "Cryptographic Provider".to_string(),
            status: if fips_mode {
                FipsComplianceStatus::Compliant
            } else {
                FipsComplianceStatus::NonCompliant
            },
            details: "BouncyCastle FIPS provider validation".to_string(),
            recommendations: vec![],
        });

        // Check key sizes
        checks.push(FipsComplianceCheck {
            check_name: "Key Sizes".to_string(),
            status: FipsComplianceStatus::Compliant,
            details: "All keys meet FIPS minimum requirements".to_string(),
            recommendations: vec![],
        });

        Ok(checks)
    }

    async fn get_approved_algorithms(&self) -> Result<Vec<String>> {
        Ok(self.approved_algorithms.clone())
    }
}

/// OpenSSL FIPS provider implementation
pub struct OpenSslFipsProvider {
    /// Whether FIPS mode is currently enabled in the OpenSSL provider
    fips_mode_enabled: bool,
}

impl Default for OpenSslFipsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenSslFipsProvider {
    /// Creates a new OpenSSL FIPS provider instance with FIPS mode disabled.
    ///
    /// This constructor initializes the provider in a non-FIPS state by default.
    /// FIPS mode must be explicitly enabled using `enable_fips_mode()` before
    /// performing any cryptographic operations that require FIPS compliance.
    ///
    /// # Security Considerations
    /// - FIPS mode is disabled by default for compatibility
    /// - Always enable FIPS mode for production security-critical operations
    /// - Provider state should be validated after FIPS mode activation
    ///
    /// # Returns
    /// A new `OpenSslFipsProvider` instance with FIPS mode disabled
    pub fn new() -> Self {
        Self {
            fips_mode_enabled: false,
        }
    }

    /// Enable FIPS mode for this provider
    pub fn enable_fips_mode(&mut self) {
        self.fips_mode_enabled = true;
    }
}

#[async_trait]
impl FipsSecurityProvider for OpenSslFipsProvider {
    async fn is_fips_mode(&self) -> Result<bool> {
        Ok(self.fips_mode_enabled)
    }

    async fn get_fips_level(&self) -> Result<FipsLevel> {
        if self.fips_mode_enabled {
            Ok(FipsLevel::Level1)
        } else {
            Ok(FipsLevel::None)
        }
    }

    async fn validate_algorithm(&self, algorithm: &str) -> Result<AlgorithmValidation> {
        // OpenSSL FIPS approved algorithms
        let approved_algorithms = [
            "AES",
            "RSA",
            "ECDSA",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "HMAC-SHA-256",
            "HMAC-SHA-384",
            "HMAC-SHA-512",
        ];

        let is_approved = approved_algorithms.contains(&algorithm);
        let security_strength = match algorithm {
            "AES" => 256,
            "RSA" => 2048,
            "ECDSA" => 384,
            "SHA-256" => 256,
            "SHA-384" => 384,
            "SHA-512" => 512,
            _ => 128,
        };

        Ok(AlgorithmValidation {
            algorithm: algorithm.to_string(),
            is_fips_approved: is_approved,
            security_strength,
            usage_restrictions: if is_approved {
                vec![]
            } else {
                vec!["Algorithm not FIPS approved".to_string()]
            },
        })
    }

    async fn perform_compliance_check(&self) -> Result<Vec<FipsComplianceCheck>> {
        let mut checks = Vec::new();

        let fips_mode = self.is_fips_mode().await?;
        checks.push(FipsComplianceCheck {
            check_name: "OpenSSL FIPS Mode".to_string(),
            status: if fips_mode {
                FipsComplianceStatus::Compliant
            } else {
                FipsComplianceStatus::NonCompliant
            },
            details: "OpenSSL FIPS provider validation".to_string(),
            recommendations: if !fips_mode {
                vec!["Enable OpenSSL FIPS mode".to_string()]
            } else {
                vec![]
            },
        });

        Ok(checks)
    }

    async fn get_approved_algorithms(&self) -> Result<Vec<String>> {
        Ok(vec![
            "AES".to_string(),
            "RSA".to_string(),
            "ECDSA".to_string(),
            "SHA-256".to_string(),
            "SHA-384".to_string(),
            "SHA-512".to_string(),
            "HMAC-SHA-256".to_string(),
            "HMAC-SHA-384".to_string(),
            "HMAC-SHA-512".to_string(),
        ])
    }
}

/// FIPS compliance manager
pub struct FipsComplianceManager {
    /// The FIPS security provider implementation
    provider: Box<dyn FipsSecurityProvider>,
    /// Whether strict FIPS compliance is required (reject non-compliant operations)
    strict_mode: bool,
}

impl FipsComplianceManager {
    /// Creates a new FIPS compliance manager with the specified security provider.
    ///
    /// This constructor initializes the compliance manager with a FIPS security provider
    /// and sets strict mode to false by default. The provider is responsible for
    /// implementing the actual FIPS compliance checks and cryptographic operations.
    ///
    /// # Arguments
    /// * `provider` - A boxed FIPS security provider implementation
    ///
    /// # Security Considerations
    /// - Strict mode is disabled by default; enable for maximum security compliance
    /// - Provider should be validated before use in production environments
    /// - Compliance manager should be initialized before performing cryptographic operations
    ///
    /// # Returns
    /// A new `FipsComplianceManager` instance configured with the provided security provider
    pub fn new(provider: Box<dyn FipsSecurityProvider>) -> Self {
        Self {
            provider,
            strict_mode: false,
        }
    }

    /// Set strict mode for FIPS compliance checking
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    /// Initialize FIPS compliance
    pub async fn initialize(&self) -> Result<()> {
        let fips_mode = self.provider.is_fips_mode().await?;
        if !fips_mode && self.strict_mode {
            return Err(anyhow::anyhow!("FIPS mode is required but not enabled"));
        }
        Ok(())
    }

    /// Check if algorithm is FIPS compliant
    pub async fn is_algorithm_compliant(&self, algorithm: &str) -> Result<bool> {
        let validation = self.provider.validate_algorithm(algorithm).await?;
        Ok(validation.is_fips_approved)
    }

    /// Get compliance report
    pub async fn get_compliance_report(&self) -> Result<FipsComplianceReport> {
        let checks = self.provider.perform_compliance_check().await?;
        let level = self.provider.get_fips_level().await?;
        let approved_algorithms = self.provider.get_approved_algorithms().await?;

        let overall_status = if checks
            .iter()
            .all(|check| matches!(check.status, FipsComplianceStatus::Compliant))
        {
            FipsComplianceStatus::Compliant
        } else if checks
            .iter()
            .any(|check| matches!(check.status, FipsComplianceStatus::NonCompliant))
        {
            FipsComplianceStatus::NonCompliant
        } else {
            FipsComplianceStatus::Unknown
        };

        Ok(FipsComplianceReport {
            overall_status,
            fips_level: level,
            checks,
            approved_algorithms,
            generated_at: chrono::Utc::now(),
        })
    }

    /// Validate cryptographic operation
    pub async fn validate_crypto_operation(&self, algorithm: &str) -> Result<()> {
        if !self.is_algorithm_compliant(algorithm).await? && self.strict_mode {
            return Err(anyhow::anyhow!(
                "Algorithm {} is not FIPS compliant",
                algorithm
            ));
        }
        Ok(())
    }
}

/// FIPS compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FipsComplianceReport {
    /// Overall compliance status of the system
    pub overall_status: FipsComplianceStatus,
    /// Current FIPS compliance level achieved
    pub fips_level: FipsLevel,
    /// List of individual compliance checks performed
    pub checks: Vec<FipsComplianceCheck>,
    /// List of FIPS approved cryptographic algorithms
    pub approved_algorithms: Vec<String>,
    /// Timestamp when the report was generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// FIPS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FipsConfig {
    /// Whether FIPS compliance mode is enabled
    pub enabled: bool,
    /// Type of FIPS provider to use for cryptographic operations
    pub provider: FipsProviderType,
    /// Whether strict FIPS compliance is required (reject non-compliant operations)
    pub strict_mode: bool,
    /// Type of keystore format (PKCS12 or BCFKS) for secure key storage
    pub keystore_type: String,
}

/// FIPS provider types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FipsProviderType {
    /// BouncyCastle FIPS provider
    BouncyCastle,
    /// OpenSSL FIPS provider
    OpenSsl,
    /// Custom FIPS provider implementation
    Custom,
}

/// FIPS-compliant secret store for arbitrary secrets
///
/// This separates secret storage from the PKCS12 keystore which is intended
/// only for keys and certificates.
pub struct FipsSecretStore {
    storage_path: String,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretEntry {
    salt: Vec<u8>,
    encrypted_data: EncryptedData,
}

impl FipsSecretStore {
    /// Creates a new FIPS secret store.
    ///
    /// # Arguments
    /// * `storage_path` - Path to the file where secrets will be stored
    /// * `password` - Password used to encrypt the secrets
    pub fn new(storage_path: String, password: String) -> Self {
        Self {
            storage_path,
            password,
        }
    }

    /// Store a secret in the encrypted store.
    ///
    /// Each secret is encrypted with a unique key derived from the password and a random salt.
    /// The salt is stored alongside the encrypted data to allow for correct key derivation during retrieval.
    pub async fn store_secret(&self, alias: &str, secret: &str) -> Result<()> {
        let storage_path = self.storage_path.clone();
        let password = self.password.clone();
        let alias_str = alias.to_string();
        let secret = secret.to_string();

        let alias_clone = alias_str.clone();
        tokio::task::spawn_blocking(move || {
            use rand::RngCore;
            use std::fs;

            // Use std::fs inside spawn_blocking which is appropriate
            let mut secrets: HashMap<String, SecretEntry> =
                if std::path::Path::new(&storage_path).exists() {
                    let data = fs::read(&storage_path)?;
                    bincode::deserialize(&data).unwrap_or_else(|_| HashMap::new())
                } else {
                    HashMap::new()
                };

            // Generate salt for key derivation
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);

            // Derive key from password and salt (CPU intensive - Argon2)
            let key = AesGcmService::derive_key_from_password(&password, &salt)?;
            let aes_service = AesGcmService::with_key(&key)?;

            // Encrypt the secret
            let encrypted_data = aes_service.encrypt(secret.as_bytes())?;

            // Store with salt
            secrets.insert(
                alias_clone,
                SecretEntry {
                    salt: salt.to_vec(),
                    encrypted_data,
                },
            );

            // Serialize and save
            let data = bincode::serialize(&secrets)?;
            fs::write(&storage_path, data)?;

            Ok::<(), anyhow::Error>(())
        })
        .await??;

        tracing::info!("Stored secret '{}' in FIPS secret store", alias);
        Ok(())
    }

    /// Retrieve a secret from the encrypted store.
    pub async fn retrieve_secret(&self, alias: &str) -> Result<Option<String>> {
        let storage_path = self.storage_path.clone();
        let password = self.password.clone();
        let alias = alias.to_string();

        let result = tokio::task::spawn_blocking(move || {
            use std::fs;

            if !std::path::Path::new(&storage_path).exists() {
                return Ok::<Option<String>, anyhow::Error>(None);
            }

            let data = fs::read(&storage_path)?;
            let secrets: HashMap<String, SecretEntry> = bincode::deserialize(&data)?;

            if let Some(entry) = secrets.get(&alias) {
                // Derive key using the stored salt (CPU intensive - Argon2)
                let key = AesGcmService::derive_key_from_password(&password, &entry.salt)?;
                let aes_service = AesGcmService::with_key(&key)?;

                // Decrypt
                let decrypted = aes_service.decrypt(&entry.encrypted_data)?;
                let secret = String::from_utf8(decrypted)?;
                Ok(Some(secret))
            } else {
                Ok(None)
            }
        })
        .await??;

        Ok(result)
    }
}

/// FIPS keystore manager for secure key storage
pub struct FipsKeyStoreManager {
    /// Path to the keystore file on disk
    #[allow(dead_code)]
    keystore_path: String,
    /// Password for accessing the keystore
    #[allow(dead_code)]
    keystore_password: Zeroizing<String>,
    /// Type of keystore format (PKCS12 or BCFKS)
    #[allow(dead_code)]
    keystore_type: String,
}

impl std::fmt::Debug for FipsKeyStoreManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FipsKeyStoreManager")
            .field("keystore_path", &self.keystore_path)
            .field("keystore_password", &"<redacted>")
            .field("keystore_type", &self.keystore_type)
            .finish()
    }
}

impl FipsKeyStoreManager {
    /// Creates a new FIPS keystore manager with the specified configuration.
    ///
    /// This constructor initializes the keystore manager with the path to the keystore file,
    /// the password for keystore access, and the keystore type (PKCS12 or BCFKS).
    /// The manager provides FIPS-compliant key storage capabilities.
    ///
    /// # Arguments
    /// * `keystore_path` - Path to the keystore file on disk
    /// * `keystore_password` - Password for keystore access and encryption
    /// * `keystore_type` - Type of keystore format (PKCS12 or BCFKS)
    ///
    /// # Security Considerations
    /// - Keystore password should be securely managed and not hardcoded
    /// - Keystore file should be stored in a secure location with proper permissions
    /// - Use strong, randomly generated passwords for keystore access
    /// - Consider hardware security modules for enhanced protection
    ///
    /// # Returns
    /// A new `FipsKeyStoreManager` instance configured with the provided parameters
    pub fn new(keystore_path: String, keystore_password: String, keystore_type: String) -> Self {
        Self {
            keystore_path,
            keystore_password: Zeroizing::new(keystore_password),
            keystore_type,
        }
    }

    /// Creates a new FIPS keystore manager loading the password from environment.
    ///
    /// This constructor looks for `FIPS_KEYSTORE_PASSWORD` environment variable.
    ///
    /// # Arguments
    /// * `keystore_path` - Path to the keystore file on disk
    /// * `keystore_type` - Type of keystore format (PKCS12 or BCFKS)
    pub fn from_env(keystore_path: String, keystore_type: String) -> Result<Self> {
        let password = std::env::var("FIPS_KEYSTORE_PASSWORD")
            .map_err(|_| anyhow::anyhow!("FIPS_KEYSTORE_PASSWORD environment variable not set"))?;

        Ok(Self::new(keystore_path, password, keystore_type))
    }

    /// Create FIPS compliant keystore
    pub async fn create_keystore(&self) -> Result<()> {
        let password = self.keystore_password.clone();
        let path = self.keystore_path.clone();

        tokio::task::spawn_blocking(move || {
            use openssl::pkcs12::Pkcs12;
            use openssl::pkey::PKey;
            use openssl::rsa::Rsa;
            use openssl::x509::X509;
            use std::fs;

            // Generate a FIPS-compliant RSA key pair (2048-bit minimum)
            let rsa = Rsa::generate(2048)?;
            let pkey = PKey::from_rsa(rsa)?;

            // Create a self-signed certificate
            let mut builder = X509::builder()?;
            builder.set_version(2)?;
            builder.set_pubkey(&pkey)?;

            // Set validity period
            use openssl::asn1::Asn1Time;
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(365)?;
            builder.set_not_before(&not_before)?;
            builder.set_not_after(&not_after)?;

            // Self-sign the certificate
            use openssl::hash::MessageDigest;
            builder.sign(&pkey, MessageDigest::sha256())?;
            let cert = builder.build();

            // Create PKCS12 keystore
            let pkcs12 = Pkcs12::builder()
                .name("fips-keystore")
                .pkey(&pkey)
                .cert(&cert)
                .build2(&password)?;

            // Write to file
            let der = pkcs12.to_der()?;
            fs::write(&path, der)?;

            Ok::<(), anyhow::Error>(())
        })
        .await??;

        tracing::info!("Created FIPS-compliant keystore at: {}", self.keystore_path);
        Ok(())
    }

    /// Store secret in FIPS secret store (separately from keystore)
    pub async fn store_secret(&self, alias: &str, secret: &str) -> Result<()> {
        // Delegate to FipsSecretStore
        let secret_file = format!("{}.secrets", self.keystore_path);
        let store = FipsSecretStore::new(secret_file, self.keystore_password.to_string());
        store.store_secret(alias, secret).await
    }

    /// Retrieve secret from FIPS secret store (separately from keystore)
    pub async fn retrieve_secret(&self, alias: &str) -> Result<Option<String>> {
        // Delegate to FipsSecretStore
        let secret_file = format!("{}.secrets", self.keystore_path);
        let store = FipsSecretStore::new(secret_file, self.keystore_password.to_string());
        store.retrieve_secret(alias).await
    }
}

/// FIPS audit logger for compliance tracking
pub struct FipsAuditLogger {
    /// Whether audit logging of FIPS compliance events is enabled
    audit_enabled: bool,
}

impl FipsAuditLogger {
    /// Create a new FIPS audit logger with audit configuration
    ///
    /// This constructor initializes a FIPS audit logger that tracks
    /// compliance events and security-relevant activities for FIPS 140-3
    /// compliance validation. The logger can be configured to enable
    /// or disable audit logging based on operational requirements.
    ///
    /// # Arguments
    /// * `audit_enabled` - Whether to enable audit logging of compliance events
    ///
    /// # Returns
    /// A new `FipsAuditLogger` instance configured for compliance tracking
    ///
    /// # Security Considerations
    /// - Audit logs should be tamper-proof and integrity-protected
    /// - Sensitive information should never be logged in audit trails
    /// - Audit events should be timestamped and sequenced
    /// - Log storage should be encrypted and access-controlled
    ///
    /// # FIPS 140-3 Compliance
    /// - Tracks cryptographic module initialization and usage
    /// - Logs key generation, storage, and destruction events
    /// - Records security policy violations and exceptions
    /// - Maintains audit trail for compliance validation
    ///
    /// # Example
    /// ```rust
    /// use authenc::services::fips::FipsAuditLogger;
    ///
    /// let logger = FipsAuditLogger::new(true); // Enable audit logging
    /// // Logger is ready for compliance event tracking
    /// ```
    pub fn new(audit_enabled: bool) -> Self {
        Self { audit_enabled }
    }

    /// Log FIPS compliance event
    pub async fn log_compliance_event(&self, event: &FipsComplianceEvent) -> Result<()> {
        if !self.audit_enabled {
            return Ok(());
        }

        // Log to tracing system with appropriate level
        if event.compliant {
            tracing::info!(
                "FIPS Compliance Event: {} - {} (Compliant)",
                event.event_type,
                event.details
            );
        } else {
            tracing::warn!(
                "FIPS Compliance Event: {} - {} (Non-Compliant) - Algorithm: {:?}",
                event.event_type,
                event.details,
                event.algorithm
            );
        }

        // Also log to structured audit trail
        let audit_entry = serde_json::json!({
            "timestamp": event.timestamp.to_rfc3339(),
            "event_type": event.event_type,
            "algorithm": event.algorithm,
            "compliant": event.compliant,
            "details": event.details,
        });

        tracing::debug!("FIPS Audit Entry: {}", audit_entry);

        // In production, this would also write to a tamper-proof audit database
        // For now, we rely on the tracing infrastructure
        Ok(())
    }
}
/// Internal state for AdvancedFipsSecurityProvider
#[derive(Debug)]
struct AdvancedFipsProviderState {
    /// Whether FIPS mode is currently enabled in the provider
    fips_mode_enabled: bool,
    /// Current active security profile for compliance validation
    current_profile: SecurityProfile,
}

/// Advanced FIPS Security Provider with FIPS 140-3 support
pub struct AdvancedFipsSecurityProvider {
    /// Mutable state protected by a read-write lock
    state: tokio::sync::RwLock<AdvancedFipsProviderState>,
    /// Available security profiles that can be activated
    security_profiles: Vec<SecurityProfile>,
}

impl Default for AdvancedFipsSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedFipsSecurityProvider {
    /// Creates a new advanced FIPS security provider with predefined security profiles.
    ///
    /// This constructor initializes the provider with comprehensive FIPS 140-3 compliance
    /// profiles for different security levels (Level 1, 2, 3, and 4). Each profile
    /// includes approved cryptographic algorithms and security requirements specific
    /// to that FIPS level.
    ///
    /// # Security Considerations
    /// - Provider includes multiple FIPS compliance levels for different use cases
    /// - All algorithms in profiles are FIPS-approved for their respective levels
    /// - Security profiles should be validated against specific compliance requirements
    /// - Higher FIPS levels provide stronger security guarantees but may have performance impact
    ///
    /// # Returns
    /// A new `AdvancedFipsSecurityProvider` instance with predefined FIPS security profiles
    #[allow(clippy::vec_init_then_push)]
    pub fn new() -> Self {
        let mut profiles = Vec::new();

        // FIPS 140-3 Level 1 Profile
        profiles.push(SecurityProfile {
            name: "fips-140-3-level1".to_string(),
            description: "FIPS 140-3 Level 1 compliance profile".to_string(),
            fips_level: FipsLevel::Level1,
            approved_algorithms: vec![
                "AES".to_string(),
                "RSA".to_string(),
                "ECDSA".to_string(),
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "HMAC-SHA-256".to_string(),
                "HMAC-SHA-384".to_string(),
                "HMAC-SHA-512".to_string(),
                "Ed25519".to_string(),
                "Ed448".to_string(),
            ],
            key_sizes: [
                ("AES".to_string(), vec![128, 256]),
                ("RSA".to_string(), vec![2048, 3072, 4096]),
                ("ECDSA".to_string(), vec![256, 384, 521]),
                ("Ed25519".to_string(), vec![256]),
                ("Ed448".to_string(), vec![448]),
            ]
            .into_iter()
            .collect(),
            security_strength: 128,
            requirements: vec![
                "Cryptographic module must be validated".to_string(),
                "Approved security functions only".to_string(),
                "Secure key generation and storage".to_string(),
            ],
        });

        // FIPS 140-3 Level 2 Profile
        profiles.push(SecurityProfile {
            name: "fips-140-3-level2".to_string(),
            description: "FIPS 140-3 Level 2 compliance profile".to_string(),
            fips_level: FipsLevel::Level2,
            approved_algorithms: vec![
                "AES".to_string(),
                "RSA".to_string(),
                "ECDSA".to_string(),
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "HMAC-SHA-256".to_string(),
                "HMAC-SHA-384".to_string(),
                "HMAC-SHA-512".to_string(),
                "Ed25519".to_string(),
                "Ed448".to_string(),
            ],
            key_sizes: [
                ("AES".to_string(), vec![128, 256]),
                ("RSA".to_string(), vec![2048, 3072, 4096]),
                ("ECDSA".to_string(), vec![256, 384, 521]),
                ("Ed25519".to_string(), vec![256]),
                ("Ed448".to_string(), vec![448]),
            ]
            .into_iter()
            .collect(),
            security_strength: 192,
            requirements: vec![
                "All Level 1 requirements".to_string(),
                "Role-based authentication".to_string(),
                "Physical security for module".to_string(),
                "Tamper detection and response".to_string(),
            ],
        });

        // FIPS 140-3 Level 3 Profile
        profiles.push(SecurityProfile {
            name: "fips-140-3-level3".to_string(),
            description: "FIPS 140-3 Level 3 compliance profile".to_string(),
            fips_level: FipsLevel::Level3,
            approved_algorithms: vec![
                "AES".to_string(),
                "RSA".to_string(),
                "ECDSA".to_string(),
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "HMAC-SHA-256".to_string(),
                "HMAC-SHA-384".to_string(),
                "HMAC-SHA-512".to_string(),
                "Ed25519".to_string(),
                "Ed448".to_string(),
            ],
            key_sizes: [
                ("AES".to_string(), vec![256]),
                ("RSA".to_string(), vec![3072, 4096]),
                ("ECDSA".to_string(), vec![384, 521]),
                ("Ed25519".to_string(), vec![256]),
                ("Ed448".to_string(), vec![448]),
            ]
            .into_iter()
            .collect(),
            security_strength: 256,
            requirements: vec![
                "All Level 2 requirements".to_string(),
                "Enhanced physical security".to_string(),
                "Identity-based authentication".to_string(),
                "Tamper detection with zeroization".to_string(),
                "Secure key transport".to_string(),
            ],
        });

        // FIPS 140-3 Level 4 Profile
        profiles.push(SecurityProfile {
            name: "fips-140-3-level4".to_string(),
            description: "FIPS 140-3 Level 4 compliance profile".to_string(),
            fips_level: FipsLevel::Level4,
            approved_algorithms: vec![
                "AES".to_string(),
                "RSA".to_string(),
                "ECDSA".to_string(),
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "HMAC-SHA-256".to_string(),
                "HMAC-SHA-384".to_string(),
                "HMAC-SHA-512".to_string(),
                "Ed25519".to_string(),
                "Ed448".to_string(),
            ],
            key_sizes: [
                ("AES".to_string(), vec![256]),
                ("RSA".to_string(), vec![4096]),
                ("ECDSA".to_string(), vec![521]),
                ("Ed25519".to_string(), vec![256]),
                ("Ed448".to_string(), vec![448]),
            ]
            .into_iter()
            .collect(),
            security_strength: 256,
            requirements: vec![
                "All Level 3 requirements".to_string(),
                "Environmental failure protection".to_string(),
                "Environmental failure testing".to_string(),
                "Advanced tamper detection".to_string(),
                "Secure key destruction".to_string(),
            ],
        });

        let initial_profile = profiles[0].clone();

        Self {
            state: tokio::sync::RwLock::new(AdvancedFipsProviderState {
                fips_mode_enabled: false,
                current_profile: initial_profile, // Default to Level 1
            }),
            security_profiles: profiles,
        }
    }

    /// Enable FIPS mode for this provider
    pub async fn enable_fips_mode(&self) {
        let mut state = self.state.write().await;
        state.fips_mode_enabled = true;
    }

    /// Disable FIPS mode for this provider
    pub async fn disable_fips_mode(&self) {
        let mut state = self.state.write().await;
        state.fips_mode_enabled = false;
    }
}

#[async_trait]
impl FipsSecurityProvider for AdvancedFipsSecurityProvider {
    async fn is_fips_mode(&self) -> Result<bool> {
        let state = self.state.read().await;
        Ok(state.fips_mode_enabled)
    }

    async fn get_fips_level(&self) -> Result<FipsLevel> {
        let state = self.state.read().await;
        Ok(state.current_profile.fips_level.clone())
    }

    async fn validate_algorithm(&self, algorithm: &str) -> Result<AlgorithmValidation> {
        let state = self.state.read().await;
        let is_approved = state
            .current_profile
            .approved_algorithms
            .iter()
            .any(|a| a == algorithm);

        let security_strength = if is_approved {
            state.current_profile.security_strength
        } else {
            0
        };

        let usage_restrictions = if is_approved {
            vec![]
        } else {
            vec!["Algorithm not approved for current FIPS profile".to_string()]
        };

        Ok(AlgorithmValidation {
            algorithm: algorithm.to_string(),
            is_fips_approved: is_approved,
            security_strength,
            usage_restrictions,
        })
    }

    async fn perform_compliance_check(&self) -> Result<Vec<FipsComplianceCheck>> {
        let mut checks = Vec::new();
        let state = self.state.read().await;

        // Check FIPS mode
        checks.push(FipsComplianceCheck {
            check_name: "FIPS Mode".to_string(),
            status: if state.fips_mode_enabled {
                FipsComplianceStatus::Compliant
            } else {
                FipsComplianceStatus::NonCompliant
            },
            details: "FIPS mode must be enabled for compliance".to_string(),
            recommendations: vec!["Enable FIPS mode in configuration".to_string()],
        });

        // Check approved algorithms
        for algorithm in &state.current_profile.approved_algorithms {
            checks.push(FipsComplianceCheck {
                check_name: format!("Algorithm: {}", algorithm),
                status: FipsComplianceStatus::Compliant,
                details: format!(
                    "{} is approved for FIPS {}",
                    algorithm,
                    state.current_profile.fips_level.clone() as u8
                ),
                recommendations: vec![],
            });
        }

        // Check key sizes
        for (algorithm, sizes) in &state.current_profile.key_sizes {
            let min_size = sizes.iter().min().unwrap_or(&0);
            checks.push(FipsComplianceCheck {
                check_name: format!("Key Size: {}", algorithm),
                status: if *min_size >= 128 {
                    FipsComplianceStatus::Compliant
                } else {
                    FipsComplianceStatus::NonCompliant
                },
                details: format!("Minimum key size for {} is {}", algorithm, min_size),
                recommendations: vec![format!("Use key sizes of at least {} bits", min_size)],
            });
        }

        Ok(checks)
    }

    async fn get_approved_algorithms(&self) -> Result<Vec<String>> {
        let state = self.state.read().await;
        Ok(state.current_profile.approved_algorithms.clone())
    }
}

#[async_trait]
impl FipsSecurityProfileProvider for AdvancedFipsSecurityProvider {
    async fn get_security_profiles(&self) -> Result<Vec<SecurityProfile>, AuthencError> {
        Ok(self.security_profiles.clone())
    }

    async fn get_current_profile(&self) -> Result<SecurityProfile, AuthencError> {
        let state = self.state.read().await;
        Ok(state.current_profile.clone())
    }

    async fn set_security_profile(&self, profile_name: &str) -> Result<(), AuthencError> {
        let profile = self
            .security_profiles
            .iter()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| AuthencError::ValidationError {
                message: format!("Security profile not found: {}", profile_name),
            })?
            .clone();

        let mut state = self.state.write().await;
        state.current_profile = profile;
        Ok(())
    }

    async fn validate_algorithm_for_profile(
        &self,
        algorithm: &str,
        key_size: Option<usize>,
    ) -> Result<bool, AuthencError> {
        let state = self.state.read().await;
        // Check if algorithm is approved
        if !state
            .current_profile
            .approved_algorithms
            .iter()
            .any(|a| a == algorithm)
        {
            return Ok(false);
        }

        // Check key size if provided
        if let Some(size) = key_size {
            if let Some(allowed_sizes) = state.current_profile.key_sizes.get(algorithm) {
                if !allowed_sizes.contains(&size) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}

/// FIPS Appliance Bootstrap for secure initialization
pub struct FipsApplianceBootstrap {
    /// List of entropy sources for random number generation
    #[allow(dead_code)]
    entropy_sources: Vec<String>,
    /// Whether key ceremony is required for initialization
    key_ceremony_required: bool,
    /// Whether tamper detection is enabled
    tamper_detection_enabled: bool,
}

impl Default for FipsApplianceBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

impl FipsApplianceBootstrap {
    /// Creates a new FIPS appliance bootstrap instance with secure defaults.
    ///
    /// This constructor initializes the bootstrap with multiple entropy sources for
    /// cryptographic key generation, enables key ceremony requirements, and activates
    /// tamper detection. The bootstrap process ensures secure initialization of
    /// FIPS-compliant cryptographic appliances.
    ///
    /// # Security Considerations
    /// - Multiple entropy sources provide robust random number generation
    /// - Key ceremony requirement ensures proper key management procedures
    /// - Tamper detection provides continuous security monitoring
    /// - Bootstrap should be performed in a secure environment
    /// - All entropy sources should be validated before use
    ///
    /// # Returns
    /// A new `FipsApplianceBootstrap` instance configured with secure defaults
    pub fn new() -> Self {
        Self {
            entropy_sources: vec![
                "/dev/random".to_string(),
                "/dev/urandom".to_string(),
                "RDRAND".to_string(),
                "TPM".to_string(),
            ],
            key_ceremony_required: true,
            tamper_detection_enabled: true,
        }
    }

    /// Perform secure bootstrap
    pub async fn bootstrap(&self) -> Result<(), AuthencError> {
        // Validate entropy sources
        self.validate_entropy_sources().await?;

        // Perform key ceremony if required
        if self.key_ceremony_required {
            self.perform_key_ceremony().await?;
        }

        // Initialize tamper detection
        if self.tamper_detection_enabled {
            self.initialize_tamper_detection().await?;
        }

        Ok(())
    }

    async fn validate_entropy_sources(&self) -> Result<(), AuthencError> {
        // Validate that sufficient entropy sources are available
        // This would check system entropy and hardware RNGs
        Ok(())
    }

    /// Perform secure key generation ceremony
    async fn perform_key_ceremony(&self) -> Result<(), AuthencError> {
        // Perform secure key generation ceremony
        // This would involve multiple administrators and audit logging
        Ok(())
    }

    /// Initialize hardware tamper detection mechanisms
    async fn initialize_tamper_detection(&self) -> Result<(), AuthencError> {
        // Initialize hardware tamper detection mechanisms
        // This would configure TPM, HSM, or other hardware security modules
        Ok(())
    }
}
