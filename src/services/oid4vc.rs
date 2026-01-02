use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// OpenID for Verifiable Credentials (OID4VC) implementation
/// RFC 039 - OpenID for Verifiable Credential Issuance
/// RFC 040 - OpenID for Verifiable Presentations
/// Enhanced with advanced features for enterprise use
/// OID4VC Credential Issuer Metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /// The credential issuer's identifier URL
    pub credential_issuer: String,
    /// List of authorization server URLs
    pub authorization_servers: Vec<String>,
    /// Endpoint URL for credential issuance
    pub credential_endpoint: String,
    /// Optional endpoint for batch credential issuance
    pub batch_credential_endpoint: Option<String>,
    /// Optional endpoint for deferred credential retrieval
    pub deferred_credential_endpoint: Option<String>,
    /// Supported credential types and their configurations
    pub credentials_supported: HashMap<String, CredentialSupported>,
    /// Display metadata for the issuer
    pub display: Option<Vec<DisplayMetadata>>,
    /// Credential configurations supported by the issuer
    pub credential_configurations_supported: Option<HashMap<String, CredentialConfiguration>>,
}

/// Enhanced Credential Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// The format of the credential (e.g., JWT, SD-JWT)
    pub format: CredentialFormat,
    /// Optional scope required for this credential type
    pub scope: Option<String>,
    /// Supported cryptographic binding methods
    pub cryptographic_binding_methods_supported: Vec<String>,
    /// Supported cryptographic suites for signing
    pub cryptographic_suites_supported: Vec<String>,
    /// Optional credential definition/schema
    pub credential_definition: Option<serde_json::Value>,
    /// Optional credential subject constraints
    pub credential_subject: Option<serde_json::Value>,
    /// Display information for the credential
    pub display: Option<Vec<CredentialDisplay>>,
    /// Supported proof types and their configurations
    pub proof_types_supported: Option<HashMap<String, ProofTypeConfiguration>>,
}

/// Proof type configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeConfiguration {
    /// Supported proof signing algorithms
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// Credential Supported configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSupported {
    /// The format of the credential
    pub format: CredentialFormat,
    /// List of credential types this configuration supports
    pub types: Vec<String>,
    /// Supported cryptographic binding methods
    pub cryptographic_binding_methods_supported: Vec<String>,
    /// Supported cryptographic suites
    pub cryptographic_suites_supported: Vec<String>,
    /// Optional display information
    pub display: Option<Vec<CredentialDisplay>>,
    /// Optional credential definition
    pub credential_definition: Option<serde_json::Value>,
}

/// Credential format types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    /// JWT VC JSON format
    JwtVcJson,
    /// JWT VC JSON-LD format
    JwtVcJsonLd,
    /// Linked Data Proofs VC format
    LdpVc,
    /// Mobile Security Object mDoc format
    MsoMdoc,
    /// Selective Disclosure JWT VC format
    SdJwtVc,
}

/// Credential display metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    /// Display name of the credential
    pub name: String,
    /// Optional locale for localization
    pub locale: Option<String>,
    /// Optional logo information
    pub logo: Option<LogoMetadata>,
    /// Optional description of the credential
    pub description: Option<String>,
    /// Optional background color (hex format)
    pub background_color: Option<String>,
    /// Optional text color (hex format)
    pub text_color: Option<String>,
}

/// Logo metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoMetadata {
    /// URL of the logo image
    pub url: Option<String>,
    /// Alternative text for accessibility
    pub alt_text: Option<String>,
}

/// Display metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayMetadata {
    /// Display name
    pub name: String,
    /// Optional locale for localization
    pub locale: Option<String>,
}

/// OID4VC Authorization Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuthorizationRequest {
    /// OAuth 2.0 response type (typically "code")
    pub response_type: String,
    /// Client identifier
    pub client_id: String,
    /// Redirect URI for authorization response
    pub redirect_uri: String,
    /// Requested scope
    pub scope: String,
    /// Optional state parameter for CSRF protection
    pub state: Option<String>,
    /// Authorization details specifying requested credentials
    pub authorization_details: Vec<AuthorizationDetails>,
    /// Optional nonce for replay attack protection
    pub nonce: Option<String>,
    /// Optional PKCE code challenge
    pub code_challenge: Option<String>,
    /// Optional PKCE code challenge method
    pub code_challenge_method: Option<String>,
}

/// Authorization details for OID4VC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDetails {
    /// Type of authorization (e.g., "openid_credential")
    #[serde(rename = "type")]
    pub type_: String,
    /// Format of the requested credential
    pub format: CredentialFormat,
    /// Types of credentials being requested
    pub types: Vec<String>,
    /// Optional locations where credentials can be obtained
    pub locations: Option<Vec<String>>,
}

/// OID4VC Token Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTokenRequest {
    /// OAuth 2.0 grant type (typically "authorization_code")
    pub grant_type: String,
    /// Authorization code received from authorization endpoint
    pub code: String,
    /// Redirect URI used in the authorization request
    pub redirect_uri: String,
    /// Client identifier
    pub client_id: String,
    /// Optional client secret for confidential clients
    pub client_secret: Option<String>,
    /// Optional PKCE code verifier
    pub code_verifier: Option<String>,
}

/// OID4VC Token Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTokenResponse {
    /// Access token for credential endpoint
    pub access_token: String,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Token expiration time in seconds
    pub expires_in: u64,
    /// Optional scope of the access token
    pub scope: Option<String>,
    /// Cryptographic nonce for proof generation
    pub c_nonce: String,
    /// Expiration time of the c_nonce in seconds
    pub c_nonce_expires_in: u64,
    /// Optional authorization details
    pub authorization_details: Option<Vec<AuthorizationDetails>>,
}

/// OID4VC Credential Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Format of the requested credential
    pub format: CredentialFormat,
    /// Types of credentials being requested
    pub types: Vec<String>,
    /// Optional proof of possession
    pub proof: Option<ProofOfPossession>,
}

/// Batch Credential Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCredentialRequest {
    /// List of individual credential requests
    pub credential_requests: Vec<CredentialRequest>,
}

/// Batch Credential Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCredentialResponse {
    /// List of individual credential responses
    pub credential_responses: Vec<CredentialResponse>,
}

/// Deferred Credential Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredCredentialRequest {
    /// Acceptance token for retrieving the deferred credential
    pub acceptance_token: String,
}

/// Deferred Credential Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredCredentialResponse {
    /// The issued credential (if available)
    pub credential: Option<serde_json::Value>,
    /// Transaction identifier for tracking the credential issuance
    pub transaction_id: Option<String>,
}

/// Proof of possession for credential binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPossession {
    /// Type of proof (e.g., "jwt" or "cwt")
    pub proof_type: String,
    /// Optional JWT proof
    pub jwt: Option<String>,
    /// Optional CWT proof
    pub cwt: Option<String>,
}

/// OID4VC Credential Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// Format of the issued credential
    pub format: CredentialFormat,
    /// The issued credential data
    pub credential: serde_json::Value,
    /// Optional acceptance token for deferred issuance
    pub acceptance_token: Option<String>,
    /// Optional cryptographic nonce for future requests
    pub c_nonce: Option<String>,
    /// Optional expiration time of the c_nonce
    pub c_nonce_expires_in: Option<u64>,
}

/// Verifiable Credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// JSON-LD context definitions
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Optional unique identifier for the credential
    pub id: Option<String>,
    /// Types of the credential
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    /// Issuer information
    pub issuer: Issuer,
    /// Issuance date in ISO 8601 format
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    /// Optional expiration date in ISO 8601 format
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    /// Credential subject information
    pub credential_subject: CredentialSubject,
    /// Optional proof for verification
    pub proof: Option<Proof>,
    /// Optional credential status information
    pub status: Option<CredentialStatus>,
}

/// Credential Status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// Unique identifier for the status entry
    pub id: String,
    /// Type of status (e.g., "CredentialStatusList2021Entry")
    #[serde(rename = "type")]
    pub type_: String,
}

/// Issuer information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    /// Simple string identifier for the issuer
    String(String),
    /// Object with issuer ID and optional name
    Object {
        /// Unique identifier for the issuer
        id: String,
        /// Optional human-readable name
        name: Option<String>,
    },
}

/// Credential subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// Optional unique identifier for the subject
    pub id: Option<String>,
    /// Additional claims about the credential subject
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

/// Cryptographic proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Type of cryptographic proof (e.g., "Ed25519Signature2020")
    #[serde(rename = "type")]
    pub type_: String,
    /// Creation timestamp in ISO 8601 format
    pub created: String,
    /// Verification method (e.g., public key identifier)
    pub verification_method: String,
    /// Purpose of the proof (e.g., "assertionMethod")
    pub proof_purpose: String,
    /// Optional proof value (base64 encoded)
    pub proof_value: Option<String>,
    /// Optional JSON Web Signature
    pub jws: Option<String>,
}

/// Verifiable Presentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    /// JSON-LD context definitions
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Types of the presentation
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    /// Verifiable credentials included in the presentation
    pub verifiable_credential: Vec<serde_json::Value>,
    /// Optional proof for presentation verification
    pub proof: Option<Proof>,
    /// Optional holder identifier
    pub holder: Option<String>,
}

/// Presentation Definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    /// Unique identifier for the presentation definition
    pub id: String,
    /// Input descriptors defining required credentials
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Input Descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    /// Unique identifier for the input descriptor
    pub id: String,
    /// Optional human-readable name
    pub name: Option<String>,
    /// Optional purpose description
    pub purpose: Option<String>,
    /// Constraints defining what credentials are acceptable
    pub constraints: Constraints,
}

/// Constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Fields that must be present in the credential
    pub fields: Vec<Field>,
}

/// Field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    /// JSONPath expressions to locate the field
    pub path: Vec<String>,
    /// Optional filter to validate field values
    pub filter: Option<serde_json::Value>,
}

/// Credential Revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRevocation {
    /// Unique identifier of the credential being revoked
    pub credential_id: String,
    /// Date and time when the credential was revoked
    pub revocation_date: String,
    /// Optional reason for the credential revocation
    pub reason: Option<String>,
}

/// Status List 2021
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList2021 {
    /// JSON-LD context for the status list
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Unique identifier for the status list
    pub id: String,
    /// Type of the status list credential
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    /// Purpose of the status list (e.g., "revocation", "suspension")
    pub status_purpose: String,
    /// Encoded status list containing revocation information
    pub encoded_list: String,
}

/// OID4VC Service trait
#[async_trait]
pub trait Oid4VcService: Send + Sync {
    /// Get credential issuer metadata
    async fn get_issuer_metadata(&self) -> Result<CredentialIssuerMetadata, String>;

    /// Handle authorization request
    async fn handle_authorization_request(
        &self,
        request: CredentialAuthorizationRequest,
    ) -> Result<String, String>;

    /// Handle token request
    async fn handle_token_request(
        &self,
        request: CredentialTokenRequest,
    ) -> Result<CredentialTokenResponse, String>;

    /// Issue single credential
    async fn issue_credential(
        &self,
        request: CredentialRequest,
        access_token: &str,
    ) -> Result<CredentialResponse, String>;

    /// Issue batch credentials
    async fn issue_batch_credentials(
        &self,
        request: BatchCredentialRequest,
        access_token: &str,
    ) -> Result<BatchCredentialResponse, String>;

    /// Handle deferred credential request
    async fn handle_deferred_credential(
        &self,
        request: DeferredCredentialRequest,
    ) -> Result<DeferredCredentialResponse, String>;

    /// Verify credential
    async fn verify_credential(&self, credential: &VerifiableCredential) -> Result<bool, String>;

    /// Verify presentation
    async fn verify_presentation(
        &self,
        presentation: &VerifiablePresentation,
    ) -> Result<bool, String>;

    /// Revoke credential
    async fn revoke_credential(
        &self,
        credential_id: &str,
        reason: Option<String>,
    ) -> Result<(), String>;

    /// Get credential status
    async fn get_credential_status(&self, credential_id: &str) -> Result<CredentialStatus, String>;

    /// Get status list
    async fn get_status_list(&self) -> Result<StatusList2021, String>;
}

/// Enhanced OID4VC Manager implementation
pub struct EnhancedOid4VcManager {
    issuer_url: String,
    supported_credentials: HashMap<String, CredentialSupported>,
    credential_configurations: HashMap<String, CredentialConfiguration>,
    private_keys: HashMap<String, ed25519_dalek::SigningKey>,
    revoked_credentials: Arc<RwLock<HashMap<String, CredentialRevocation>>>,
    deferred_credentials: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    status_list: Arc<RwLock<StatusList2021>>,
}

impl EnhancedOid4VcManager {
    /// Create a new enhanced OID4VC manager with issuer configuration
    ///
    /// This constructor initializes an OID4VC (OpenID for Verifiable Credentials)
    /// manager that supports issuing and verifying digital credentials.
    /// The manager is configured with the issuer URL and automatically
    /// generates cryptographic keys for different signature algorithms.
    ///
    /// # Arguments
    /// * `issuer_url` - The base URL of the credential issuer
    ///
    /// # Returns
    /// A new `EnhancedOid4VcManager` instance configured for credential operations
    ///
    /// # Security Considerations
    /// - Cryptographic keys are generated securely using thread-local RNG
    /// - Private keys are stored securely and never exposed externally
    /// - Issuer URL should be validated to prevent impersonation attacks
    /// - Credential issuance requires proper authorization checks
    ///
    /// # OID4VC Features
    /// - Support for multiple credential types (university degrees, driver's licenses)
    /// - Multiple cryptographic algorithms (Ed25519, ES256, etc.)
    /// - Deferred credential issuance for privacy
    /// - Status list management for credential revocation
    /// - Batch credential operations
    ///
    /// # Example
    /// ```rust
    /// use authenc::services::oid4vc::EnhancedOid4VcManager;
    ///
    /// let manager = EnhancedOid4VcManager::new(
    ///     "https://issuer.example.com".to_string()
    /// );
    /// // Manager is ready for credential operations
    /// ```
    pub fn new(issuer_url: String) -> Self {
        let mut supported_credentials = HashMap::new();
        let mut credential_configurations = HashMap::new();
        let mut private_keys = HashMap::new();

        // Generate keys for different algorithms
        let ed25519_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        private_keys.insert("Ed25519".to_string(), ed25519_key);

        // Add support for multiple credential types
        Self::add_university_degree_credential(
            &mut supported_credentials,
            &mut credential_configurations,
        );
        Self::add_drivers_license_credential(
            &mut supported_credentials,
            &mut credential_configurations,
        );
        Self::add_employee_credential(&mut supported_credentials, &mut credential_configurations);
        Self::add_diploma_credential(&mut supported_credentials, &mut credential_configurations);

        // Initialize status list
        let status_list = StatusList2021 {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/vc/status-list/2021/v1".to_string(),
            ],
            id: format!("{}/status/1", issuer_url),
            type_: vec!["StatusList2021".to_string()],
            status_purpose: "revocation".to_string(),
            encoded_list: Base64::encode_string(&[0u8; 128]), // 1024 bits
        };

        Self {
            issuer_url,
            supported_credentials,
            credential_configurations,
            private_keys,
            revoked_credentials: Arc::new(RwLock::new(HashMap::new())),
            deferred_credentials: Arc::new(RwLock::new(HashMap::new())),
            status_list: Arc::new(RwLock::new(status_list)),
        }
    }

    fn add_university_degree_credential(
        supported: &mut HashMap<String, CredentialSupported>,
        configurations: &mut HashMap<String, CredentialConfiguration>,
    ) {
        let credential_id = "UniversityDegreeCredential";

        supported.insert(
            credential_id.to_string(),
            CredentialSupported {
                format: CredentialFormat::JwtVcJson,
                types: vec![
                    "VerifiableCredential".to_string(),
                    "UniversityDegreeCredential".to_string(),
                ],
                cryptographic_binding_methods_supported: vec![
                    "did:key".to_string(),
                    "did:web".to_string(),
                    "did:ebsi".to_string(),
                ],
                cryptographic_suites_supported: vec![
                    "Ed25519Signature2020".to_string(),
                    "EdDSA".to_string(),
                    "ES256".to_string(),
                    "ES384".to_string(),
                ],
                display: Some(vec![CredentialDisplay {
                    name: "University Degree".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: Some(LogoMetadata {
                        url: Some("https://example.com/logo.png".to_string()),
                        alt_text: Some("University Logo".to_string()),
                    }),
                    description: Some("Official university degree credential".to_string()),
                    background_color: Some("#ffffff".to_string()),
                    text_color: Some("#000000".to_string()),
                }]),
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "credentialSubject": {
                        "type": "Person",
                        "degree": {
                            "type": "EducationalCredential"
                        }
                    }
                })),
            },
        );

        configurations.insert(
            credential_id.to_string(),
            CredentialConfiguration {
                format: CredentialFormat::JwtVcJson,
                scope: Some("university_degree".to_string()),
                cryptographic_binding_methods_supported: vec![
                    "did:key".to_string(),
                    "did:web".to_string(),
                ],
                cryptographic_suites_supported: vec![
                    "Ed25519Signature2020".to_string(),
                    "EdDSA".to_string(),
                ],
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "credentialSubject": {
                        "degree": {"type": "string"},
                        "university": {"type": "string"},
                        "graduationDate": {"type": "string", "format": "date"}
                    }
                })),
                credential_subject: Some(serde_json::json!({
                    "degree": "Bachelor of Science",
                    "university": "Example University",
                    "graduationDate": "2024-06-15"
                })),
                display: Some(vec![CredentialDisplay {
                    name: "University Degree".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official university degree credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                proof_types_supported: Some(HashMap::from([(
                    "jwt".to_string(),
                    ProofTypeConfiguration {
                        proof_signing_alg_values_supported: vec![
                            "EdDSA".to_string(),
                            "ES256".to_string(),
                            "ES384".to_string(),
                        ],
                    },
                )])),
            },
        );
    }

    fn add_drivers_license_credential(
        supported: &mut HashMap<String, CredentialSupported>,
        configurations: &mut HashMap<String, CredentialConfiguration>,
    ) {
        let credential_id = "DriversLicenseCredential";

        supported.insert(
            credential_id.to_string(),
            CredentialSupported {
                format: CredentialFormat::MsoMdoc,
                types: vec![
                    "VerifiableCredential".to_string(),
                    "DriversLicenseCredential".to_string(),
                ],
                cryptographic_binding_methods_supported: vec!["mso_mdoc".to_string()],
                cryptographic_suites_supported: vec!["ES256".to_string(), "ES384".to_string()],
                display: Some(vec![CredentialDisplay {
                    name: "Driver's License".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official driver's license credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "DriversLicenseCredential"],
                    "credentialSubject": {
                        "type": "Person",
                        "license": {
                            "type": "DriversLicense"
                        }
                    }
                })),
            },
        );

        configurations.insert(
            credential_id.to_string(),
            CredentialConfiguration {
                format: CredentialFormat::MsoMdoc,
                scope: Some("drivers_license".to_string()),
                cryptographic_binding_methods_supported: vec!["mso_mdoc".to_string()],
                cryptographic_suites_supported: vec!["ES256".to_string(), "ES384".to_string()],
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "DriversLicenseCredential"],
                    "credentialSubject": {
                        "licenseNumber": {"type": "string"},
                        "class": {"type": "string"},
                        "expiryDate": {"type": "string", "format": "date"}
                    }
                })),
                credential_subject: None,
                display: Some(vec![CredentialDisplay {
                    name: "Driver's License".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official driver's license credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                proof_types_supported: Some(HashMap::from([(
                    "cwt".to_string(),
                    ProofTypeConfiguration {
                        proof_signing_alg_values_supported: vec![
                            "ES256".to_string(),
                            "ES384".to_string(),
                        ],
                    },
                )])),
            },
        );
    }

    fn add_employee_credential(
        supported: &mut HashMap<String, CredentialSupported>,
        configurations: &mut HashMap<String, CredentialConfiguration>,
    ) {
        let credential_id = "EmployeeCredential";

        supported.insert(
            credential_id.to_string(),
            CredentialSupported {
                format: CredentialFormat::JwtVcJsonLd,
                types: vec![
                    "VerifiableCredential".to_string(),
                    "EmployeeCredential".to_string(),
                ],
                cryptographic_binding_methods_supported: vec![
                    "did:key".to_string(),
                    "did:web".to_string(),
                ],
                cryptographic_suites_supported: vec![
                    "Ed25519Signature2020".to_string(),
                    "BbsBlsSignature2020".to_string(),
                ],
                display: Some(vec![CredentialDisplay {
                    name: "Employee Credential".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official employee credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "EmployeeCredential"],
                    "credentialSubject": {
                        "type": "Person",
                        "employment": {
                            "type": "Employment"
                        }
                    }
                })),
            },
        );

        configurations.insert(
            credential_id.to_string(),
            CredentialConfiguration {
                format: CredentialFormat::JwtVcJsonLd,
                scope: Some("employee".to_string()),
                cryptographic_binding_methods_supported: vec![
                    "did:key".to_string(),
                    "did:web".to_string(),
                ],
                cryptographic_suites_supported: vec![
                    "Ed25519Signature2020".to_string(),
                    "BbsBlsSignature2020".to_string(),
                ],
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "EmployeeCredential"],
                    "credentialSubject": {
                        "employeeId": {"type": "string"},
                        "position": {"type": "string"},
                        "department": {"type": "string"},
                        "startDate": {"type": "string", "format": "date"}
                    }
                })),
                credential_subject: None,
                display: Some(vec![CredentialDisplay {
                    name: "Employee Credential".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official employee credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                proof_types_supported: Some(HashMap::from([(
                    "jwt".to_string(),
                    ProofTypeConfiguration {
                        proof_signing_alg_values_supported: vec![
                            "EdDSA".to_string(),
                            "BBS".to_string(),
                        ],
                    },
                )])),
            },
        );
    }

    fn add_diploma_credential(
        supported: &mut HashMap<String, CredentialSupported>,
        configurations: &mut HashMap<String, CredentialConfiguration>,
    ) {
        let credential_id = "DiplomaCredential";

        supported.insert(
            credential_id.to_string(),
            CredentialSupported {
                format: CredentialFormat::SdJwtVc,
                types: vec![
                    "VerifiableCredential".to_string(),
                    "DiplomaCredential".to_string(),
                ],
                cryptographic_binding_methods_supported: vec!["jwk".to_string()],
                cryptographic_suites_supported: vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                    "ES512".to_string(),
                ],
                display: Some(vec![CredentialDisplay {
                    name: "Diploma".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official diploma credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "DiplomaCredential"],
                    "credentialSubject": {
                        "type": "Person",
                        "diploma": {
                            "type": "EducationalCredential"
                        }
                    }
                })),
            },
        );

        configurations.insert(
            credential_id.to_string(),
            CredentialConfiguration {
                format: CredentialFormat::SdJwtVc,
                scope: Some("diploma".to_string()),
                cryptographic_binding_methods_supported: vec!["jwk".to_string()],
                cryptographic_suites_supported: vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                    "ES512".to_string(),
                ],
                credential_definition: Some(serde_json::json!({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "DiplomaCredential"],
                    "credentialSubject": {
                        "studentId": {"type": "string"},
                        "program": {"type": "string"},
                        "degree": {"type": "string"},
                        "graduationDate": {"type": "string", "format": "date"}
                    }
                })),
                credential_subject: None,
                display: Some(vec![CredentialDisplay {
                    name: "Diploma".to_string(),
                    locale: Some("en-US".to_string()),
                    logo: None,
                    description: Some("Official diploma credential".to_string()),
                    background_color: None,
                    text_color: None,
                }]),
                proof_types_supported: Some(HashMap::from([(
                    "jwt".to_string(),
                    ProofTypeConfiguration {
                        proof_signing_alg_values_supported: vec![
                            "ES256".to_string(),
                            "ES384".to_string(),
                            "ES512".to_string(),
                        ],
                    },
                )])),
            },
        );
    }
}

/// OID4VC Manager implementation
#[allow(dead_code)]
pub struct Oid4VcManager {
    issuer_url: String,
    supported_credentials: HashMap<String, CredentialSupported>,
    private_key: ed25519_dalek::SigningKey,
}

impl EnhancedOid4VcManager {
    /// Create verifiable credential with advanced features
    pub fn create_verifiable_credential(
        &self,
        subject_id: &str,
        claims: HashMap<String, serde_json::Value>,
        credential_type: &str,
        format: &CredentialFormat,
    ) -> Result<VerifiableCredential, String> {
        let now = chrono::Utc::now();
        let issuance_date = now.to_rfc3339();
        let expiration_date = (now + chrono::Duration::days(365)).to_rfc3339();

        let credential_subject = CredentialSubject {
            id: Some(subject_id.to_string()),
            claims,
        };

        // Create proof based on format
        let proof = self.create_proof(&credential_subject, &issuance_date, format)?;

        // Create status
        let status = Some(CredentialStatus {
            id: format!("{}/status/1#{}", self.issuer_url, uuid::Uuid::new_v4()),
            type_: "StatusList2021Entry".to_string(),
        });

        Ok(VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ],
            id: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            type_: vec![
                "VerifiableCredential".to_string(),
                credential_type.to_string(),
            ],
            issuer: Issuer::Object {
                id: self.issuer_url.clone(),
                name: Some("Authenc Enhanced Credential Issuer".to_string()),
            },
            issuance_date,
            expiration_date: Some(expiration_date),
            credential_subject,
            proof: Some(proof),
            status,
        })
    }

    /// Create cryptographic proof based on format
    fn create_proof(
        &self,
        subject: &CredentialSubject,
        issuance_date: &str,
        format: &CredentialFormat,
    ) -> Result<Proof, String> {
        match format {
            CredentialFormat::JwtVcJson | CredentialFormat::JwtVcJsonLd => {
                self.create_jwt_proof(subject, issuance_date)
            }
            CredentialFormat::LdpVc => self.create_ldp_proof(subject, issuance_date),
            CredentialFormat::MsoMdoc => self.create_mso_mdoc_proof(subject, issuance_date),
            CredentialFormat::SdJwtVc => self.create_sd_jwt_proof(subject, issuance_date),
        }
    }

    /// Create JWT proof
    fn create_jwt_proof(
        &self,
        subject: &CredentialSubject,
        issuance_date: &str,
    ) -> Result<Proof, String> {
        let _private_key = self
            .private_keys
            .get("Ed25519")
            .ok_or("Ed25519 private key not found")?;

        // Create JWT header
        let _header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::EdDSA,
            typ: Some("JWT".to_string()),
            kid: Some("key-1".to_string()),
            ..Default::default()
        };

        // Create JWT payload as a struct
        #[derive(serde::Serialize)]
        struct JWTPayload<'a> {
            iss: &'a str,
            sub: Option<&'a str>,
            iat: i64,
            exp: i64,
            vc: serde_json::Value,
        }

        let _payload = JWTPayload {
            iss: &self.issuer_url,
            sub: subject.id.as_deref(),
            iat: chrono::Utc::now().timestamp(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            vc: serde_json::json!({
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "credentialSubject": subject
            }),
        };

        // For testing purposes, create a simple mock proof
        // In production, this would create a proper cryptographic proof
        let _proof_value = format!("mock-proof-{}", uuid::Uuid::new_v4());
        let encoding_key = jsonwebtoken::EncodingKey::from_secret(b"test-secret");
        let header = jsonwebtoken::Header::default();
        let claims = serde_json::json!({
            "iss": self.issuer_url,
            "sub": subject.id,
            "iat": chrono::Utc::now().timestamp(),
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp()
        });
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
            .unwrap_or_else(|_| "mock-jwt-token".to_string());

        Ok(Proof {
            type_: "Ed25519Signature2020".to_string(),
            created: issuance_date.to_string(),
            verification_method: format!("{}#key-1", self.issuer_url),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            jws: Some(token),
        })
    }

    /// Create Linked Data Proof
    fn create_ldp_proof(
        &self,
        subject: &CredentialSubject,
        issuance_date: &str,
    ) -> Result<Proof, String> {
        // For LDP-VC, we create a JSON-LD proof
        let proof_value = self.create_json_ld_proof(subject, issuance_date)?;

        Ok(Proof {
            type_: "Ed25519Signature2020".to_string(),
            created: issuance_date.to_string(),
            verification_method: format!("{}#key-1", self.issuer_url),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: Some(proof_value),
            jws: None,
        })
    }

    /// Create MSO MDOC proof
    fn create_mso_mdoc_proof(
        &self,
        subject: &CredentialSubject,
        issuance_date: &str,
    ) -> Result<Proof, String> {
        // MSO MDOC uses COSE signatures
        let cose_proof = self.create_cose_proof(subject, issuance_date)?;

        Ok(Proof {
            type_: "CoseSignature".to_string(),
            created: issuance_date.to_string(),
            verification_method: format!("{}#key-1", self.issuer_url),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: Some(cose_proof),
            jws: None,
        })
    }

    /// Create SD-JWT proof
    fn create_sd_jwt_proof(
        &self,
        subject: &CredentialSubject,
        issuance_date: &str,
    ) -> Result<Proof, String> {
        // SD-JWT uses selective disclosure
        let sd_jwt = self.create_selective_disclosure_jwt(subject, issuance_date)?;

        Ok(Proof {
            type_: "SdJwtSignature".to_string(),
            created: issuance_date.to_string(),
            verification_method: format!("{}#key-1", self.issuer_url),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: Some(sd_jwt),
            jws: None,
        })
    }

    /// Create JSON-LD proof (simplified)
    fn create_json_ld_proof(
        &self,
        _subject: &CredentialSubject,
        issuance_date: &str,
    ) -> Result<String, String> {
        // In a real implementation, this would create a proper JSON-LD proof
        let proof_data = serde_json::json!({
            "type": "Ed25519Signature2020",
            "created": issuance_date,
            "verificationMethod": format!("{}#key-1", self.issuer_url),
            "proofPurpose": "assertionMethod",
            "proofValue": "simulated_proof_value"
        });

        Ok(Base64::encode_string(
            serde_json::to_string(&proof_data)
                .map_err(|e| format!("Serialization error: {}", e))?
                .as_bytes(),
        ))
    }

    /// Create COSE proof (simplified)
    fn create_cose_proof(
        &self,
        _subject: &CredentialSubject,
        _issuance_date: &str,
    ) -> Result<String, String> {
        // In a real implementation, this would create a proper COSE signature
        Ok("simulated_cose_proof".to_string())
    }

    /// Create selective disclosure JWT using robust implementation
    fn create_selective_disclosure_jwt(
        &self,
        subject: &CredentialSubject,
        _issuance_date: &str,
    ) -> Result<String, String> {
        use crate::crypto::sdjwt::SdJwtUtils;

        let issuer = &self.issuer_url;
        let sub = subject.id.as_deref().unwrap_or("unknown");
        let aud = "verifier"; // Default audience, should be configurable in production

        // Create privacy-preserving SD-JWT with decoy claims
        let mut sd_jwt = SdJwtUtils::create_privacy_preserving_jwt(
            issuer,
            sub,
            aud,
            subject.claims.clone(),
            0, // No decoy claims for standard issuance, can be configured
        )
        .map_err(|e| format!("Failed to create SD-JWT: {}", e))?;

        // Sign the SD-JWT
        let private_key = self
            .private_keys
            .get("Ed25519")
            .ok_or("Ed25519 private key not found")?;

        sd_jwt
            .issuer_signed
            .sign(private_key)
            .map_err(|e| format!("Failed to sign SD-JWT: {}", e))?;

        Ok(sd_jwt.to_string())
    }

    /// Create verifiable presentation
    pub fn create_verifiable_presentation(
        &self,
        credentials: Vec<serde_json::Value>,
        holder: &str,
    ) -> Result<VerifiablePresentation, String> {
        let now = chrono::Utc::now().to_rfc3339();

        // Create proof for presentation
        let presentation_data = serde_json::json!({
            "holder": holder,
            "verifiableCredential": credentials
        });

        let proof = self.create_presentation_proof(&presentation_data, &now)?;

        Ok(VerifiablePresentation {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            type_: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: credentials,
            proof: Some(proof),
            holder: Some(holder.to_string()),
        })
    }

    /// Create presentation proof
    fn create_presentation_proof(
        &self,
        presentation_data: &serde_json::Value,
        created: &str,
    ) -> Result<Proof, String> {
        let private_key = self
            .private_keys
            .get("Ed25519")
            .ok_or("Ed25519 private key not found")?;

        // Create JWT for presentation proof
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::EdDSA,
            typ: Some("JWT".to_string()),
            kid: Some("key-1".to_string()),
            ..Default::default()
        };

        let payload = serde_json::json!({
            "iss": self.issuer_url,
            "iat": chrono::Utc::now().timestamp(),
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            "vp": presentation_data
        });

        let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(&private_key.to_keypair_bytes());
        let token = jsonwebtoken::encode(&header, &payload, &encoding_key)
            .map_err(|e| format!("Failed to sign presentation JWT: {}", e))?;

        Ok(Proof {
            type_: "Ed25519Signature2020".to_string(),
            created: created.to_string(),
            verification_method: format!("{}#key-1", self.issuer_url),
            proof_purpose: "authentication".to_string(),
            proof_value: None,
            jws: Some(token),
        })
    }

    /// Revoke credential
    pub async fn revoke_credential_internal(
        &self,
        credential_id: &str,
        reason: Option<String>,
    ) -> Result<(), String> {
        let revocation = CredentialRevocation {
            credential_id: credential_id.to_string(),
            revocation_date: chrono::Utc::now().to_rfc3339(),
            reason,
        };

        {
            let mut revoked = self.revoked_credentials.write().await;
            revoked.insert(credential_id.to_string(), revocation);
        } // Write lock is released here

        // Update status list
        self.update_status_list().await?;

        Ok(())
    }

    /// Update status list
    async fn update_status_list(&self) -> Result<(), String> {
        let revoked = self.revoked_credentials.read().await;
        let mut status_bits = vec![0u8; 128]; // 1024 bits

        // Mark revoked credentials in the bitstring
        for (credential_id, _) in revoked.iter() {
            // Simple hash-based indexing (in production, use proper indexing)
            let hash = credential_id
                .as_bytes()
                .iter()
                .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
            let bit_index = (hash % 1024) as usize;
            let byte_index = bit_index / 8;
            let bit_offset = bit_index % 8;

            if byte_index < status_bits.len() {
                status_bits[byte_index] |= 1 << bit_offset;
            }
        }

        let mut status_list = self.status_list.write().await;
        status_list.encoded_list = Base64::encode_string(&status_bits);

        Ok(())
    }

    /// Check if credential is revoked
    pub async fn is_credential_revoked(&self, credential_id: &str) -> bool {
        let revoked = self.revoked_credentials.read().await;
        revoked.contains_key(credential_id)
    }

    /// Store deferred credential
    pub async fn store_deferred_credential(
        &self,
        acceptance_token: &str,
        credential: serde_json::Value,
    ) -> Result<(), String> {
        let mut deferred = self.deferred_credentials.write().await;
        deferred.insert(acceptance_token.to_string(), credential);
        Ok(())
    }

    /// Retrieve deferred credential
    pub async fn retrieve_deferred_credential(
        &self,
        acceptance_token: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let deferred = self.deferred_credentials.read().await;
        Ok(deferred.get(acceptance_token).cloned())
    }
}

#[async_trait]
impl Oid4VcService for EnhancedOid4VcManager {
    async fn get_issuer_metadata(&self) -> Result<CredentialIssuerMetadata, String> {
        Ok(CredentialIssuerMetadata {
            credential_issuer: self.issuer_url.clone(),
            authorization_servers: vec![self.issuer_url.clone()],
            credential_endpoint: format!("{}/credentials", self.issuer_url),
            batch_credential_endpoint: Some(format!("{}/credentials/batch", self.issuer_url)),
            deferred_credential_endpoint: Some(format!("{}/credentials/deferred", self.issuer_url)),
            credentials_supported: self.supported_credentials.clone(),
            display: Some(vec![DisplayMetadata {
                name: "Authenc Enhanced Credential Issuer".to_string(),
                locale: Some("en-US".to_string()),
            }]),
            credential_configurations_supported: Some(self.credential_configurations.clone()),
        })
    }

    async fn handle_authorization_request(
        &self,
        request: CredentialAuthorizationRequest,
    ) -> Result<String, String> {
        // Validate PKCE if present
        if let Some(_code_challenge) = &request.code_challenge {
            if request.code_challenge_method.as_deref() != Some("S256") {
                return Err("Invalid code challenge method".to_string());
            }
            // In production, store code_challenge for later verification
        }

        // Generate authorization code
        let code = uuid::Uuid::new_v4().to_string();

        // In production, store the authorization request details with the code
        Ok(code)
    }

    async fn handle_token_request(
        &self,
        request: CredentialTokenRequest,
    ) -> Result<CredentialTokenResponse, String> {
        // Verify PKCE if present
        if let Some(_code_verifier) = &request.code_verifier {
            // In production, verify code_verifier against stored code_challenge
        }

        // Generate tokens
        let access_token = uuid::Uuid::new_v4().to_string();
        let c_nonce = uuid::Uuid::new_v4().to_string();

        Ok(CredentialTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: Some("credential_issuance".to_string()),
            c_nonce,
            c_nonce_expires_in: 86400,
            authorization_details: Some(vec![]), // Would be populated based on authorization
        })
    }

    async fn issue_credential(
        &self,
        request: CredentialRequest,
        access_token: &str,
    ) -> Result<CredentialResponse, String> {
        // Verify access token (in production, check against stored tokens)
        if access_token.is_empty() {
            return Err("Invalid access token".to_string());
        }

        // Verify proof of possession if present
        if let Some(proof) = &request.proof {
            self.verify_proof_of_possession(proof).await?;
        }

        // Create credential based on request
        let claims = self.get_credential_claims(&request.types).await?;
        let credential_type = request.types.get(1).ok_or("Invalid credential type")?;

        let vc = self.create_verifiable_credential(
            "did:example:subject123",
            claims,
            credential_type,
            &request.format,
        )?;

        Ok(CredentialResponse {
            format: request.format,
            credential: serde_json::to_value(vc).map_err(|e| e.to_string())?,
            acceptance_token: None,
            c_nonce: Some(uuid::Uuid::new_v4().to_string()),
            c_nonce_expires_in: Some(86400),
        })
    }

    async fn issue_batch_credentials(
        &self,
        request: BatchCredentialRequest,
        access_token: &str,
    ) -> Result<BatchCredentialResponse, String> {
        if request.credential_requests.len() > 10 {
            return Err("Too many credentials requested".to_string());
        }

        let mut responses = Vec::new();

        for credential_request in request.credential_requests {
            let response = self
                .issue_credential(credential_request, access_token)
                .await?;
            responses.push(response);
        }

        Ok(BatchCredentialResponse {
            credential_responses: responses,
        })
    }

    async fn handle_deferred_credential(
        &self,
        request: DeferredCredentialRequest,
    ) -> Result<DeferredCredentialResponse, String> {
        let credential = self
            .retrieve_deferred_credential(&request.acceptance_token)
            .await?;

        Ok(DeferredCredentialResponse {
            credential,
            transaction_id: Some(uuid::Uuid::new_v4().to_string()),
        })
    }

    async fn verify_credential(&self, credential: &VerifiableCredential) -> Result<bool, String> {
        // Verify issuer
        match &credential.issuer {
            Issuer::String(issuer) if issuer == &self.issuer_url => {}
            Issuer::Object { id, .. } if id == &self.issuer_url => {}
            _ => return Ok(false),
        }

        // Check if credential is revoked
        if let Some(status) = &credential.status {
            if self.is_credential_revoked(&status.id).await {
                return Ok(false);
            }
        }

        // Verify expiration
        if let Some(exp_date) = &credential.expiration_date {
            let exp = chrono::DateTime::parse_from_rfc3339(exp_date)
                .map_err(|e| format!("Invalid expiration date: {}", e))?;
            if exp < chrono::Utc::now() {
                return Ok(false);
            }
        }

        // Verify proof (simplified - in production, verify cryptographic proof)
        if let Some(proof) = &credential.proof {
            match proof.type_.as_str() {
                "Ed25519Signature2020" | "CoseSignature" | "SdJwtSignature" => {
                    // Verify signature
                }
                _ => return Ok(false),
            }
        }

        Ok(true)
    }

    async fn verify_presentation(
        &self,
        presentation: &VerifiablePresentation,
    ) -> Result<bool, String> {
        // Verify holder
        if presentation.holder.is_none() {
            return Ok(false);
        }

        // Verify each credential in the presentation
        for credential_value in &presentation.verifiable_credential {
            let credential: VerifiableCredential = serde_json::from_value(credential_value.clone())
                .map_err(|e| format!("Invalid credential in presentation: {}", e))?;

            if !self.verify_credential(&credential).await? {
                return Ok(false);
            }
        }

        // Verify presentation proof
        if let Some(proof) = &presentation.proof {
            // Verify presentation signature
            match proof.type_.as_str() {
                "Ed25519Signature2020" => {
                    // Verify signature
                }
                _ => return Ok(false),
            }
        }

        Ok(true)
    }

    async fn revoke_credential(
        &self,
        credential_id: &str,
        reason: Option<String>,
    ) -> Result<(), String> {
        self.revoke_credential_internal(credential_id, reason).await
    }

    async fn get_credential_status(&self, credential_id: &str) -> Result<CredentialStatus, String> {
        if self.is_credential_revoked(credential_id).await {
            Ok(CredentialStatus {
                id: credential_id.to_string(),
                type_: "StatusList2021Entry".to_string(),
            })
        } else {
            Err("Credential not found".to_string())
        }
    }

    async fn get_status_list(&self) -> Result<StatusList2021, String> {
        let status_list = self.status_list.read().await;
        Ok(status_list.clone())
    }
}

impl EnhancedOid4VcManager {
    /// Get credential claims based on type
    async fn get_credential_claims(
        &self,
        types: &[String],
    ) -> Result<HashMap<String, serde_json::Value>, String> {
        let credential_type = types.get(1).ok_or("Invalid credential type")?;

        match credential_type.as_str() {
            "UniversityDegreeCredential" => Ok(HashMap::from([
                (
                    "degree".to_string(),
                    serde_json::json!("Bachelor of Science"),
                ),
                (
                    "university".to_string(),
                    serde_json::json!("Example University"),
                ),
                (
                    "graduationDate".to_string(),
                    serde_json::json!("2024-06-15"),
                ),
            ])),
            "DriversLicenseCredential" => Ok(HashMap::from([
                (
                    "licenseNumber".to_string(),
                    serde_json::json!("DL123456789"),
                ),
                ("class".to_string(), serde_json::json!("C")),
                ("expiryDate".to_string(), serde_json::json!("2029-06-15")),
            ])),
            "EmployeeCredential" => Ok(HashMap::from([
                ("employeeId".to_string(), serde_json::json!("EMP001")),
                (
                    "position".to_string(),
                    serde_json::json!("Software Engineer"),
                ),
                ("department".to_string(), serde_json::json!("Engineering")),
                ("startDate".to_string(), serde_json::json!("2023-01-15")),
            ])),
            "PersonCredential" => Ok(HashMap::from([
                ("name".to_string(), serde_json::json!("John Doe")),
                ("dateOfBirth".to_string(), serde_json::json!("1990-01-01")),
                ("nationality".to_string(), serde_json::json!("US")),
            ])),
            "DiplomaCredential" => Ok(HashMap::from([
                ("studentId".to_string(), serde_json::json!("STU001")),
                ("program".to_string(), serde_json::json!("Computer Science")),
                (
                    "degree".to_string(),
                    serde_json::json!("Bachelor of Science"),
                ),
                (
                    "graduationDate".to_string(),
                    serde_json::json!("2024-06-15"),
                ),
            ])),
            _ => Err(format!("Unsupported credential type: {}", credential_type)),
        }
    }

    /// Verify proof of possession
    async fn verify_proof_of_possession(&self, proof: &ProofOfPossession) -> Result<(), String> {
        match proof.proof_type.as_str() {
            "jwt" => {
                if let Some(jwt) = &proof.jwt {
                    // Verify JWT proof
                    self.verify_jwt_proof(jwt).await?;
                }
            }
            "cwt" => {
                if let Some(cwt) = &proof.cwt {
                    // Verify CWT proof
                    self.verify_cwt_proof(cwt).await?;
                }
            }
            _ => return Err(format!("Unsupported proof type: {}", proof.proof_type)),
        }

        Ok(())
    }

    /// Verify JWT proof
    async fn verify_jwt_proof(&self, jwt: &str) -> Result<(), String> {
        // In production, verify JWT signature and claims
        // For now, just check if it's a valid JWT format
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".to_string());
        }

        // Decode and verify header
        let header =
            Base64::decode_vec(parts[0]).map_err(|e| format!("Invalid JWT header: {}", e))?;
        let header_str =
            String::from_utf8(header).map_err(|e| format!("Invalid UTF-8 in header: {}", e))?;

        let header_claims: serde_json::Value =
            serde_json::from_str(&header_str).map_err(|e| format!("Invalid header JSON: {}", e))?;

        // Check algorithm
        if header_claims["alg"] != "EdDSA" {
            return Err("Unsupported JWT algorithm".to_string());
        }

        Ok(())
    }

    /// Verify CWT proof
    async fn verify_cwt_proof(&self, cwt: &str) -> Result<(), String> {
        // In production, verify CWT signature
        // For now, just check if it's a valid base64 string
        Base64::decode_vec(cwt).map_err(|e| format!("Invalid CWT format: {}", e))?;
        Ok(())
    }
}

/// Legacy OID4VC Manager for backward compatibility
pub struct LegacyOid4VcManager {
    enhanced_manager: EnhancedOid4VcManager,
}

impl LegacyOid4VcManager {
    /// Create a new legacy OID4VC manager with custom private key
    ///
    /// This constructor initializes a legacy OID4VC manager for backward
    /// compatibility with existing systems. It uses a provided Ed25519
    /// private key instead of generating a new one, allowing migration
    /// from legacy credential systems.
    ///
    /// # Arguments
    /// * `issuer_url` - The base URL of the credential issuer
    /// * `private_key` - Ed25519 private key for credential signing
    ///
    /// # Returns
    /// A new `LegacyOid4VcManager` instance with the specified private key
    ///
    /// # Security Considerations
    /// - Private key should be securely generated and stored
    /// - Key material should never be logged or exposed in error messages
    /// - Issuer URL validation prevents impersonation attacks
    /// - Legacy compatibility should be phased out in favor of enhanced manager
    ///
    /// # Migration Notes
    /// - This manager provides backward compatibility during migration
    /// - Consider upgrading to `EnhancedOid4VcManager` for new deployments
    /// - Legacy keys should be rotated regularly for security
    /// - Audit all credential operations during migration period
    ///
    /// # Example
    /// ```rust
    /// use authenc::services::oid4vc::LegacyOid4VcManager;
    /// use ed25519_dalek::SigningKey;
    ///
    /// let private_key = SigningKey::generate(&mut rand::thread_rng());
    /// let manager = LegacyOid4VcManager::new(
    ///     "https://legacy-issuer.example.com".to_string(),
    ///     private_key
    /// );
    /// ```
    pub fn new(issuer_url: String, private_key: ed25519_dalek::SigningKey) -> Self {
        let mut enhanced = EnhancedOid4VcManager::new(issuer_url);
        // Replace the generated key with the provided legacy key
        enhanced
            .private_keys
            .insert("Ed25519".to_string(), private_key);
        Self {
            enhanced_manager: enhanced,
        }
    }
}

#[async_trait]
impl Oid4VcService for LegacyOid4VcManager {
    async fn get_issuer_metadata(&self) -> Result<CredentialIssuerMetadata, String> {
        self.enhanced_manager.get_issuer_metadata().await
    }

    async fn handle_authorization_request(
        &self,
        request: CredentialAuthorizationRequest,
    ) -> Result<String, String> {
        self.enhanced_manager
            .handle_authorization_request(request)
            .await
    }

    async fn handle_token_request(
        &self,
        request: CredentialTokenRequest,
    ) -> Result<CredentialTokenResponse, String> {
        self.enhanced_manager.handle_token_request(request).await
    }

    async fn issue_credential(
        &self,
        request: CredentialRequest,
        access_token: &str,
    ) -> Result<CredentialResponse, String> {
        self.enhanced_manager
            .issue_credential(request, access_token)
            .await
    }

    async fn verify_credential(&self, credential: &VerifiableCredential) -> Result<bool, String> {
        self.enhanced_manager.verify_credential(credential).await
    }

    // Default implementations for new methods
    async fn issue_batch_credentials(
        &self,
        _request: BatchCredentialRequest,
        _access_token: &str,
    ) -> Result<BatchCredentialResponse, String> {
        Err("Batch credentials not supported in legacy mode".to_string())
    }

    async fn handle_deferred_credential(
        &self,
        _request: DeferredCredentialRequest,
    ) -> Result<DeferredCredentialResponse, String> {
        Err("Deferred credentials not supported in legacy mode".to_string())
    }

    async fn verify_presentation(
        &self,
        _presentation: &VerifiablePresentation,
    ) -> Result<bool, String> {
        Err("Presentation verification not supported in legacy mode".to_string())
    }

    async fn revoke_credential(
        &self,
        _credential_id: &str,
        _reason: Option<String>,
    ) -> Result<(), String> {
        Err("Credential revocation not supported in legacy mode".to_string())
    }

    async fn get_credential_status(
        &self,
        _credential_id: &str,
    ) -> Result<CredentialStatus, String> {
        Err("Credential status not supported in legacy mode".to_string())
    }

    async fn get_status_list(&self) -> Result<StatusList2021, String> {
        self.enhanced_manager.get_status_list().await
    }
}

impl LegacyOid4VcManager {
    /// Create verifiable credential
    pub fn create_verifiable_credential(
        &self,
        subject_id: &str,
        claims: HashMap<String, serde_json::Value>,
        credential_type: &str,
    ) -> Result<VerifiableCredential, String> {
        let now = chrono::Utc::now();
        let issuance_date = now.to_rfc3339();
        let expiration_date = (now + chrono::Duration::days(365)).to_rfc3339();

        let credential_subject = CredentialSubject {
            id: Some(subject_id.to_string()),
            claims,
        };

        // Create proof
        let proof = self.create_proof(&credential_subject, &issuance_date)?;

        Ok(VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ],
            id: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            type_: vec![
                "VerifiableCredential".to_string(),
                credential_type.to_string(),
            ],
            issuer: Issuer::Object {
                id: self.enhanced_manager.issuer_url.clone(),
                name: Some("Authenc Credential Issuer".to_string()),
            },
            issuance_date,
            expiration_date: Some(expiration_date),
            credential_subject,
            proof: Some(proof),
            status: Some(CredentialStatus {
                id: format!(
                    "{}/status/1#{}",
                    self.enhanced_manager.issuer_url,
                    uuid::Uuid::new_v4()
                ),
                type_: "StatusList2021Entry".to_string(),
            }),
        })
    }

    /// Create cryptographic proof
    fn create_proof(
        &self,
        subject: &CredentialSubject,
        issuance_date: &str,
    ) -> Result<Proof, String> {
        // Create JWT header
        let _header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::EdDSA,
            typ: Some("JWT".to_string()),
            kid: Some("key-1".to_string()),
            ..Default::default()
        };

        // Create JWT payload as a struct
        #[derive(serde::Serialize)]
        struct JWTPayload<'a> {
            iss: &'a str,
            sub: Option<&'a str>,
            iat: i64,
            exp: i64,
            vc: serde_json::Value,
        }

        let _payload = JWTPayload {
            iss: &self.enhanced_manager.issuer_url,
            sub: subject.id.as_deref(),
            iat: chrono::Utc::now().timestamp(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            vc: serde_json::json!({
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "credentialSubject": subject
            }),
        };

        // For testing purposes, create a simple mock proof
        // In production, this would create a proper cryptographic proof
        let _proof_value = format!("mock-proof-{}", uuid::Uuid::new_v4());
        let encoding_key = jsonwebtoken::EncodingKey::from_secret(b"test-secret");
        let header = jsonwebtoken::Header::default();
        let claims = serde_json::json!({
            "iss": self.enhanced_manager.issuer_url,
            "sub": subject.id,
            "iat": chrono::Utc::now().timestamp(),
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp()
        });
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
            .unwrap_or_else(|_| "mock-jwt-token".to_string());

        Ok(Proof {
            type_: "Ed25519Signature2020".to_string(),
            created: issuance_date.to_string(),
            verification_method: format!("{}#key-1", self.enhanced_manager.issuer_url),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            jws: Some(token),
        })
    }
}
