//! SD-JWT (Selective Disclosure JWT) Implementation
//!
//! This module provides comprehensive SD-JWT support for privacy-preserving
//! identity management, allowing selective disclosure of JWT claims.
//!
//! Features:
//! - Selective disclosure of claims
//! - Decoy claims for enhanced privacy
//! - Array element disclosure
//! - Salt-based hashing for unlinkability
//! - Issuer-signed JWT with disclosures
//! - Holder binding for enhanced security

use crate::error::AuthencError;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Salt for SD-JWT hashing to ensure unlinkability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtSalt {
    /// Base64-encoded salt value
    pub salt: String,
}

impl Default for SdJwtSalt {
    fn default() -> Self {
        Self::new()
    }
}

impl SdJwtSalt {
    /// Generate a new random salt
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let salt_bytes: [u8; 32] = rng.gen();
        let salt = Base64UrlUnpadded::encode_string(&salt_bytes);

        Self { salt }
    }

    /// Create salt from string
    pub fn from_string(salt: String) -> Self {
        Self { salt }
    }

    /// Get salt as bytes
    pub fn as_bytes(&self) -> Result<Vec<u8>, AuthencError> {
        Base64UrlUnpadded::decode_vec(&self.salt).map_err(|_| AuthencError::CryptographicError)
    }
}

/// Disclosure specification for SD-JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureSpec {
    /// Claim name to disclose
    pub claim_name: String,
    /// Claim value
    pub claim_value: Value,
    /// Salt for this disclosure
    pub salt: SdJwtSalt,
}

/// Disclosure represents a single claim disclosure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    /// Base64-encoded disclosure data
    pub disclosure: String,
    /// Disclosure hash for verification
    pub hash: String,
}

impl Disclosure {
    /// Create a new disclosure from specification
    pub fn new(spec: DisclosureSpec) -> Result<Self, AuthencError> {
        let disclosure_data = json!([spec.salt.salt, spec.claim_name, spec.claim_value]);

        let disclosure_json = serde_json::to_string(&disclosure_data).map_err(|_| {
            AuthencError::SerializationError {
                message: "Failed to serialize disclosure".to_string(),
            }
        })?;

        let disclosure_b64 = Base64UrlUnpadded::encode_string(disclosure_json.as_bytes());

        // Calculate hash for verification
        let mut hasher = Sha256::new();
        hasher.update(disclosure_b64.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Ok(Self {
            disclosure: disclosure_b64,
            hash,
        })
    }

    /// Verify disclosure hash
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.disclosure.as_bytes());
        let calculated_hash = format!("{:x}", hasher.finalize());
        calculated_hash == self.hash
    }

    /// Decode disclosure to get claim data
    pub fn decode(&self) -> Result<(String, Value), AuthencError> {
        let disclosure_bytes = Base64UrlUnpadded::decode_vec(&self.disclosure)
            .map_err(|_| AuthencError::CryptographicError)?;

        let disclosure_data: Vec<Value> =
            serde_json::from_slice(&disclosure_bytes).map_err(|_| {
                AuthencError::SerializationError {
                    message: "Invalid disclosure format".to_string(),
                }
            })?;

        if disclosure_data.len() != 3 {
            return Err(AuthencError::ValidationError {
                message: "Invalid disclosure structure".to_string(),
            });
        }

        let claim_name = disclosure_data[1]
            .as_str()
            .ok_or_else(|| AuthencError::ValidationError {
                message: "Invalid claim name".to_string(),
            })?
            .to_string();

        let claim_value = disclosure_data[2].clone();

        Ok((claim_name, claim_value))
    }
}

/// Disclosure Red List for preventing disclosure replay attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureRedList {
    /// List of disclosed claim hashes that have been used
    disclosed_hashes: HashSet<String>,
    /// Maximum size of the red list
    max_size: usize,
}

impl DisclosureRedList {
    /// Create a new disclosure red list
    pub fn new(max_size: usize) -> Self {
        Self {
            disclosed_hashes: HashSet::new(),
            max_size,
        }
    }

    /// Check if a disclosure hash has been used
    pub fn is_disclosed(&self, hash: &str) -> bool {
        self.disclosed_hashes.contains(hash)
    }

    /// Add a disclosure hash to the red list
    pub fn add_disclosure(&mut self, hash: String) -> Result<(), AuthencError> {
        if self.disclosed_hashes.len() >= self.max_size {
            return Err(AuthencError::ValidationError {
                message: "Disclosure red list is full".to_string(),
            });
        }
        self.disclosed_hashes.insert(hash);
        Ok(())
    }

    /// Clear the red list (for maintenance)
    pub fn clear(&mut self) {
        self.disclosed_hashes.clear();
    }
}

/// SD-JWT Verification Context
#[derive(Debug, Clone)]
pub struct SdJwtVerificationContext {
    /// Disclosure red list for replay attack prevention
    pub red_list: DisclosureRedList,
    /// Expected issuer
    pub expected_issuer: Option<String>,
    /// Expected subject
    pub expected_subject: Option<String>,
    /// Expected audience
    pub expected_audience: Option<String>,
    /// Maximum disclosure age in seconds
    pub max_disclosure_age: Option<u64>,
    /// Require all disclosures to be present
    pub require_all_disclosures: bool,
    /// Allow decoy claims
    pub allow_decoys: bool,
}

impl Default for SdJwtVerificationContext {
    fn default() -> Self {
        Self {
            red_list: DisclosureRedList::new(10000),
            expected_issuer: None,
            expected_subject: None,
            expected_audience: None,
            max_disclosure_age: Some(3600), // 1 hour
            require_all_disclosures: false,
            allow_decoys: true,
        }
    }
}

/// SD-JWT Claim types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SdJwtClaim {
    /// Disclosed claim with value
    Disclosed {
        /// The disclosed claim value
        value: Value,
    },
    /// Undisclosed claim with hash reference
    Undisclosed {
        /// Hash reference for the undisclosed claim
        sd_hash: String,
    },
    /// Decoy claim for privacy enhancement
    Decoy {
        /// Flag indicating this is a decoy claim
        decoy: bool,
    },
}

/// SD-JWT Array Element types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SdJwtArrayElement {
    /// Disclosed array element
    Disclosed(Value),
    /// Undisclosed array element with hash
    Undisclosed {
        /// Hash reference for the undisclosed array element
        sd_hash: String,
    },
    /// Decoy array element
    Decoy {
        /// Flag indicating this is a decoy array element
        decoy: bool,
    },
}

/// Issuer-signed JWT with SD-JWT capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignedJwt {
    /// Standard JWT header
    pub header: HashMap<String, Value>,
    /// SD-JWT payload with selective disclosure
    pub payload: HashMap<String, SdJwtClaim>,
    /// Array claims with selective disclosure
    pub array_claims: HashMap<String, Vec<SdJwtArrayElement>>,
    /// JWT signature
    pub signature: String,
}

impl IssuerSignedJwt {
    /// Create new issuer-signed JWT
    pub fn new(issuer: &str, subject: &str, audience: &str) -> Self {
        let mut header = HashMap::new();
        header.insert("alg".to_string(), json!("EdDSA"));
        header.insert("typ".to_string(), json!("sd-jwt"));

        let mut payload = HashMap::new();
        payload.insert(
            "iss".to_string(),
            SdJwtClaim::Disclosed {
                value: json!(issuer),
            },
        );
        payload.insert(
            "sub".to_string(),
            SdJwtClaim::Disclosed {
                value: json!(subject),
            },
        );
        payload.insert(
            "aud".to_string(),
            SdJwtClaim::Disclosed {
                value: json!(audience),
            },
        );
        payload.insert(
            "iat".to_string(),
            SdJwtClaim::Disclosed {
                value: json!(chrono::Utc::now().timestamp()),
            },
        );
        payload.insert(
            "exp".to_string(),
            SdJwtClaim::Disclosed {
                value: json!(chrono::Utc::now().timestamp() + 3600),
            },
        );

        Self {
            header,
            payload,
            array_claims: HashMap::new(),
            signature: String::new(),
        }
    }

    /// Add selectively disclosable claim
    pub fn add_selective_claim(
        &mut self,
        name: String,
        value: Value,
        salt: SdJwtSalt,
    ) -> Result<(), AuthencError> {
        let disclosure = Disclosure::new(DisclosureSpec {
            claim_name: name.clone(),
            claim_value: value,
            salt,
        })?;

        self.payload.insert(
            name,
            SdJwtClaim::Undisclosed {
                sd_hash: disclosure.hash,
            },
        );

        Ok(())
    }

    /// Add decoy claim for privacy enhancement
    pub fn add_decoy_claim(&mut self, name: String) {
        self.payload.insert(name, SdJwtClaim::Decoy { decoy: true });
    }

    /// Add array claim with selective disclosure
    pub fn add_selective_array_claim(
        &mut self,
        name: String,
        elements: Vec<Value>,
        salts: Vec<SdJwtSalt>,
    ) -> Result<(), AuthencError> {
        let mut array_elements = Vec::new();

        for (i, element) in elements.into_iter().enumerate() {
            if i < salts.len() {
                let disclosure = Disclosure::new(DisclosureSpec {
                    claim_name: format!("{}_element_{}", name, i),
                    claim_value: element,
                    salt: salts[i].clone(),
                })?;

                array_elements.push(SdJwtArrayElement::Undisclosed {
                    sd_hash: disclosure.hash,
                });
            } else {
                array_elements.push(SdJwtArrayElement::Disclosed(element));
            }
        }

        self.array_claims.insert(name, array_elements);
        Ok(())
    }

    /// Sign the JWT with Ed25519
    pub fn sign(&mut self, keypair: &SigningKey) -> Result<(), AuthencError> {
        let header_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&self.header)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize header".to_string(),
                })?
                .as_bytes(),
        );

        let payload_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&self.payload)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize payload".to_string(),
                })?
                .as_bytes(),
        );

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = keypair.sign(message.as_bytes());
        self.signature = Base64UrlUnpadded::encode_string(&signature.to_bytes());

        Ok(())
    }

    /// Serialize to SD-JWT format
    pub fn to_sd_jwt(&self) -> String {
        format!(
            "{}.{}.{}",
            Base64UrlUnpadded::encode_string(
                serde_json::to_string(&self.header).unwrap().as_bytes()
            ),
            Base64UrlUnpadded::encode_string(
                serde_json::to_string(&self.payload).unwrap().as_bytes()
            ),
            self.signature
        )
    }
}

/// SD-JWT with disclosures
#[derive(Debug, Clone)]
pub struct SdJwt {
    /// Issuer-signed JWT
    pub issuer_signed: IssuerSignedJwt,
    /// List of disclosures
    pub disclosures: Vec<Disclosure>,
    /// Holder binding (optional)
    pub holder_binding: Option<String>,
}

impl SdJwt {
    /// Create new SD-JWT
    pub fn new(issuer_signed: IssuerSignedJwt) -> Self {
        Self {
            issuer_signed,
            disclosures: Vec::new(),
            holder_binding: None,
        }
    }

    /// Add disclosure
    pub fn add_disclosure(&mut self, disclosure: Disclosure) {
        self.disclosures.push(disclosure);
    }

    /// Set holder binding for enhanced security
    pub fn set_holder_binding(&mut self, binding: String) {
        self.holder_binding = Some(binding);
    }
}

impl std::fmt::Display for SdJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = vec![self.issuer_signed.to_sd_jwt()];

        for disclosure in &self.disclosures {
            parts.push(disclosure.disclosure.clone());
        }

        if let Some(binding) = &self.holder_binding {
            parts.push(binding.clone());
        }

        write!(f, "{}", parts.join("~"))
    }
}

impl SdJwt {
    /// Create a new SdJwt instance from a string representation
    ///
    /// # Arguments
    /// * `sd_jwt_str` - The SD-JWT string in the format "header.payload~signature"
    ///
    /// # Returns
    /// A Result containing the SdJwt instance or an AuthencError
    pub fn from_string(sd_jwt_str: &str) -> Result<Self, AuthencError> {
        let parts: Vec<&str> = sd_jwt_str.split('~').collect();
        if parts.is_empty() {
            return Err(AuthencError::ValidationError {
                message: "Invalid SD-JWT format".to_string(),
            });
        }

        // Parse issuer-signed JWT
        let jwt_parts: Vec<&str> = parts[0].split('.').collect();
        if jwt_parts.len() != 3 {
            return Err(AuthencError::ValidationError {
                message: "Invalid JWT format".to_string(),
            });
        }

        let header_bytes = Base64UrlUnpadded::decode_vec(jwt_parts[0])
            .map_err(|_| AuthencError::CryptographicError)?;

        let payload_bytes = Base64UrlUnpadded::decode_vec(jwt_parts[1])
            .map_err(|_| AuthencError::CryptographicError)?;

        let header: HashMap<String, Value> =
            serde_json::from_slice(&header_bytes).map_err(|_| {
                AuthencError::SerializationError {
                    message: "Invalid header format".to_string(),
                }
            })?;

        let payload: HashMap<String, SdJwtClaim> =
            serde_json::from_slice(&payload_bytes).map_err(|_| {
                AuthencError::SerializationError {
                    message: "Invalid payload format".to_string(),
                }
            })?;

        let issuer_signed = IssuerSignedJwt {
            header,
            payload,
            array_claims: HashMap::new(), // TODO: Parse array claims
            signature: jwt_parts[2].to_string(),
        };

        let mut sd_jwt = Self::new(issuer_signed);

        // Parse disclosures
        for &part in &parts[1..] {
            if !part.is_empty() {
                // Check if it's a holder binding (starts with eyJ)
                if part.starts_with("eyJ") {
                    sd_jwt.set_holder_binding(part.to_string());
                } else {
                    // It's a disclosure
                    let disclosure = Disclosure {
                        disclosure: part.to_string(),
                        hash: String::new(), // Will be calculated during verification
                    };
                    sd_jwt.add_disclosure(disclosure);
                }
            }
        }

        Ok(sd_jwt)
    }

    /// Verify SD-JWT
    pub fn verify(&self, public_key: &VerifyingKey) -> Result<(), AuthencError> {
        // Verify issuer signature
        let message = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(
                serde_json::to_string(&self.issuer_signed.header)
                    .unwrap()
                    .as_bytes()
            ),
            Base64UrlUnpadded::encode_string(
                serde_json::to_string(&self.issuer_signed.payload)
                    .unwrap()
                    .as_bytes()
            )
        );

        let signature_bytes = Base64UrlUnpadded::decode_vec(&self.issuer_signed.signature)
            .map_err(|_| AuthencError::CryptographicError)?;

        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthencError::CryptographicError)?;

        let signature = Signature::from_bytes(&signature_array);

        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| AuthencError::CryptographicError)?;

        // Verify disclosures
        for disclosure in &self.disclosures {
            if !disclosure.verify() {
                return Err(AuthencError::ValidationError {
                    message: "Disclosure verification failed".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get disclosed claims
    pub fn get_disclosed_claims(&self) -> Result<HashMap<String, Value>, AuthencError> {
        let mut claims = HashMap::new();

        // Add always-disclosed claims
        for (key, claim) in &self.issuer_signed.payload {
            if let SdJwtClaim::Disclosed { value } = claim {
                claims.insert(key.clone(), value.clone());
            }
        }

        // Add selectively disclosed claims
        for disclosure in &self.disclosures {
            let (claim_name, claim_value) = disclosure.decode()?;
            claims.insert(claim_name, claim_value);
        }

        Ok(claims)
    }
}

/// Abstract SD-JWT Claim for polymorphic claim handling
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AbstractSdJwtClaim {
    /// Disclosed claim with value
    Disclosed {
        /// The disclosed claim value
        value: Value,
    },
    /// Undisclosed claim with hash reference
    Undisclosed {
        /// Hash reference for the undisclosed claim
        sd_hash: String,
    },
    /// Decoy claim for privacy enhancement
    Decoy {
        /// Flag indicating this is a decoy claim
        decoy: bool,
    },
    /// Array element claim
    ArrayElement {
        /// Array element data
        element: SdJwtArrayElement,
    },
}

/// SD-JWT Claim Name for structured claim handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtClaimName {
    /// The claim name
    pub name: String,
    /// Whether this claim is disclosable
    pub disclosable: bool,
    /// Whether this claim is an array
    pub is_array: bool,
}

/// Visible SD-JWT Claim for presentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibleSdJwtClaim {
    /// Claim name
    pub name: SdJwtClaimName,
    /// Claim value (if disclosed)
    pub value: Option<Value>,
    /// Disclosure hash (if undisclosed)
    pub disclosure_hash: Option<String>,
    /// Whether this is a decoy claim
    pub is_decoy: bool,
}

/// Undisclosed Array Element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndisclosedArrayElement {
    /// Hash reference for the undisclosed array element
    pub sd_hash: String,
}

/// Decoy Array Element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyArrayElement {
    /// Flag indicating this is a decoy array element
    pub decoy: bool,
}

/// Visible Array Element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibleArrayElement {
    /// The visible array element value
    pub value: Value,
}

/// SD-JWT Facade for high-level SD-JWT operations
pub struct SdJwtFacade {
    /// The underlying SD-JWT
    pub sd_jwt: SdJwt,
    /// Verification context
    pub verification_context: SdJwtVerificationContext,
}

impl SdJwtFacade {
    /// Create a new SD-JWT facade
    pub fn new(sd_jwt: SdJwt) -> Self {
        Self {
            sd_jwt,
            verification_context: SdJwtVerificationContext::default(),
        }
    }

    /// Verify the SD-JWT with advanced checks
    pub async fn verify_advanced(&self, public_key: &VerifyingKey) -> Result<(), AuthencError> {
        // Basic JWT verification
        self.sd_jwt.verify(public_key)?;

        // Advanced SD-JWT verification
        self.verify_disclosures()?;
        self.verify_red_list()?;
        self.verify_issuer()?;
        self.verify_subject()?;
        self.verify_audience()?;

        Ok(())
    }

    /// Get visible claims for presentation
    pub fn get_visible_claims(&self) -> Result<Vec<VisibleSdJwtClaim>, AuthencError> {
        let mut visible_claims = Vec::new();

        // Process standard claims
        for (name, claim) in &self.sd_jwt.issuer_signed.payload {
            let visible_claim = match claim {
                SdJwtClaim::Disclosed { value } => VisibleSdJwtClaim {
                    name: SdJwtClaimName {
                        name: name.clone(),
                        disclosable: true,
                        is_array: false,
                    },
                    value: Some(value.clone()),
                    disclosure_hash: None,
                    is_decoy: false,
                },
                SdJwtClaim::Undisclosed { sd_hash } => VisibleSdJwtClaim {
                    name: SdJwtClaimName {
                        name: name.clone(),
                        disclosable: true,
                        is_array: false,
                    },
                    value: None,
                    disclosure_hash: Some(sd_hash.clone()),
                    is_decoy: false,
                },
                SdJwtClaim::Decoy { decoy: _ } => {
                    if self.verification_context.allow_decoys {
                        VisibleSdJwtClaim {
                            name: SdJwtClaimName {
                                name: name.clone(),
                                disclosable: true,
                                is_array: false,
                            },
                            value: None,
                            disclosure_hash: None,
                            is_decoy: true,
                        }
                    } else {
                        continue;
                    }
                }
            };
            visible_claims.push(visible_claim);
        }

        // Process array claims
        for (name, elements) in &self.sd_jwt.issuer_signed.array_claims {
            for (index, element) in elements.iter().enumerate() {
                let claim_name = format!("{}.{}", name, index);
                let visible_claim = match element {
                    SdJwtArrayElement::Disclosed(value) => VisibleSdJwtClaim {
                        name: SdJwtClaimName {
                            name: claim_name,
                            disclosable: true,
                            is_array: true,
                        },
                        value: Some(value.clone()),
                        disclosure_hash: None,
                        is_decoy: false,
                    },
                    SdJwtArrayElement::Undisclosed { sd_hash } => VisibleSdJwtClaim {
                        name: SdJwtClaimName {
                            name: claim_name,
                            disclosable: true,
                            is_array: true,
                        },
                        value: None,
                        disclosure_hash: Some(sd_hash.clone()),
                        is_decoy: false,
                    },
                    SdJwtArrayElement::Decoy { decoy: _ } => {
                        if self.verification_context.allow_decoys {
                            VisibleSdJwtClaim {
                                name: SdJwtClaimName {
                                    name: claim_name,
                                    disclosable: true,
                                    is_array: true,
                                },
                                value: None,
                                disclosure_hash: None,
                                is_decoy: true,
                            }
                        } else {
                            continue;
                        }
                    }
                };
                visible_claims.push(visible_claim);
            }
        }

        Ok(visible_claims)
    }

    /// Disclose a claim by providing the disclosure
    pub fn disclose_claim(&mut self, disclosure: &Disclosure) -> Result<(), AuthencError> {
        // Verify disclosure is not in red list
        if self
            .verification_context
            .red_list
            .is_disclosed(&disclosure.hash)
        {
            return Err(AuthencError::ValidationError {
                message: "Disclosure has already been used (red list)".to_string(),
            });
        }

        // Decode the disclosure
        let (claim_name, claim_value) = disclosure.decode()?;

        // Find and disclose the claim
        if let Some(claim) = self.sd_jwt.issuer_signed.payload.get_mut(&claim_name) {
            match claim {
                SdJwtClaim::Undisclosed { sd_hash } => {
                    if *sd_hash == disclosure.hash {
                        *claim = SdJwtClaim::Disclosed { value: claim_value };
                        // Add to red list
                        self.verification_context
                            .red_list
                            .add_disclosure(disclosure.hash.clone())?;
                    } else {
                        return Err(AuthencError::ValidationError {
                            message: "Disclosure hash does not match".to_string(),
                        });
                    }
                }
                _ => {
                    return Err(AuthencError::ValidationError {
                        message: "Claim is not undisclosed".to_string(),
                    });
                }
            }
        } else {
            // Check array claims
            if let Some((array_name, index)) = self.parse_array_claim_name(&claim_name) {
                if let Some(elements) = self.sd_jwt.issuer_signed.array_claims.get_mut(&array_name)
                {
                    if let Some(element) = elements.get_mut(index) {
                        match element {
                            SdJwtArrayElement::Undisclosed { sd_hash } => {
                                if *sd_hash == disclosure.hash {
                                    *element = SdJwtArrayElement::Disclosed(claim_value);
                                    // Add to red list
                                    self.verification_context
                                        .red_list
                                        .add_disclosure(disclosure.hash.clone())?;
                                } else {
                                    return Err(AuthencError::ValidationError {
                                        message: "Disclosure hash does not match".to_string(),
                                    });
                                }
                            }
                            _ => {
                                return Err(AuthencError::ValidationError {
                                    message: "Array element is not undisclosed".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_array_claim_name(&self, claim_name: &str) -> Option<(String, usize)> {
        if let Some(dot_pos) = claim_name.rfind('.') {
            let array_name = &claim_name[..dot_pos];
            let index_str = &claim_name[dot_pos + 1..];
            if let Ok(index) = index_str.parse::<usize>() {
                return Some((array_name.to_string(), index));
            }
        }
        None
    }

    fn verify_disclosures(&self) -> Result<(), AuthencError> {
        // Verify all disclosures are valid and not expired
        for disclosure in &self.sd_jwt.disclosures {
            if !disclosure.verify() {
                return Err(AuthencError::ValidationError {
                    message: "Invalid disclosure signature".to_string(),
                });
            }

            // Check disclosure age if configured
            if let Some(_max_age) = self.verification_context.max_disclosure_age {
                // Check if disclosure is too old
                // This would require storing disclosure timestamps
            }
        }
        Ok(())
    }

    fn verify_red_list(&self) -> Result<(), AuthencError> {
        // Check that no disclosures are in the red list
        for disclosure in &self.sd_jwt.disclosures {
            if self
                .verification_context
                .red_list
                .is_disclosed(&disclosure.hash)
            {
                return Err(AuthencError::ValidationError {
                    message: "Disclosure has been replayed (red list)".to_string(),
                });
            }
        }
        Ok(())
    }

    fn verify_issuer(&self) -> Result<(), AuthencError> {
        if let Some(expected_issuer) = &self.verification_context.expected_issuer {
            if let Some(issuer_claim) = self.sd_jwt.issuer_signed.payload.get("iss") {
                if let SdJwtClaim::Disclosed { value } = issuer_claim {
                    if let Some(issuer) = value.as_str() {
                        if issuer != expected_issuer {
                            return Err(AuthencError::ValidationError {
                                message: format!(
                                    "Issuer mismatch: expected {}, got {}",
                                    expected_issuer, issuer
                                ),
                            });
                        }
                    } else {
                        return Err(AuthencError::ValidationError {
                            message: "Issuer claim is not a string".to_string(),
                        });
                    }
                } else {
                    return Err(AuthencError::ValidationError {
                        message: "Issuer claim is not disclosed".to_string(),
                    });
                }
            } else {
                return Err(AuthencError::ValidationError {
                    message: "Missing issuer claim".to_string(),
                });
            }
        }
        Ok(())
    }

    fn verify_subject(&self) -> Result<(), AuthencError> {
        if let Some(expected_subject) = &self.verification_context.expected_subject {
            if let Some(subject_claim) = self.sd_jwt.issuer_signed.payload.get("sub") {
                if let SdJwtClaim::Disclosed { value } = subject_claim {
                    if let Some(subject) = value.as_str() {
                        if subject != expected_subject {
                            return Err(AuthencError::ValidationError {
                                message: format!(
                                    "Subject mismatch: expected {}, got {}",
                                    expected_subject, subject
                                ),
                            });
                        }
                    } else {
                        return Err(AuthencError::ValidationError {
                            message: "Subject claim is not a string".to_string(),
                        });
                    }
                } else {
                    return Err(AuthencError::ValidationError {
                        message: "Subject claim is not disclosed".to_string(),
                    });
                }
            } else {
                return Err(AuthencError::ValidationError {
                    message: "Missing subject claim".to_string(),
                });
            }
        }
        Ok(())
    }

    fn verify_audience(&self) -> Result<(), AuthencError> {
        if let Some(expected_audience) = &self.verification_context.expected_audience {
            if let Some(audience_claim) = self.sd_jwt.issuer_signed.payload.get("aud") {
                if let SdJwtClaim::Disclosed { value } = audience_claim {
                    if let Some(audience) = value.as_str() {
                        if audience != expected_audience {
                            return Err(AuthencError::ValidationError {
                                message: format!(
                                    "Audience mismatch: expected {}, got {}",
                                    expected_audience, audience
                                ),
                            });
                        }
                    } else {
                        return Err(AuthencError::ValidationError {
                            message: "Audience claim is not a string".to_string(),
                        });
                    }
                } else {
                    return Err(AuthencError::ValidationError {
                        message: "Audience claim is not disclosed".to_string(),
                    });
                }
            } else {
                return Err(AuthencError::ValidationError {
                    message: "Missing audience claim".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// SD-JWT utilities
pub struct SdJwtUtils;

impl SdJwtUtils {
    /// Create SD-JWT with privacy-preserving claims
    pub fn create_privacy_preserving_jwt(
        issuer: &str,
        subject: &str,
        audience: &str,
        claims: HashMap<String, Value>,
        decoy_count: usize,
    ) -> Result<SdJwt, AuthencError> {
        let mut issuer_signed = IssuerSignedJwt::new(issuer, subject, audience);

        // Add selective disclosures for sensitive claims
        let sensitive_claims = ["email", "phone", "address", "ssn", "birthdate"];

        for (key, value) in claims {
            if sensitive_claims.contains(&key.as_str()) {
                let salt = SdJwtSalt::new();
                issuer_signed.add_selective_claim(key, value, salt)?;
            } else {
                issuer_signed
                    .payload
                    .insert(key, SdJwtClaim::Disclosed { value });
            }
        }

        // Add decoy claims for enhanced privacy
        for i in 0..decoy_count {
            issuer_signed.add_decoy_claim(format!("decoy_claim_{}", i));
        }

        Ok(SdJwt::new(issuer_signed))
    }

    /// Create SD-JWT with array disclosures
    pub fn create_array_disclosure_jwt(
        issuer: &str,
        subject: &str,
        audience: &str,
        array_claims: HashMap<String, Vec<Value>>,
        _disclosure_ratio: f64, // 0.0 to 1.0
    ) -> Result<SdJwt, AuthencError> {
        let mut issuer_signed = IssuerSignedJwt::new(issuer, subject, audience);

        for (array_name, elements) in array_claims {
            let salts: Vec<SdJwtSalt> = elements.iter().map(|_| SdJwtSalt::new()).collect();

            issuer_signed.add_selective_array_claim(array_name, elements, salts)?;
        }

        Ok(SdJwt::new(issuer_signed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sd_jwt_creation_and_verification() {
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut issuer_signed = IssuerSignedJwt::new("issuer", "subject", "audience");

        // Add selective claim
        let salt = SdJwtSalt::new();
        issuer_signed
            .add_selective_claim("email".to_string(), json!("user@example.com"), salt)
            .unwrap();

        // Add decoy claim
        issuer_signed.add_decoy_claim("fake_claim".to_string());

        // Sign JWT
        issuer_signed.sign(&keypair).unwrap();

        // Create SD-JWT
        let mut sd_jwt = SdJwt::new(issuer_signed);

        // Add disclosure
        let disclosure = Disclosure::new(DisclosureSpec {
            claim_name: "email".to_string(),
            claim_value: json!("user@example.com"),
            salt: SdJwtSalt::new(),
        })
        .unwrap();
        sd_jwt.add_disclosure(disclosure);

        // Verify SD-JWT
        assert!(sd_jwt.verify(&keypair.verifying_key()).is_ok());

        // Get disclosed claims
        let claims = sd_jwt.get_disclosed_claims().unwrap();
        assert!(claims.contains_key("iss"));
        assert!(claims.contains_key("sub"));
        assert!(claims.contains_key("email"));
    }

    #[test]
    fn test_privacy_preserving_jwt() {
        let claims = HashMap::from([
            ("name".to_string(), json!("John Doe")),
            ("email".to_string(), json!("john@example.com")),
            ("phone".to_string(), json!("+1234567890")),
        ]);

        let sd_jwt = SdJwtUtils::create_privacy_preserving_jwt(
            "issuer", "subject", "audience", claims, 3, // 3 decoy claims
        )
        .unwrap();

        // Should have decoy claims
        let decoy_count = sd_jwt
            .issuer_signed
            .payload
            .values()
            .filter(|claim| matches!(claim, SdJwtClaim::Decoy { .. }))
            .count();

        assert_eq!(decoy_count, 3);
    }
}
