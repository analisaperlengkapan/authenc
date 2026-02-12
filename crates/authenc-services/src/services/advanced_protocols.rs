//! Advanced OAuth2/OIDC Protocol Extensions
//!
//! This module implements advanced OAuth2 and OIDC protocol features
//! for enterprise identity management, including:
//! - Rich Authorization Requests (RAR)
//! - JWT Secured Authorization Response Mode (JARM)
//! - OAuth 2.0 Token Exchange
//! - Advanced grant types and flows

use authenc_core::error::AuthencError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Rich Authorization Request (RAR) implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichAuthorizationRequest {
    /// The authorization details specifying what the client is requesting access to
    pub authorization_details: Vec<AuthorizationDetail>,
    /// Additional request parameters beyond the standard OAuth2 parameters
    pub additional_parameters: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Authorization detail for Rich Authorization Requests (RAR)
/// Specifies fine-grained permissions for specific resources and actions
pub struct AuthorizationDetail {
    /// The type of authorization (e.g., "account_information", "payment_initiation")
    #[serde(rename = "type")]
    pub type_: String,
    /// The locations (endpoints or resources) for which authorization is requested
    pub locations: Option<Vec<String>>,
    /// The actions that the client wants to perform (e.g., "read", "write", "delete")
    pub actions: Option<Vec<String>>,
    /// The data types that the client wants to access
    pub datatypes: Option<Vec<String>>,
    /// The identifiers of specific resources
    pub identifiers: Option<Vec<String>>,
    /// Additional fields specific to the authorization type
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

impl Default for RichAuthorizationRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl RichAuthorizationRequest {
    /// Create a new empty Rich Authorization Request
    pub fn new() -> Self {
        Self {
            authorization_details: Vec::new(),
            additional_parameters: HashMap::new(),
        }
    }

    /// Add an authorization detail to the request
    ///
    /// # Arguments
    /// * `detail` - The authorization detail to add
    pub fn add_detail(&mut self, detail: AuthorizationDetail) {
        self.authorization_details.push(detail);
    }

    /// Validate the Rich Authorization Request according to OAuth2 RAR specification
    ///
    /// # Returns
    /// * `Ok(())` if the request is valid
    /// * `Err(AuthencError)` if validation fails
    pub fn validate(&self) -> Result<(), AuthencError> {
        if self.authorization_details.is_empty() {
            return Err(AuthencError::ValidationError {
                message: "RAR must contain at least one authorization detail".to_string(),
            });
        }

        for detail in &self.authorization_details {
            if detail.type_.is_empty() {
                return Err(AuthencError::ValidationError {
                    message: "Authorization detail type cannot be empty".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Convert the Rich Authorization Request to JSON for inclusion in JWT
    ///
    /// # Returns
    /// * `Ok(Value)` containing the JSON representation
    /// * `Err(AuthencError)` if serialization fails
    pub fn to_json(&self) -> Result<Value, AuthencError> {
        serde_json::to_value(self).map_err(|_| AuthencError::SerializationError {
            message: "Failed to serialize RAR".to_string(),
        })
    }
}

/// JWT Secured Authorization Response Mode (JARM) implementation
/// Provides signed and optionally encrypted authorization responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSecuredAuthorizationResponse {
    /// The issuer of the response (authorization server identifier)
    pub iss: String,
    /// The audience of the response (client identifier)
    pub aud: String,
    /// The client ID that requested the authorization
    pub client_id: Option<String>,
    /// The expiration time of the JWT response
    pub exp: i64,
    /// The issued at time of the JWT response
    pub iat: i64,
    /// The response type (e.g., "code", "token")
    pub response_type: Option<String>,
    /// The state parameter from the original request
    pub state: Option<String>,
    /// The authorization code (for authorization code flow)
    pub code: Option<String>,
    /// The access token (for implicit flow)
    pub access_token: Option<String>,
    /// The token type (usually "Bearer")
    pub token_type: Option<String>,
    /// The expiration time of the access token in seconds
    pub expires_in: Option<i64>,
    /// The granted scope
    pub scope: Option<String>,
    /// The ID token (for OpenID Connect)
    pub id_token: Option<String>,
    /// Error code if the authorization failed
    pub error: Option<String>,
    /// Human-readable error description
    pub error_description: Option<String>,
    /// URI pointing to more error information
    pub error_uri: Option<String>,
}

impl JwtSecuredAuthorizationResponse {
    /// Create a successful authorization response
    ///
    /// # Arguments
    /// * `issuer` - The authorization server identifier
    /// * `audience` - The client identifier
    /// * `client_id` - The client that requested authorization
    /// * `code` - Optional authorization code
    /// * `access_token` - Optional access token
    /// * `id_token` - Optional ID token
    /// * `state` - Optional state parameter
    /// * `scope` - Optional granted scope
    #[allow(clippy::too_many_arguments)]
    pub fn success(
        issuer: String,
        audience: String,
        client_id: String,
        code: Option<String>,
        access_token: Option<String>,
        id_token: Option<String>,
        state: Option<String>,
        scope: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer,
            aud: audience,
            client_id: Some(client_id),
            exp: now + 300, // 5 minutes
            iat: now,
            response_type: Some("code".to_string()),
            state,
            code,
            access_token: access_token.clone(),
            token_type: access_token.as_ref().map(|_| "Bearer".to_string()),
            expires_in: access_token.as_ref().map(|_| 3600),
            scope,
            id_token,
            error: None,
            error_description: None,
            error_uri: None,
        }
    }

    /// Create an error authorization response
    ///
    /// # Arguments
    /// * `issuer` - The authorization server identifier
    /// * `audience` - The client identifier
    /// * `error` - The error code
    /// * `error_description` - Optional human-readable error description
    /// * `state` - Optional state parameter from the original request
    pub fn error(
        issuer: String,
        audience: String,
        error: String,
        error_description: Option<String>,
        state: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer,
            aud: audience,
            client_id: None,
            exp: now + 300, // 5 minutes
            iat: now,
            response_type: None,
            state,
            code: None,
            access_token: None,
            token_type: None,
            expires_in: None,
            scope: None,
            id_token: None,
            error: Some(error),
            error_description,
            error_uri: None,
        }
    }

    /// Sign the response as a JWT using EdDSA
    ///
    /// # Arguments
    /// * `signing_key` - The Ed25519 signing key to use for signing
    ///
    /// # Returns
    /// * `Ok(String)` containing the signed JWT
    /// * `Err(AuthencError)` if signing or serialization fails
    pub fn sign(&self, signing_key: &ed25519_dalek::SigningKey) -> Result<String, AuthencError> {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use ed25519_dalek::Signer;

        let header = json!({
            "alg": "EdDSA",
            "typ": "oauth-authz-rsp+jwt"
        });

        let payload = serde_json::to_value(self).map_err(|_| AuthencError::SerializationError {
            message: "Failed to serialize JARM response".to_string(),
        })?;

        let header_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&header)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize header".to_string(),
                })?
                .as_bytes(),
        );

        let payload_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&payload)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize payload".to_string(),
                })?
                .as_bytes(),
        );

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = signing_key.sign(message.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }
}

/// OAuth 2.0 Token Exchange implementation
/// Allows exchanging one type of token for another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    /// The grant type (must be "urn:ietf:params:oauth:grant-type:token-exchange")
    pub grant_type: String,
    /// The subject token to be exchanged
    pub subject_token: String,
    /// The type of the subject token (e.g., "urn:ietf:params:oauth:token-type:access_token")
    pub subject_token_type: String,
    /// Optional actor token representing the identity of the acting party
    pub actor_token: Option<String>,
    /// The type of the actor token
    pub actor_token_type: Option<String>,
    /// The type of token requested in the response
    pub requested_token_type: Option<String>,
    /// The resource parameter specifying the target resource
    pub resource: Option<String>,
    /// The audience parameter specifying the target audience
    pub audience: Option<String>,
    /// The scope parameter specifying the requested scope
    pub scope: Option<String>,
    /// Additional parameters specific to the token exchange request
    #[serde(flatten)]
    pub additional_parameters: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Response payload for OAuth 2.0 Token Exchange
/// Contains the exchanged token and associated metadata
pub struct TokenExchangeResponse {
    /// The exchanged access token
    pub access_token: String,
    /// The type of the token (usually "Bearer")
    pub token_type: String,
    /// The expiration time of the token in seconds
    pub expires_in: Option<i64>,
    /// The scope of the exchanged token
    pub scope: Option<String>,
    /// The issued token type
    pub issued_token_type: String,
    /// The refresh token (optional)
    pub refresh_token: Option<String>,
}

/// Token Exchange Grant Type Handler
/// Handles OAuth 2.0 Token Exchange grant type requests
pub struct TokenExchangeGrantTypeHandler;

impl TokenExchangeGrantTypeHandler {
    /// Handle token exchange request
    ///
    /// # Arguments
    /// * `request` - The token exchange request
    /// * `client_id` - The client identifier making the request
    ///
    /// # Returns
    /// * `Ok(TokenExchangeResponse)` containing the exchanged token
    /// * `Err(AuthencError)` if the exchange fails
    pub async fn handle_exchange(
        &self,
        request: TokenExchangeRequest,
        client_id: &str,
    ) -> Result<TokenExchangeResponse, AuthencError> {
        // Validate grant type
        if request.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
            return Err(AuthencError::ValidationError {
                message: "Invalid grant type for token exchange".to_string(),
            });
        }

        // Validate subject token
        self.validate_subject_token(&request.subject_token, &request.subject_token_type)
            .await?;

        // Validate actor token if present
        if let Some(actor_token) = &request.actor_token {
            if let Some(actor_token_type) = &request.actor_token_type {
                self.validate_actor_token(actor_token, actor_token_type)
                    .await?;
            } else {
                return Err(AuthencError::ValidationError {
                    message: "Actor token type required when actor token is provided".to_string(),
                });
            }
        }

        // Perform the token exchange
        self.perform_token_exchange(request, client_id).await
    }

    async fn validate_subject_token(
        &self,
        _token: &str,
        token_type: &str,
    ) -> Result<(), AuthencError> {
        // Validate the subject token based on its type
        match token_type {
            "urn:ietf:params:oauth:token-type:access_token" => {
                // Validate access token
                // This would integrate with token validation logic
                Ok(())
            }
            "urn:ietf:params:oauth:token-type:refresh_token" => {
                // Validate refresh token
                Ok(())
            }
            "urn:ietf:params:oauth:token-type:id_token" => {
                // Validate ID token
                Ok(())
            }
            _ => Err(AuthencError::ValidationError {
                message: format!("Unsupported subject token type: {}", token_type),
            }),
        }
    }

    async fn validate_actor_token(
        &self,
        _token: &str,
        token_type: &str,
    ) -> Result<(), AuthencError> {
        // Validate the actor token
        match token_type {
            "urn:ietf:params:oauth:token-type:access_token" => Ok(()),
            _ => Err(AuthencError::ValidationError {
                message: format!("Unsupported actor token type: {}", token_type),
            }),
        }
    }

    async fn perform_token_exchange(
        &self,
        request: TokenExchangeRequest,
        _client_id: &str,
    ) -> Result<TokenExchangeResponse, AuthencError> {
        // Generate new token based on the exchange request
        // This would integrate with token generation logic

        let access_token = "new_access_token_here".to_string();
        let token_type = "Bearer".to_string();
        let issued_token_type = request
            .requested_token_type
            .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:access_token".to_string());

        Ok(TokenExchangeResponse {
            access_token,
            token_type,
            expires_in: Some(3600),
            scope: request.scope,
            issued_token_type,
            refresh_token: None,
        })
    }
}

/// Advanced Grant Types Manager
/// Manages advanced OAuth2 grant types like token exchange
pub struct AdvancedGrantTypesManager {
    token_exchange_handler: TokenExchangeGrantTypeHandler,
}

impl Default for AdvancedGrantTypesManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedGrantTypesManager {
    /// Create a new advanced grant types manager
    pub fn new() -> Self {
        Self {
            token_exchange_handler: TokenExchangeGrantTypeHandler,
        }
    }

    /// Handle advanced grant type requests
    ///
    /// # Arguments
    /// * `grant_type` - The grant type identifier
    /// * `parameters` - The request parameters
    /// * `client_id` - The client identifier
    ///
    /// # Returns
    /// * `Ok(HashMap<String, String>)` containing the response parameters
    /// * `Err(AuthencError)` if the grant type is not supported or processing fails
    pub async fn handle_grant_type(
        &self,
        grant_type: &str,
        parameters: HashMap<String, String>,
        client_id: &str,
    ) -> Result<HashMap<String, String>, AuthencError> {
        match grant_type {
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                let request: TokenExchangeRequest =
                    serde_json::from_value(serde_json::to_value(&parameters).map_err(|_| {
                        AuthencError::SerializationError {
                            message: "Failed to parse token exchange request".to_string(),
                        }
                    })?)
                    .map_err(|_| AuthencError::ValidationError {
                        message: "Invalid token exchange request format".to_string(),
                    })?;

                let response = self
                    .token_exchange_handler
                    .handle_exchange(request, client_id)
                    .await?;

                let mut result = HashMap::new();
                result.insert("access_token".to_string(), response.access_token);
                result.insert("token_type".to_string(), response.token_type);
                if let Some(expires_in) = response.expires_in {
                    result.insert("expires_in".to_string(), expires_in.to_string());
                }
                if let Some(scope) = response.scope {
                    result.insert("scope".to_string(), scope);
                }
                result.insert("issued_token_type".to_string(), response.issued_token_type);

                Ok(result)
            }
            _ => Err(AuthencError::ValidationError {
                message: format!("Unsupported grant type: {}", grant_type),
            }),
        }
    }
}

/// OAuth 2.0 Device Authorization Flow
/// Request payload for device authorization grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// The client identifier requesting device authorization
    pub client_id: String,
    /// The scope of access requested
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Response payload for OAuth 2.0 Device Authorization Grant
/// Contains the device code and user instructions for device flow
pub struct DeviceAuthorizationResponse {
    /// The device code used for polling token status
    pub device_code: String,
    /// The user code to be entered at the verification URI
    pub user_code: String,
    /// The URI where the user should enter the user code
    pub verification_uri: String,
    /// The complete verification URI with user code pre-filled
    pub verification_uri_complete: Option<String>,
    /// The expiration time in seconds
    pub expires_in: i64,
    /// The minimum interval in seconds between polling requests
    pub interval: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Request payload for device token exchange
/// Used to poll for token status during device flow
pub struct DeviceTokenRequest {
    /// The grant type (must be "urn:ietf:params:oauth:grant-type:device_code")
    pub grant_type: String,
    /// The device code obtained from device authorization
    pub device_code: String,
    /// The client identifier
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Response payload for device token requests
/// Either indicates authorization is pending or provides the access token
pub enum DeviceTokenResponse {
    /// Authorization pending - user hasn't completed the flow yet
    Pending {
        /// Error code (usually "authorization_pending")
        error: String,
        /// Human-readable error description
        error_description: String,
    },
    /// Authorization completed - access token granted
    Success {
        /// The access token
        access_token: String,
        /// The token type (usually "Bearer")
        token_type: String,
        /// The expiration time in seconds
        expires_in: Option<i64>,
        /// The granted scope
        scope: Option<String>,
        /// Refresh token
        refresh_token: Option<String>,
    },
}

/// Device Authorization Grant Type Handler
/// Manages OAuth 2.0 Device Authorization Flow
pub struct DeviceAuthorizationGrantTypeHandler {
    device_codes: HashMap<String, DeviceCodeState>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DeviceCodeState {
    client_id: String,
    scope: Option<String>,
    user_code: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    authorized: bool,
}

impl Default for DeviceAuthorizationGrantTypeHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuthorizationGrantTypeHandler {
    /// Create a new device authorization grant type handler
    pub fn new() -> Self {
        Self {
            device_codes: HashMap::new(),
        }
    }

    /// Handle device authorization request
    ///
    /// # Arguments
    /// * `request` - The device authorization request
    ///
    /// # Returns
    /// * `Ok(DeviceAuthorizationResponse)` containing device and user codes
    /// * `Err(AuthencError)` if the request processing fails
    pub async fn handle_device_authorization(
        &mut self,
        request: DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse, AuthencError> {
        let device_code = uuid::Uuid::new_v4().to_string();
        let user_code = self.generate_user_code();
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

        let state = DeviceCodeState {
            client_id: request.client_id,
            scope: request.scope,
            user_code: user_code.clone(),
            expires_at,
            authorized: false,
        };

        self.device_codes.insert(device_code.clone(), state);

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code: user_code.clone(),
            verification_uri: "https://auth.example.com/device".to_string(),
            verification_uri_complete: Some(format!(
                "https://auth.example.com/device?user_code={}",
                user_code
            )),
            expires_in: 600,
            interval: Some(5),
        })
    }

    /// Handle device token request
    ///
    /// # Arguments
    /// * `request` - The device token request
    ///
    /// # Returns
    /// * `Ok(DeviceTokenResponse)` containing either pending status or access token
    /// * `Err(AuthencError)` if the request is invalid
    pub async fn handle_device_token(
        &mut self,
        request: DeviceTokenRequest,
    ) -> Result<DeviceTokenResponse, AuthencError> {
        // Validate grant type
        if request.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
            return Err(AuthencError::ValidationError {
                message: "Invalid grant type for device token".to_string(),
            });
        }

        // Get device code state
        let state = self.device_codes.get(&request.device_code).ok_or_else(|| {
            AuthencError::ValidationError {
                message: "Invalid device code".to_string(),
            }
        })?;

        // Check expiration
        if chrono::Utc::now() > state.expires_at {
            return Ok(DeviceTokenResponse::Pending {
                error: "expired_token".to_string(),
                error_description: "The device code has expired".to_string(),
            });
        }

        // Check if authorized
        if !state.authorized {
            return Ok(DeviceTokenResponse::Pending {
                error: "authorization_pending".to_string(),
                error_description: "The authorization request is still pending".to_string(),
            });
        }

        // Generate tokens
        let access_token = "device_access_token".to_string();
        let token_type = "Bearer".to_string();

        Ok(DeviceTokenResponse::Success {
            access_token,
            token_type,
            expires_in: Some(3600),
            scope: state.scope.clone(),
            refresh_token: Some("device_refresh_token".to_string()),
        })
    }

    /// Authorize device code (called when user completes authorization)
    ///
    /// # Arguments
    /// * `user_code` - The user code entered by the user
    ///
    /// # Returns
    /// * `Ok(())` if the device code was successfully authorized
    /// * `Err(AuthencError)` if the user code is invalid
    pub async fn authorize_device_code(&mut self, user_code: &str) -> Result<(), AuthencError> {
        // Find device code by user code
        for state in self.device_codes.values_mut() {
            if state.user_code == user_code {
                state.authorized = true;
                return Ok(());
            }
        }

        Err(AuthencError::ValidationError {
            message: "Invalid user code".to_string(),
        })
    }

    fn generate_user_code(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!("{:04}", rng.gen_range(0..10000))
    }
}
