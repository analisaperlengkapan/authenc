//! Advanced OAuth2/OIDC Protocol Extensions
//!
//! This module implements advanced OAuth2 and OIDC protocol features
//! that Keycloak supports but Authenc is missing, including:
//! - Rich Authorization Requests (RAR)
//! - JWT Secured Authorization Response Mode (JARM)
//! - OAuth 2.0 Token Exchange
//! - Advanced grant types and flows

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use async_trait::async_trait;
use crate::error::AuthencError;

/// Rich Authorization Request (RAR) implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichAuthorizationRequest {
    /// The authorization details
    pub authorization_details: Vec<AuthorizationDetail>,
    /// Additional request parameters
    pub additional_parameters: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// The type of authorization
    #[serde(rename = "type")]
    pub type_: String,
    /// The locations for the authorization
    pub locations: Option<Vec<String>>,
    /// The actions for the authorization
    pub actions: Option<Vec<String>>,
    /// The data types for the authorization
    pub datatypes: Option<Vec<String>>,
    /// The identifiers for the authorization
    pub identifiers: Option<Vec<String>>,
    /// Additional fields specific to the authorization type
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

impl RichAuthorizationRequest {
    /// Create a new RAR
    pub fn new() -> Self {
        Self {
            authorization_details: Vec::new(),
            additional_parameters: HashMap::new(),
        }
    }

    /// Add an authorization detail
    pub fn add_detail(&mut self, detail: AuthorizationDetail) {
        self.authorization_details.push(detail);
    }

    /// Validate the RAR
    pub fn validate(&self) -> Result<(), AuthencError> {
        if self.authorization_details.is_empty() {
            return Err(AuthencError::ValidationError {
                message: "RAR must contain at least one authorization detail".to_string()
            });
        }

        for detail in &self.authorization_details {
            if detail.type_.is_empty() {
                return Err(AuthencError::ValidationError {
                    message: "Authorization detail type cannot be empty".to_string()
                });
            }
        }

        Ok(())
    }

    /// Convert to JSON for inclusion in JWT
    pub fn to_json(&self) -> Result<Value, AuthencError> {
        serde_json::to_value(self)
            .map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize RAR".to_string()
            })
    }
}

/// JWT Secured Authorization Response Mode (JARM) implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSecuredAuthorizationResponse {
    /// The issuer of the response
    pub iss: String,
    /// The audience of the response
    pub aud: String,
    /// The client ID
    pub client_id: Option<String>,
    /// The expiration time
    pub exp: i64,
    /// The issued at time
    pub iat: i64,
    /// The response type
    pub response_type: Option<String>,
    /// The state parameter
    pub state: Option<String>,
    /// The authorization code
    pub code: Option<String>,
    /// The access token
    pub access_token: Option<String>,
    /// The token type
    pub token_type: Option<String>,
    /// The expiration time of the access token
    pub expires_in: Option<i64>,
    /// The scope
    pub scope: Option<String>,
    /// The ID token
    pub id_token: Option<String>,
    /// Error information
    pub error: Option<String>,
    /// Error description
    pub error_description: Option<String>,
    /// Error URI
    pub error_uri: Option<String>,
}

impl JwtSecuredAuthorizationResponse {
    /// Create a successful authorization response
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

    /// Sign the response as a JWT
    pub fn sign(&self, signing_key: &ed25519_dalek::SigningKey) -> Result<String, AuthencError> {
        use ed25519_dalek::Signer;
        use base64ct::{Base64UrlUnpadded, Encoding};

        let header = json!({
            "alg": "EdDSA",
            "typ": "oauth-authz-rsp+jwt"
        });

        let payload = serde_json::to_value(self)
            .map_err(|_| AuthencError::SerializationError {
                message: "Failed to serialize JARM response".to_string()
            })?;

        let header_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&header)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize header".to_string()
                })?
                .as_bytes()
        );

        let payload_b64 = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&payload)
                .map_err(|_| AuthencError::SerializationError {
                    message: "Failed to serialize payload".to_string()
                })?
                .as_bytes()
        );

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = signing_key.sign(message.as_bytes());
        let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }
}

/// OAuth 2.0 Token Exchange implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    /// The grant type (must be "urn:ietf:params:oauth:grant-type:token-exchange")
    pub grant_type: String,
    /// The subject token
    pub subject_token: String,
    /// The subject token type
    pub subject_token_type: String,
    /// The actor token (optional)
    pub actor_token: Option<String>,
    /// The actor token type (optional)
    pub actor_token_type: Option<String>,
    /// The requested token type
    pub requested_token_type: Option<String>,
    /// The resource parameter
    pub resource: Option<String>,
    /// The audience parameter
    pub audience: Option<String>,
    /// The scope parameter
    pub scope: Option<String>,
    /// Additional parameters
    #[serde(flatten)]
    pub additional_parameters: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeResponse {
    /// The access token
    pub access_token: String,
    /// The token type
    pub token_type: String,
    /// The expiration time
    pub expires_in: Option<i64>,
    /// The scope
    pub scope: Option<String>,
    /// The issued token type
    pub issued_token_type: String,
    /// The refresh token (optional)
    pub refresh_token: Option<String>,
}

/// Token Exchange Grant Type Handler
pub struct TokenExchangeGrantTypeHandler;

impl TokenExchangeGrantTypeHandler {
    /// Handle token exchange request
    pub async fn handle_exchange(
        &self,
        request: TokenExchangeRequest,
        client_id: &str,
    ) -> Result<TokenExchangeResponse, AuthencError> {
        // Validate grant type
        if request.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
            return Err(AuthencError::ValidationError {
                message: "Invalid grant type for token exchange".to_string()
            });
        }

        // Validate subject token
        self.validate_subject_token(&request.subject_token, &request.subject_token_type).await?;

        // Validate actor token if present
        if let Some(actor_token) = &request.actor_token {
            if let Some(actor_token_type) = &request.actor_token_type {
                self.validate_actor_token(actor_token, actor_token_type).await?;
            } else {
                return Err(AuthencError::ValidationError {
                    message: "Actor token type required when actor token is provided".to_string()
                });
            }
        }

        // Perform the token exchange
        self.perform_token_exchange(request, client_id).await
    }

    async fn validate_subject_token(&self, token: &str, token_type: &str) -> Result<(), AuthencError> {
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
                message: format!("Unsupported subject token type: {}", token_type)
            })
        }
    }

    async fn validate_actor_token(&self, token: &str, token_type: &str) -> Result<(), AuthencError> {
        // Validate the actor token
        match token_type {
            "urn:ietf:params:oauth:token-type:access_token" => {
                Ok(())
            }
            _ => Err(AuthencError::ValidationError {
                message: format!("Unsupported actor token type: {}", token_type)
            })
        }
    }

    async fn perform_token_exchange(
        &self,
        request: TokenExchangeRequest,
        client_id: &str,
    ) -> Result<TokenExchangeResponse, AuthencError> {
        // Generate new token based on the exchange request
        // This would integrate with token generation logic

        let access_token = "new_access_token_here".to_string();
        let token_type = "Bearer".to_string();
        let issued_token_type = request.requested_token_type
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
pub struct AdvancedGrantTypesManager {
    token_exchange_handler: TokenExchangeGrantTypeHandler,
}

impl AdvancedGrantTypesManager {
    pub fn new() -> Self {
        Self {
            token_exchange_handler: TokenExchangeGrantTypeHandler,
        }
    }

    /// Handle advanced grant type
    pub async fn handle_grant_type(
        &self,
        grant_type: &str,
        parameters: HashMap<String, String>,
        client_id: &str,
    ) -> Result<HashMap<String, String>, AuthencError> {
        match grant_type {
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                let request: TokenExchangeRequest = serde_json::from_value(
                    serde_json::to_value(&parameters)
                        .map_err(|_| AuthencError::SerializationError {
                            message: "Failed to parse token exchange request".to_string()
                        })?
                )
                .map_err(|_| AuthencError::ValidationError {
                    message: "Invalid token exchange request format".to_string()
                })?;

                let response = self.token_exchange_handler.handle_exchange(request, client_id).await?;

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
                message: format!("Unsupported grant type: {}", grant_type)
            })
        }
    }
}

/// OAuth 2.0 Device Authorization Flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// The client ID
    pub client_id: String,
    /// The scope
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device code
    pub device_code: String,
    /// The user code
    pub user_code: String,
    /// The verification URI
    pub verification_uri: String,
    /// The verification URI complete
    pub verification_uri_complete: Option<String>,
    /// The expiration time
    pub expires_in: i64,
    /// The interval for polling
    pub interval: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    /// The grant type (must be "urn:ietf:params:oauth:grant-type:device_code")
    pub grant_type: String,
    /// The device code
    pub device_code: String,
    /// The client ID
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceTokenResponse {
    /// Authorization pending
    Pending {
        /// Error code
        error: String,
        /// Error description
        error_description: String,
    },
    /// Authorization completed
    Success {
        /// Access token
        access_token: String,
        /// Token type
        token_type: String,
        /// Expiration time
        expires_in: Option<i64>,
        /// Scope
        scope: Option<String>,
        /// Refresh token
        refresh_token: Option<String>,
    },
}

/// Device Authorization Grant Type Handler
pub struct DeviceAuthorizationGrantTypeHandler {
    device_codes: HashMap<String, DeviceCodeState>,
}

#[derive(Debug, Clone)]
struct DeviceCodeState {
    client_id: String,
    scope: Option<String>,
    user_code: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    authorized: bool,
}

impl DeviceAuthorizationGrantTypeHandler {
    pub fn new() -> Self {
        Self {
            device_codes: HashMap::new(),
        }
    }

    /// Handle device authorization request
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
            verification_uri_complete: Some(format!("https://auth.example.com/device?user_code={}", user_code)),
            expires_in: 600,
            interval: Some(5),
        })
    }

    /// Handle device token request
    pub async fn handle_device_token(
        &mut self,
        request: DeviceTokenRequest,
    ) -> Result<DeviceTokenResponse, AuthencError> {
        // Validate grant type
        if request.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
            return Err(AuthencError::ValidationError {
                message: "Invalid grant type for device token".to_string()
            });
        }

        // Get device code state
        let state = self.device_codes.get(&request.device_code)
            .ok_or_else(|| AuthencError::ValidationError {
                message: "Invalid device code".to_string()
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
    pub async fn authorize_device_code(&mut self, user_code: &str) -> Result<(), AuthencError> {
        // Find device code by user code
        for (device_code, state) in &mut self.device_codes {
            if state.user_code == user_code {
                state.authorized = true;
                return Ok(());
            }
        }

        Err(AuthencError::ValidationError {
            message: "Invalid user code".to_string()
        })
    }

    fn generate_user_code(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!("{:04}", rng.gen_range(0..10000))
    }
}
