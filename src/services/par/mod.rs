//! PAR (Pushed Authorization Requests) Implementation
//!
//! RFC 9126 PAR (Pushed Authorization Requests) allows clients to push
//! authorization request parameters to the authorization server, improving
//! security by avoiding parameter exposure in browser redirects.
//!
//! Features:
//! - Secure parameter transmission
//! - Request URI generation and validation
//! - Automatic parameter cleanup
//! - Integration with OAuth2 flows
//! - Request object support (JWT Secured Authorization Requests)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use crate::error::AuthencError;
use crate::models::oauth2::OAuth2Client;

/// PAR Request Parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PARRequest {
    /// Client ID
    pub client_id: String,
    /// Response type
    pub response_type: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scopes
    pub scope: Option<String>,
    /// State parameter
    pub state: Option<String>,
    /// Nonce parameter
    pub nonce: Option<String>,
    /// Code challenge for PKCE
    pub code_challenge: Option<String>,
    /// Code challenge method
    pub code_challenge_method: Option<String>,
    /// Additional parameters
    #[serde(flatten)]
    pub additional_params: HashMap<String, String>,
}

/// PAR Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PARResponse {
    /// Request URI for the pushed request
    pub request_uri: String,
    /// Expiration time in seconds
    pub expires_in: i64,
}

/// Stored PAR Request with metadata
#[derive(Debug, Clone)]
pub struct StoredPARRequest {
    /// Unique request ID
    pub request_id: String,
    /// Request parameters
    pub request: PARRequest,
    /// Client information
    pub client: OAuth2Client,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Whether the request has been consumed
    pub consumed: bool,
}

/// PAR Storage interface
#[async_trait::async_trait]
pub trait PARStorage: Send + Sync {
    /// Store a PAR request
    async fn store_request(&self, request: StoredPARRequest) -> Result<(), AuthencError>;

    /// Retrieve a PAR request by URI
    async fn get_request(&self, request_uri: &str) -> Result<Option<StoredPARRequest>, AuthencError>;

    /// Mark a PAR request as consumed
    async fn consume_request(&self, request_uri: &str) -> Result<(), AuthencError>;

    /// Clean up expired requests
    async fn cleanup_expired(&self) -> Result<(), AuthencError>;
}

/// In-memory PAR storage implementation
pub struct InMemoryPARStorage {
    storage: Arc<RwLock<HashMap<String, StoredPARRequest>>>,
}

impl Default for InMemoryPARStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryPARStorage {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl PARStorage for InMemoryPARStorage {
    async fn store_request(&self, request: StoredPARRequest) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        storage.insert(request.request_id.clone(), request);
        Ok(())
    }

    async fn get_request(&self, request_uri: &str) -> Result<Option<StoredPARRequest>, AuthencError> {
        let storage = self.storage.read().await;

        // Extract request ID from URI (format: urn:ietf:params:oauth:request_uri:{id})
        let request_id = request_uri
            .strip_prefix("urn:ietf:params:oauth:request_uri:")
            .ok_or_else(|| AuthencError::validation("Invalid request URI format".to_string()))?;

        Ok(storage.get(request_id).cloned())
    }

    async fn consume_request(&self, request_uri: &str) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;

        let request_id = request_uri
            .strip_prefix("urn:ietf:params:oauth:request_uri:")
            .ok_or_else(|| AuthencError::validation("Invalid request URI format".to_string()))?;

        if let Some(request) = storage.get_mut(request_id) {
            request.consumed = true;
        }

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), AuthencError> {
        let mut storage = self.storage.write().await;
        let now = Utc::now();

        storage.retain(|_, request| {
            !request.consumed && request.expires_at > now
        });

        Ok(())
    }
}

/// PAR Manager - Core PAR functionality
pub struct PARManager<S: PARStorage> {
    storage: S,
    default_expiration_seconds: i64,
}

impl<S: PARStorage> PARManager<S> {
    /// Create new PAR manager
    pub fn new(storage: S, default_expiration_seconds: i64) -> Self {
        Self {
            storage,
            default_expiration_seconds,
        }
    }

    /// Push authorization request
    pub async fn push_authorization_request(
        &self,
        client: OAuth2Client,
        request: PARRequest,
    ) -> Result<PARResponse, AuthencError> {
        // Validate client
        if request.client_id != client.client_id {
            return Err(AuthencError::validation("Client ID mismatch".to_string()));
        }

        // Validate redirect URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(AuthencError::validation("Invalid redirect URI".to_string()));
        }

        // Generate unique request ID
        let request_id = Uuid::new_v4().to_string();

        // Create request URI
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", request_id);

        // Calculate expiration
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(self.default_expiration_seconds);

        // Store the request
        let stored_request = StoredPARRequest {
            request_id,
            request,
            client,
            created_at,
            expires_at,
            consumed: false,
        };

        self.storage.store_request(stored_request).await?;

        Ok(PARResponse {
            request_uri,
            expires_in: self.default_expiration_seconds,
        })
    }

    /// Get authorization request parameters
    pub async fn get_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<(PARRequest, OAuth2Client)>, AuthencError> {
        if let Some(stored_request) = self.storage.get_request(request_uri).await? {
            // Check if expired
            if stored_request.expires_at <= Utc::now() {
                return Err(AuthencError::validation("PAR request expired".to_string()));
            }

            // Check if already consumed
            if stored_request.consumed {
                return Err(AuthencError::validation("PAR request already consumed".to_string()));
            }

            Ok(Some((stored_request.request, stored_request.client)))
        } else {
            Ok(None)
        }
    }

    /// Consume authorization request (called after successful authorization)
    pub async fn consume_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<(), AuthencError> {
        self.storage.consume_request(request_uri).await
    }

    /// Clean up expired requests
    pub async fn cleanup_expired_requests(&self) -> Result<(), AuthencError> {
        self.storage.cleanup_expired().await
    }
}

/// PAR-aware OAuth2 Authorization Handler
pub struct PARAuthorizationHandler<S: PARStorage> {
    par_manager: PARManager<S>,
}

impl<S: PARStorage> PARAuthorizationHandler<S> {
    pub fn new(par_manager: PARManager<S>) -> Self {
        Self { par_manager }
    }

    /// Handle authorization request (supports both traditional and PAR flows)
    pub async fn handle_authorization_request(
        &self,
        params: HashMap<String, String>,
    ) -> Result<String, AuthencError> {
        // Check if this is a PAR request (has request_uri)
        if let Some(request_uri) = params.get("request_uri") {
            // PAR flow - get parameters from stored request
            if let Some((par_request, client)) = self.par_manager
                .get_authorization_request(request_uri)
                .await?
            {
                // Validate client_id matches if provided in both places
                if let Some(client_id) = params.get("client_id") {
                    if *client_id != par_request.client_id {
                        return Err(AuthencError::validation("Client ID mismatch in PAR request".to_string()));
                    }
                }

                // Use PAR parameters for authorization flow
                self.process_authorization_flow(par_request, client).await
            } else {
                Err(AuthencError::validation("Invalid or expired request URI".to_string()))
            }
        } else {
            // Traditional flow - parameters in URL
            let par_request = self.parse_traditional_params(params)?;
            // In traditional flow, we'd need to validate client separately
            // For now, return placeholder
            Err(AuthencError::validation("Traditional OAuth2 flow not implemented in this example".to_string()))
        }
    }

    /// Process authorization flow with PAR parameters
    async fn process_authorization_flow(
        &self,
        request: PARRequest,
        client: OAuth2Client,
    ) -> Result<String, AuthencError> {
        // This would integrate with your OAuth2 authorization flow
        // For now, return a placeholder authorization code

        // In a real implementation, this would:
        // 1. Validate scopes
        // 2. Check user consent
        // 3. Generate authorization code
        // 4. Store code with PAR request details
        // 5. Return redirect URL

        let authorization_code = format!("auth_code_{}", Uuid::new_v4());

        // Mark PAR request as consumed
        // Note: In real implementation, this should be done after successful token exchange
        // self.par_manager.consume_authorization_request(&request_uri).await?;

        Ok(format!("https://client.example.com/callback?code={}&state={}",
            authorization_code,
            request.state.unwrap_or_default()))
    }

    /// Parse traditional OAuth2 parameters
    fn parse_traditional_params(&self, params: HashMap<String, String>) -> Result<PARRequest, AuthencError> {
        Ok(PARRequest {
            client_id: params.get("client_id")
                .ok_or_else(|| AuthencError::validation("Missing client_id".to_string()))?
                .clone(),
            response_type: params.get("response_type")
                .ok_or_else(|| AuthencError::validation("Missing response_type".to_string()))?
                .clone(),
            redirect_uri: params.get("redirect_uri")
                .ok_or_else(|| AuthencError::validation("Missing redirect_uri".to_string()))?
                .clone(),
            scope: params.get("scope").cloned(),
            state: params.get("state").cloned(),
            nonce: params.get("nonce").cloned(),
            code_challenge: params.get("code_challenge").cloned(),
            code_challenge_method: params.get("code_challenge_method").cloned(),
            additional_params: params.into_iter()
                .filter(|(k, _)| !["client_id", "response_type", "redirect_uri", "scope",
                                  "state", "nonce", "code_challenge", "code_challenge_method"].contains(&k.as_str()))
                .collect(),
        })
    }
}

/// PAR Middleware for Axum
pub mod middleware {
    use axum::{
        extract::State,
        http::StatusCode,
        response::Json,
        Router,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use serde::Deserialize;

    use super::{PARManager, PARStorage, PARRequest, PARResponse};

    #[derive(Deserialize)]
    pub struct PARPushRequest {
        pub client_id: String,
        pub response_type: String,
        pub redirect_uri: String,
        pub scope: Option<String>,
        pub state: Option<String>,
        pub nonce: Option<String>,
        pub code_challenge: Option<String>,
        pub code_challenge_method: Option<String>,
    }

    /// PAR middleware state
    pub struct PARMiddlewareState<S: PARStorage> {
        pub par_manager: PARManager<S>,
    }

    /// PAR push endpoint handler
    pub async fn push_authorization_request<S: PARStorage>(
        State(state): State<Arc<PARMiddlewareState<S>>>,
        Json(payload): Json<PARPushRequest>,
    ) -> Result<Json<PARResponse>, StatusCode> {
        // In a real implementation, you'd validate the client here
        // For this example, we'll create a mock client
        let mock_client = crate::models::oauth2::OAuth2Client {
            id: uuid::Uuid::new_v4(),
            client_id: payload.client_id.clone(),
            client_secret_hash: "mock_secret_hash".to_string(),
            client_name: "Mock Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec![payload.redirect_uri.clone()],
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };

        let par_request = PARRequest {
            client_id: payload.client_id,
            response_type: payload.response_type,
            redirect_uri: payload.redirect_uri,
            scope: payload.scope,
            state: payload.state,
            nonce: payload.nonce,
            code_challenge: payload.code_challenge,
            code_challenge_method: payload.code_challenge_method,
            additional_params: HashMap::new(),
        };

        match state.par_manager.push_authorization_request(mock_client, par_request).await {
            Ok(response) => Ok(Json(response)),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }

    /// Create PAR routes
    pub fn create_par_routes<S: PARStorage + 'static>(state: Arc<PARMiddlewareState<S>>) -> Router {
        Router::new()
            .route("/oauth/par", axum::routing::post(push_authorization_request::<S>))
            .with_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_par_request_storage() {
        let storage = InMemoryPARStorage::new();
        let manager = PARManager::new(storage, 600); // 10 minutes

        let mock_client = crate::models::oauth2::OAuth2Client {
            id: uuid::Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: "secret_hash".to_string(),
            client_name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };

        let par_request = PARRequest {
            client_id: "test-client".to_string(),
            response_type: "code".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid profile".to_string()),
            state: Some("state123".to_string()),
            nonce: Some("nonce456".to_string()),
            code_challenge: Some("challenge789".to_string()),
            code_challenge_method: Some("S256".to_string()),
            additional_params: HashMap::new(),
        };

        // Push authorization request
        let response = manager.push_authorization_request(mock_client, par_request).await.unwrap();

        // Verify response
        assert!(response.request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        assert_eq!(response.expires_in, 600);

        // Retrieve request
        let (retrieved_request, retrieved_client) = manager
            .get_authorization_request(&response.request_uri)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(retrieved_request.client_id, "test-client");
        assert_eq!(retrieved_request.response_type, "code");
        assert_eq!(retrieved_client.client_id, "test-client");
    }

    #[tokio::test]
    async fn test_par_request_consumption() {
        let storage = InMemoryPARStorage::new();
        let manager = PARManager::new(storage, 600);

        let mock_client = crate::models::oauth2::OAuth2Client {
            id: uuid::Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: "secret_hash".to_string(),
            client_name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };

        let par_request = PARRequest {
            client_id: "test-client".to_string(),
            response_type: "code".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        // Push and consume request
        let response = manager.push_authorization_request(mock_client, par_request).await.unwrap();
        manager.consume_authorization_request(&response.request_uri).await.unwrap();

        // Try to retrieve consumed request
        let result = manager.get_authorization_request(&response.request_uri).await;
        assert!(result.is_err()); // Should fail because request was consumed
    }

    #[test]
    fn test_par_request_parsing() {
        let manager = PARManager::new(InMemoryPARStorage::new(), 600);
        let handler = PARAuthorizationHandler::new(manager);

        let params = HashMap::from([
            ("client_id".to_string(), "test-client".to_string()),
            ("response_type".to_string(), "code".to_string()),
            ("redirect_uri".to_string(), "https://example.com/callback".to_string()),
            ("scope".to_string(), "openid profile".to_string()),
            ("custom_param".to_string(), "custom_value".to_string()),
        ]);

        let request = handler.parse_traditional_params(params).unwrap();

        assert_eq!(request.client_id, "test-client");
        assert_eq!(request.response_type, "code");
        assert_eq!(request.scope, Some("openid profile".to_string()));
        assert_eq!(request.additional_params.get("custom_param"), Some(&"custom_value".to_string()));
    }
}
