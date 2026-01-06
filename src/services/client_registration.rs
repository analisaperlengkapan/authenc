use async_trait::async_trait;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{AuthencError, Result};
use crate::models::client_registration::{
    ClientRegistrationRequest, ClientRegistrationResponse, ClientUpdateRequest, SoftwareStatement,
};
use crate::models::oidc_client::OidcClient;
use crate::services::oidc_client_store::OidcClientStore;
use jsonwebtoken::{DecodingKey, Validation, decode};

/// Service for handling OAuth 2.0 Dynamic Client Registration (RFC 7591/7592)
#[async_trait]
pub trait ClientRegistrationService: Send + Sync {
    /// Register a new OAuth 2.0 client dynamically
    async fn register_client(
        &self,
        request: ClientRegistrationRequest,
        software_statement: Option<String>,
    ) -> Result<ClientRegistrationResponse>;

    /// Get client configuration
    async fn get_client_configuration(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<ClientRegistrationResponse>;

    /// Update client configuration
    async fn update_client_configuration(
        &self,
        client_id: &str,
        registration_access_token: &str,
        request: ClientUpdateRequest,
    ) -> Result<ClientRegistrationResponse>;

    /// Delete client registration
    async fn delete_client_registration(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<()>;

    /// Validate software statement
    async fn validate_software_statement(&self, token: &str) -> Result<SoftwareStatement>;
}

/// Default implementation of Client Registration Service
pub struct DefaultClientRegistrationService {
    client_store: Arc<OidcClientStore>,
    registration_tokens: Arc<RwLock<HashMap<String, String>>>, // client_id -> registration_access_token
    enable_dynamic_registration: bool,
    require_software_statement: bool,
    validation_secret: Option<Vec<u8>>,
}

impl DefaultClientRegistrationService {
    /// Create a new client registration service
    pub fn new(
        client_store: Arc<OidcClientStore>,
        enable_dynamic_registration: bool,
        require_software_statement: bool,
        validation_secret: Option<Vec<u8>>,
    ) -> Self {
        Self {
            client_store,
            registration_tokens: Arc::new(RwLock::new(HashMap::new())),
            enable_dynamic_registration,
            require_software_statement,
            validation_secret,
        }
    }

    /// Generate a unique client ID
    fn generate_client_id(&self) -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate a client secret
    fn generate_client_secret(&self) -> String {
        // Generate a secure random client secret
        use rand::distributions::Alphanumeric;
        use rand::{Rng, thread_rng};

        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Generate a registration access token
    fn generate_registration_access_token(&self) -> String {
        // Generate a secure random token
        use rand::distributions::Alphanumeric;
        use rand::{Rng, thread_rng};

        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    /// Validate client registration request
    fn validate_registration_request(&self, request: &ClientRegistrationRequest) -> Result<()> {
        // Validate required fields
        if request.redirect_uris.is_empty() {
            return Err(AuthencError::ValidationError {
                message: "At least one redirect URI is required".to_string(),
            });
        }

        // Validate redirect URIs
        for uri in &request.redirect_uris {
            if !uri.starts_with("https://") && !uri.starts_with("http://") {
                return Err(AuthencError::ValidationError {
                    message: "Redirect URIs must use http or https scheme".to_string(),
                });
            }
        }

        // Validate response types
        if let Some(response_types) = &request.response_types {
            let valid_types = ["code", "token", "id_token"];
            for rt in response_types {
                if !valid_types.contains(&rt.as_str()) {
                    return Err(AuthencError::ValidationError {
                        message: format!("Invalid response type: {}", rt),
                    });
                }
            }
        }

        // Validate grant types
        if let Some(grant_types) = &request.grant_types {
            let valid_types = [
                "authorization_code",
                "implicit",
                "password",
                "client_credentials",
                "refresh_token",
            ];
            for gt in grant_types {
                if !valid_types.contains(&gt.as_str()) {
                    return Err(AuthencError::ValidationError {
                        message: format!("Invalid grant type: {}", gt),
                    });
                }
            }
        }

        // Validate application type
        if let Some(app_type) = &request.application_type {
            if app_type != "web" && app_type != "native" {
                return Err(AuthencError::ValidationError {
                    message: "Application type must be 'web' or 'native'".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Convert registration request to OIDC client
    fn request_to_client(&self, request: &ClientRegistrationRequest) -> OidcClient {
        let client_id = self.generate_client_id();
        let client_secret = self.generate_client_secret();

        OidcClient {
            id: client_id.clone(),
            client_id,
            client_secret,
            redirect_uris: request.redirect_uris.clone(),
            name: request
                .client_name
                .clone()
                .unwrap_or_else(|| "Dynamic Client".to_string()),
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Convert OIDC client to registration response
    fn client_to_response(
        &self,
        client: &OidcClient,
        registration_access_token: &str,
    ) -> ClientRegistrationResponse {
        let response = ClientRegistrationResponse {
            client_id: client.client_id.clone(),
            client_id_issued_at: Some(chrono::Utc::now().timestamp()),
            client_secret: Some(client.client_secret.clone()),
            client_secret_expires_at: None, // Never expires by default
            redirect_uris: client.redirect_uris.clone(),
            response_types: Some(vec!["code".to_string()]), // Default to authorization code
            grant_types: Some(vec!["authorization_code".to_string()]),
            application_type: Some("web".to_string()),
            contacts: None,
            client_name: Some(client.name.clone()),
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks_uri: None,
            jwks: None,
            sector_identifier_uri: None,
            subject_type: Some("public".to_string()),
            id_token_signed_response_alg: Some("RS256".to_string()),
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: Some(false),
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            registration_access_token: Some(registration_access_token.to_string()),
            registration_client_uri: Some(format!("/register/{}", client.client_id)),
            additional_metadata: HashMap::new(),
        };

        response
    }
}

#[async_trait]
impl ClientRegistrationService for DefaultClientRegistrationService {
    async fn register_client(
        &self,
        request: ClientRegistrationRequest,
        software_statement: Option<String>,
    ) -> Result<ClientRegistrationResponse> {
        // Check if dynamic registration is enabled
        if !self.enable_dynamic_registration {
            return Err(AuthencError::ConfigurationError {
                message: "Dynamic client registration is not enabled".to_string(),
            });
        }

        // Validate software statement if provided or required
        let parsed_stmt = if let Some(token) = &software_statement {
            Some(self.validate_software_statement(token).await?)
        } else if self.require_software_statement {
            return Err(AuthencError::ValidationError {
                message: "Software statement is required".to_string(),
            });
        } else {
            None
        };

        // Merge software statement metadata if present (RFC 7591)
        let request = if let Some(stmt) = &parsed_stmt {
            // Serialize request to Value to allow merging
            let mut request_value =
                serde_json::to_value(&request).map_err(|e| AuthencError::SerializationError {
                    message: format!("Failed to serialize request: {}", e),
                })?;

            // Merge metadata from software statement
            if let Some(obj) = request_value.as_object_mut() {
                for (k, v) in &stmt.client_metadata {
                    obj.insert(k.clone(), v.clone());
                }
            }

            // Deserialize back to request
            serde_json::from_value(request_value).map_err(|e| AuthencError::ValidationError {
                message: format!("Failed to merge software statement: {}", e),
            })?
        } else {
            request
        };

        // Validate registration request
        self.validate_registration_request(&request)?;

        // Create OIDC client
        let client = self.request_to_client(&request);
        let client_id = client.client_id.clone();

        // Store client
        self.client_store.add(client).await?;

        // Generate registration access token
        let registration_token = self.generate_registration_access_token();

        // Store registration token
        {
            let mut tokens = self.registration_tokens.write().await;
            tokens.insert(client_id.clone(), registration_token.clone());
        }

        // Convert to response (need to get client again since it was moved)
        let client = self.client_store.get(&client_id).await?.ok_or_else(|| {
            AuthencError::ResourceNotFound {
                resource: format!("client {}", client_id),
            }
        })?;
        let response = self.client_to_response(&client, &registration_token);

        Ok(response)
    }

    async fn get_client_configuration(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<ClientRegistrationResponse> {
        // Validate registration access token
        {
            let tokens = self.registration_tokens.read().await;
            if let Some(stored_token) = tokens.get(client_id) {
                if stored_token != registration_access_token {
                    return Err(AuthencError::AuthenticationFailed);
                }
            } else {
                return Err(AuthencError::AuthenticationFailed);
            }
        }

        // Get client
        let client = self.client_store.get(client_id).await?.ok_or_else(|| {
            AuthencError::ResourceNotFound {
                resource: format!("client {}", client_id),
            }
        })?;

        // Convert to response
        let response = self.client_to_response(&client, registration_access_token);

        Ok(response)
    }

    async fn update_client_configuration(
        &self,
        client_id: &str,
        registration_access_token: &str,
        request: ClientUpdateRequest,
    ) -> Result<ClientRegistrationResponse> {
        // Validate registration access token
        {
            let tokens = self.registration_tokens.read().await;
            if let Some(stored_token) = tokens.get(client_id) {
                if stored_token != registration_access_token {
                    return Err(AuthencError::AuthenticationFailed);
                }
            } else {
                return Err(AuthencError::AuthenticationFailed);
            }
        }

        // Get existing client
        let mut client = self.client_store.get(client_id).await?.ok_or_else(|| {
            AuthencError::ResourceNotFound {
                resource: format!("client {}", client_id),
            }
        })?;
        let client_id = client.client_id.clone();

        // Update client fields
        if let Some(redirect_uris) = &request.redirect_uris {
            client.redirect_uris = redirect_uris.clone();
        }

        if let Some(client_name) = &request.client_name {
            client.name = client_name.clone();
        }

        // Update client (delete and re-add)
        self.client_store.delete(&client_id).await?;
        self.client_store.add(client).await?;

        // Get updated client for response
        let client = self.client_store.get(&client_id).await?.ok_or_else(|| {
            AuthencError::ResourceNotFound {
                resource: format!("client {}", client_id),
            }
        })?;

        // Convert to response
        let response = self.client_to_response(&client, registration_access_token);

        Ok(response)
    }

    async fn delete_client_registration(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<()> {
        // Validate registration access token
        {
            let tokens = self.registration_tokens.read().await;
            if let Some(stored_token) = tokens.get(client_id) {
                if stored_token != registration_access_token {
                    return Err(AuthencError::AuthenticationFailed);
                }
            } else {
                return Err(AuthencError::AuthenticationFailed);
            }
        }

        // Delete client
        self.client_store.delete(client_id).await?;

        // Remove registration token
        {
            let mut tokens = self.registration_tokens.write().await;
            tokens.remove(client_id);
        }

        Ok(())
    }

    async fn validate_software_statement(&self, token: &str) -> Result<SoftwareStatement> {
        validate_software_statement_token(token, self.validation_secret.as_deref())
    }
}

/// Helper function to validate software statement token
/// Separated for easier testing without instantiating the service
fn validate_software_statement_token(
    token: &str,
    validation_secret: Option<&[u8]>,
) -> Result<SoftwareStatement> {
    // If we have a validation secret, use it. Otherwise fail if validation is required.
    let key = if let Some(secret) = validation_secret {
        DecodingKey::from_secret(secret)
    } else {
        // If validation is strictly required but no key is configured, this is an error
        return Err(AuthencError::ConfigurationError {
            message: "Software statement validation is required but no key is configured"
                .to_string(),
        });
    };

    // Configure validation
    // Software statements might not have expiration, so we don't require it by default
    let mut validation = Validation::default();
    validation.required_spec_claims.remove("exp");

    let token_data = decode::<SoftwareStatement>(token, &key, &validation).map_err(|e| {
        AuthencError::ValidationError {
            message: format!("Invalid software statement: {}", e),
        }
    })?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    #[test]
    fn test_validate_software_statement_token() {
        let secret = b"test_secret";

        // Create a valid payload
        let payload = SoftwareStatement {
            software_id: Some("test_software".to_string()),
            software_version: Some("1.0".to_string()),
            client_metadata: [("client_name".to_string(), json!("Test Client"))]
                .into_iter()
                .collect(),
        };

        // Create a valid token
        let token = encode(
            &Header::default(),
            &payload,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        // Test valid token
        let result = validate_software_statement_token(&token, Some(secret));
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.software_id, Some("test_software".to_string()));

        // Test invalid signature
        let result = validate_software_statement_token(&token, Some(b"wrong_secret"));
        assert!(
            result.is_err(),
            "Expected error for invalid signature, got {:?}",
            result
        );
        match result {
            Err(AuthencError::ValidationError { message }) => {
                // The error message from jsonwebtoken depends on the error type.
                // It typically contains "InvalidSignature" or similar.
                // We just verify it failed validation.
                println!("Validation error message: {}", message);
                assert!(!message.is_empty());
            }
            _ => panic!("Expected ValidationError, got {:?}", result),
        }

        // Test missing secret configuration
        let result = validate_software_statement_token(&token, None);
        assert!(result.is_err());
        match result {
            Err(AuthencError::ConfigurationError { message }) => {
                assert!(message.contains("no key is configured"));
            }
            _ => panic!("Expected ConfigurationError"),
        }
    }
}
