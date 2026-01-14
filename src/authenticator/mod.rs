//! Custom Authenticator Support for Authenc
//!
//! Provides extensible authentication flow execution with custom authenticators.
//! Supports username-password, OTP, conditional, and custom authentication mechanisms.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Authentication context for authenticators
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Realm identifier for the authentication
    pub realm_id: Uuid,
    /// Client identifier if applicable
    pub client_id: Option<String>,
    /// Session identifier for the authentication flow
    pub session_id: Option<Uuid>,
    /// User identifier if authenticated
    pub user_id: Option<Uuid>,
    /// Username of the authenticating user
    pub username: Option<String>,
    /// IP address of the client
    pub ip_address: String,
    /// User agent string from the client
    pub user_agent: Option<String>,
    /// Authentication data shared between authenticators
    pub auth_data: HashMap<String, JsonValue>,
    /// Flow-specific data for the authentication process
    pub flow_data: HashMap<String, JsonValue>,
}

impl AuthContext {
    /// Create a new authentication context
    pub fn new(realm_id: Uuid, ip_address: String) -> Self {
        Self {
            realm_id,
            client_id: None,
            session_id: None,
            user_id: None,
            username: None,
            ip_address,
            user_agent: None,
            auth_data: HashMap::new(),
            flow_data: HashMap::new(),
        }
    }

    /// Add client information to the context
    pub fn with_client(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    /// Add session information to the context
    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Add user information to the context
    pub fn with_user(mut self, user_id: Uuid, username: String) -> Self {
        self.user_id = Some(user_id);
        self.username = Some(username);
        self
    }

    /// Add authentication data to the context
    pub fn with_auth_data(mut self, key: String, value: JsonValue) -> Self {
        self.auth_data.insert(key, value);
        self
    }
}

/// Authentication result status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthStatus {
    /// Authentication completed successfully
    Success,
    /// Authentication failed
    Failed,
    /// Authenticator was skipped in the flow
    Skipped,
    /// Authentication was attempted but not completed
    Attempted,
    /// Additional action is required to complete authentication
    RequiresAction,
}

impl AuthStatus {
    /// Convert status to string representation
    pub fn as_str(&self) -> &str {
        match self {
            AuthStatus::Success => "SUCCESS",
            AuthStatus::Failed => "FAILED",
            AuthStatus::Skipped => "SKIPPED",
            AuthStatus::Attempted => "ATTEMPTED",
            AuthStatus::RequiresAction => "REQUIRES_ACTION",
        }
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Status of the authentication attempt
    pub status: AuthStatus,
    /// User identifier if authentication succeeded
    pub user_id: Option<Uuid>,
    /// Error message if authentication failed
    pub error_message: Option<String>,
    /// Required actions to complete authentication
    pub required_actions: Vec<String>,
    /// Updates to apply to the authentication context
    pub context_updates: HashMap<String, JsonValue>,
}

impl AuthResult {
    /// Create a successful authentication result
    pub fn success(user_id: Uuid) -> Self {
        Self {
            status: AuthStatus::Success,
            user_id: Some(user_id),
            error_message: None,
            required_actions: Vec::new(),
            context_updates: HashMap::new(),
        }
    }

    /// Create a failed authentication result
    pub fn failed(error: String) -> Self {
        Self {
            status: AuthStatus::Failed,
            user_id: None,
            error_message: Some(error),
            required_actions: Vec::new(),
            context_updates: HashMap::new(),
        }
    }

    /// Create a result requiring additional action
    pub fn requires_action(action: String) -> Self {
        Self {
            status: AuthStatus::RequiresAction,
            user_id: None,
            error_message: None,
            required_actions: vec![action],
            context_updates: HashMap::new(),
        }
    }

    /// Create a skipped authentication result
    pub fn skipped() -> Self {
        Self {
            status: AuthStatus::Skipped,
            user_id: None,
            error_message: None,
            required_actions: Vec::new(),
            context_updates: HashMap::new(),
        }
    }
}

/// Authenticator requirement level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Requirement {
    /// Authenticator must be executed successfully
    Required,
    /// Authenticator provides alternative authentication path
    Alternative,
    /// Authenticator is disabled and will not execute
    Disabled,
    /// Authenticator executes based on conditions
    Conditional,
}

impl Requirement {
    /// Convert requirement to string representation
    pub fn as_str(&self) -> &str {
        match self {
            Requirement::Required => "REQUIRED",
            Requirement::Alternative => "ALTERNATIVE",
            Requirement::Disabled => "DISABLED",
            Requirement::Conditional => "CONDITIONAL",
        }
    }

    /// Parse requirement from string
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "REQUIRED" => Requirement::Required,
            "ALTERNATIVE" => Requirement::Alternative,
            "DISABLED" => Requirement::Disabled,
            "CONDITIONAL" => Requirement::Conditional,
            _ => Requirement::Required,
        }
    }
}

impl std::str::FromStr for Requirement {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

/// Custom authenticator trait
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Get authenticator name
    fn name(&self) -> &str;

    /// Get authenticator type
    fn authenticator_type(&self) -> &str;

    /// Check if authenticator can handle the current context
    async fn can_authenticate(&self, context: &AuthContext) -> bool;

    /// Perform authentication
    async fn authenticate(&self, context: &mut AuthContext) -> Result<AuthResult, AuthError>;

    /// Validate authenticator configuration
    fn validate_config(&self, config: &JsonValue) -> Result<(), AuthError>;

    /// Get authenticator priority (lower runs first)
    fn priority(&self) -> i32 {
        100
    }
}

/// Authenticator error types
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Provided credentials are invalid
    InvalidCredentials,
    /// Authenticator configuration is invalid
    InvalidConfiguration(String),
    /// User account was not found
    UserNotFound,
    /// User account is disabled
    UserDisabled,
    /// Required data for authentication is missing
    MissingRequiredData(String),
    /// Authentication process failed
    AuthenticationFailed(String),
    /// Too many authentication attempts
    TooManyAttempts,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::UserDisabled => write!(f, "User is disabled"),
            AuthError::MissingRequiredData(msg) => write!(f, "Missing required data: {}", msg),
            AuthError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            AuthError::TooManyAttempts => write!(f, "Too many authentication attempts"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Username/Password authenticator
pub struct UsernamePasswordAuthenticator {
    name: String,
}

impl UsernamePasswordAuthenticator {
    /// Create a new username/password authenticator
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl Authenticator for UsernamePasswordAuthenticator {
    fn name(&self) -> &str {
        &self.name
    }

    fn authenticator_type(&self) -> &str {
        "username-password"
    }

    async fn can_authenticate(&self, context: &AuthContext) -> bool {
        context.auth_data.contains_key("username") && context.auth_data.contains_key("password")
    }

    async fn authenticate(&self, context: &mut AuthContext) -> Result<AuthResult, AuthError> {
        let username = context
            .auth_data
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingRequiredData("username".to_string()))?;

        let password = context
            .auth_data
            .get("password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingRequiredData("password".to_string()))?;

        // In real implementation, verify against database
        // This is a placeholder
        if username.is_empty() || password.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }

        // Simulate user ID lookup
        let user_id = Uuid::new_v4();
        context.user_id = Some(user_id);
        context.username = Some(username.to_string());

        Ok(AuthResult::success(user_id))
    }

    fn validate_config(&self, _config: &JsonValue) -> Result<(), AuthError> {
        Ok(())
    }

    fn priority(&self) -> i32 {
        10
    }
}

/// OTP (One-Time Password) authenticator
pub struct OTPAuthenticator {
    name: String,
    otp_length: usize,
}

impl OTPAuthenticator {
    /// Create a new OTP authenticator
    pub fn new(name: String, otp_length: usize) -> Self {
        Self { name, otp_length }
    }
}

#[async_trait]
impl Authenticator for OTPAuthenticator {
    fn name(&self) -> &str {
        &self.name
    }

    fn authenticator_type(&self) -> &str {
        "otp"
    }

    async fn can_authenticate(&self, context: &AuthContext) -> bool {
        context.auth_data.contains_key("otp_code")
    }

    async fn authenticate(&self, context: &mut AuthContext) -> Result<AuthResult, AuthError> {
        let otp_code = context
            .auth_data
            .get("otp_code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingRequiredData("otp_code".to_string()))?;

        if otp_code.len() != self.otp_length {
            return Err(AuthError::InvalidCredentials);
        }

        // In real implementation, verify OTP against stored secret
        // This is a placeholder
        if context.user_id.is_none() {
            return Err(AuthError::UserNotFound);
        }

        Ok(AuthResult::success(context.user_id.unwrap()))
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), AuthError> {
        if let Some(length) = config.get("otp_length")
            && !length.is_number() {
                return Err(AuthError::InvalidConfiguration(
                    "otp_length must be a number".to_string(),
                ));
            }
        Ok(())
    }

    fn priority(&self) -> i32 {
        20
    }
}

/// Conditional authenticator (executes based on conditions)
pub struct ConditionalAuthenticator {
    name: String,
    condition_type: String, // user-attribute, role, group, etc.
    condition_value: String,
}

impl ConditionalAuthenticator {
    /// Create a new conditional authenticator
    pub fn new(name: String, condition_type: String, condition_value: String) -> Self {
        Self {
            name,
            condition_type,
            condition_value,
        }
    }

    fn evaluate_condition(&self, context: &AuthContext) -> bool {
        match self.condition_type.as_str() {
            "always" => true,
            "has-user" => context.user_id.is_some(),
            "no-user" => context.user_id.is_none(),
            "client-match" => context
                .client_id
                .as_ref()
                .map(|c| c == &self.condition_value)
                .unwrap_or(false),
            _ => false,
        }
    }
}

#[async_trait]
impl Authenticator for ConditionalAuthenticator {
    fn name(&self) -> &str {
        &self.name
    }

    fn authenticator_type(&self) -> &str {
        "conditional"
    }

    async fn can_authenticate(&self, context: &AuthContext) -> bool {
        self.evaluate_condition(context)
    }

    async fn authenticate(&self, context: &mut AuthContext) -> Result<AuthResult, AuthError> {
        if self.evaluate_condition(context) {
            Ok(AuthResult::success(
                context.user_id.unwrap_or_else(Uuid::new_v4),
            ))
        } else {
            Ok(AuthResult::skipped())
        }
    }

    fn validate_config(&self, config: &JsonValue) -> Result<(), AuthError> {
        if config.get("condition_type").is_none() {
            return Err(AuthError::InvalidConfiguration(
                "condition_type is required".to_string(),
            ));
        }
        Ok(())
    }

    fn priority(&self) -> i32 {
        50
    }
}

/// Authentication flow executor
pub struct AuthFlowExecutor {
    authenticators: Arc<RwLock<Vec<Arc<dyn Authenticator>>>>,
}

impl AuthFlowExecutor {
    /// Create a new authentication flow executor
    pub fn new() -> Self {
        Self {
            authenticators: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an authenticator with the executor
    pub async fn register(&self, authenticator: Arc<dyn Authenticator>) {
        let mut auth = self.authenticators.write().await;
        auth.push(authenticator);
        auth.sort_by_key(|a| a.priority());
    }

    /// Execute authentication flow with given requirements
    pub async fn execute_flow(
        &self,
        context: &mut AuthContext,
        requirements: &[(Uuid, Requirement)],
    ) -> Result<AuthResult, AuthError> {
        let authenticators = self.authenticators.read().await;
        let mut alternative_success = false;
        let mut last_error = None;

        for (_id, requirement) in requirements {
            match requirement {
                Requirement::Disabled => continue,
                Requirement::Required => {
                    for auth in authenticators.iter() {
                        if auth.can_authenticate(context).await {
                            match auth.authenticate(context).await {
                                Ok(result) if result.status == AuthStatus::Success => {
                                    return Ok(result);
                                }
                                Err(e) => {
                                    last_error = Some(e);
                                }
                                _ => {}
                            }
                        }
                    }
                    if let Some(err) = last_error {
                        return Err(err);
                    }
                }
                Requirement::Alternative => {
                    for auth in authenticators.iter() {
                        if auth.can_authenticate(context).await
                            && let Ok(result) = auth.authenticate(context).await
                                && result.status == AuthStatus::Success {
                                    alternative_success = true;
                                    break;
                                }
                    }
                }
                Requirement::Conditional => {
                    for auth in authenticators.iter() {
                        if auth.authenticator_type() == "conditional"
                            && auth.can_authenticate(context).await
                        {
                            auth.authenticate(context).await?;
                        }
                    }
                }
            }
        }

        if alternative_success || context.user_id.is_some() {
            Ok(AuthResult::success(
                context.user_id.unwrap_or_else(Uuid::new_v4),
            ))
        } else {
            Err(AuthError::AuthenticationFailed(
                "No authenticator succeeded".to_string(),
            ))
        }
    }
}

impl Default for AuthFlowExecutor {
    fn default() -> Self {
        Self::new()
    }
}
