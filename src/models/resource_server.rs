use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// Resource server entity for managing resources and scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServer {
    /// Unique identifier for the resource server
    pub id: Uuid,
    /// Client ID associated with this resource server
    pub client_id: String,
    /// Name of the resource server
    pub name: Option<String>,
    /// Description of the resource server
    pub description: Option<String>,
    /// Whether the resource server is enabled
    pub enabled: bool,
    /// ID of the realm this resource server belongs to
    pub realm_id: Uuid,
    /// Policy enforcement mode
    pub policy_enforcement_mode: PolicyEnforcementMode,
    /// Decision strategy for policies
    pub decision_strategy: DecisionStrategy,
    /// Allow remote resource management
    pub allow_remote_resource_management: bool,
    /// Timestamp when the resource server was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the resource server was last updated
    pub updated_at: DateTime<Utc>,
}

/// Policy enforcement modes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum PolicyEnforcementMode {
    /// Enforce policies
    #[default]
    Enforcing,
    /// Permit all requests
    Permissive,
    /// Deny all requests
    Disabled,
}

impl PolicyEnforcementMode {
    /// Convert to string representation
    pub fn as_str(&self) -> &str {
        match self {
            PolicyEnforcementMode::Enforcing => "enforcing",
            PolicyEnforcementMode::Permissive => "permissive",
            PolicyEnforcementMode::Disabled => "disabled",
        }
    }
}

impl std::str::FromStr for PolicyEnforcementMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "enforcing" => Ok(PolicyEnforcementMode::Enforcing),
            "permissive" => Ok(PolicyEnforcementMode::Permissive),
            "disabled" => Ok(PolicyEnforcementMode::Disabled),
            _ => Err(format!("Unknown policy enforcement mode: {}", s)),
        }
    }
}

/// Decision strategies for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum DecisionStrategy {
    /// Unanimous decision (all policies must permit)
    #[default]
    Unanimous,
    /// Affirmative decision (at least one policy must permit)
    Affirmative,
    /// Consensus decision (majority of policies must permit)
    Consensus,
}

impl DecisionStrategy {
    /// Convert to string representation
    pub fn as_str(&self) -> &str {
        match self {
            DecisionStrategy::Unanimous => "unanimous",
            DecisionStrategy::Affirmative => "affirmative",
            DecisionStrategy::Consensus => "consensus",
        }
    }
}

impl std::str::FromStr for DecisionStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unanimous" => Ok(DecisionStrategy::Unanimous),
            "affirmative" => Ok(DecisionStrategy::Affirmative),
            "consensus" => Ok(DecisionStrategy::Consensus),
            _ => Err(format!("Unknown decision strategy: {}", s)),
        }
    }
}

/// Resource server creation request
#[derive(Debug, Deserialize)]
pub struct CreateResourceServerRequest {
    /// Client ID associated with this resource server
    pub client_id: String,
    /// Name of the resource server
    pub name: Option<String>,
    /// Description of the resource server
    pub description: Option<String>,
    /// Policy enforcement mode
    pub policy_enforcement_mode: Option<PolicyEnforcementMode>,
    /// Decision strategy for policies
    pub decision_strategy: Option<DecisionStrategy>,
    /// Allow remote resource management
    pub allow_remote_resource_management: Option<bool>,
}

/// Resource server update request
#[derive(Debug, Deserialize)]
pub struct UpdateResourceServerRequest {
    /// New name for the resource server
    pub name: Option<String>,
    /// New description for the resource server
    pub description: Option<String>,
    /// New policy enforcement mode
    pub policy_enforcement_mode: Option<PolicyEnforcementMode>,
    /// New decision strategy
    pub decision_strategy: Option<DecisionStrategy>,
    /// New remote resource management setting
    pub allow_remote_resource_management: Option<bool>,
}

/// Resource server response
#[derive(Debug, Serialize)]
pub struct ResourceServerResponse {
    /// Unique identifier for the resource server
    pub id: Uuid,
    /// Client ID associated with this resource server
    pub client_id: String,
    /// Name of the resource server
    pub name: Option<String>,
    /// Description of the resource server
    pub description: Option<String>,
    /// Whether the resource server is enabled
    pub enabled: bool,
    /// ID of the realm this resource server belongs to
    pub realm_id: Uuid,
    /// Policy enforcement mode
    pub policy_enforcement_mode: PolicyEnforcementMode,
    /// Decision strategy for policies
    pub decision_strategy: DecisionStrategy,
    /// Allow remote resource management
    pub allow_remote_resource_management: bool,
    /// Timestamp when the resource server was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the resource server was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<ResourceServer> for ResourceServerResponse {
    fn from(server: ResourceServer) -> Self {
        Self {
            id: server.id,
            client_id: server.client_id,
            name: server.name,
            description: server.description,
            enabled: server.enabled,
            realm_id: server.realm_id,
            policy_enforcement_mode: server.policy_enforcement_mode,
            decision_strategy: server.decision_strategy,
            allow_remote_resource_management: server.allow_remote_resource_management,
            created_at: server.created_at,
            updated_at: server.updated_at,
        }
    }
}

impl ResourceServer {
    /// Create a new resource server
    pub fn new(client_id: String, realm_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            client_id,
            name: None,
            description: None,
            enabled: true,
            realm_id,
            policy_enforcement_mode: PolicyEnforcementMode::default(),
            decision_strategy: DecisionStrategy::default(),
            allow_remote_resource_management: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update resource server fields
    pub fn update(&mut self, request: UpdateResourceServerRequest) {
        if let Some(name) = request.name {
            self.name = Some(name);
        }
        if let Some(description) = request.description {
            self.description = Some(description);
        }
        if let Some(policy_enforcement_mode) = request.policy_enforcement_mode {
            self.policy_enforcement_mode = policy_enforcement_mode;
        }
        if let Some(decision_strategy) = request.decision_strategy {
            self.decision_strategy = decision_strategy;
        }
        if let Some(allow_remote_resource_management) = request.allow_remote_resource_management {
            self.allow_remote_resource_management = allow_remote_resource_management;
        }
        self.updated_at = Utc::now();
    }

    /// Check if resource server is active
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Disable the resource server
    pub fn disable(&mut self) {
        self.enabled = false;
        self.updated_at = Utc::now();
    }

    /// Enable the resource server
    pub fn enable(&mut self) {
        self.enabled = true;
        self.updated_at = Utc::now();
    }
}
