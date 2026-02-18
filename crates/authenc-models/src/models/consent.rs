//! User Consent Management Models
//!
//! This module provides data structures for managing user consents
//! in compliance with GDPR and other privacy regulations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User Consent Model
/// Represents a user's consent for a client application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConsent {
    /// Unique identifier for the consent record
    pub id: Uuid,
    /// User ID who granted the consent
    pub user_id: Uuid,
    /// Client ID that received the consent
    pub client_id: String,
    /// Scopes that were consented to
    pub scopes: Vec<String>,
    /// When the consent was granted
    pub granted_at: DateTime<Utc>,
    /// When the consent expires (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Additional consent metadata
    pub metadata: serde_json::Value,
}

/// Consent Grant Request
/// Request structure for granting consent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentGrantRequest {
    /// Client ID requesting consent
    pub client_id: String,
    /// Scopes being requested
    pub scopes: Vec<String>,
    /// Consent duration in seconds (optional)
    pub expires_in: Option<i64>,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Consent Revocation Request
/// Request structure for revoking consent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRevocationRequest {
    /// Client ID to revoke consent for
    pub client_id: String,
    /// Specific scopes to revoke (optional, revokes all if not specified)
    pub scopes: Option<Vec<String>>,
}

/// Consent Response for API
/// Response structure for consent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentResponse {
    /// Client ID that has consent
    pub client_id: String,
    /// Client name (if available)
    pub client_name: Option<String>,
    /// Granted scopes
    pub scopes: Vec<String>,
    /// When consent was granted
    pub granted_at: DateTime<Utc>,
    /// When consent expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Consent Scope Information
/// Information about a specific scope in a consent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentScopeInfo {
    /// Scope name
    pub name: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Whether this scope is required
    pub required: bool,
}

/// Consent Context
/// Context information for consent requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentContext {
    /// Client information
    pub client_id: String,
    /// Human-readable client name
    pub client_name: Option<String>,
    /// Human-readable client description
    pub client_description: Option<String>,
    /// Requested scopes with descriptions
    pub scopes: Vec<ConsentScopeInfo>,
    /// Additional context information
    pub metadata: Option<serde_json::Value>,
}
