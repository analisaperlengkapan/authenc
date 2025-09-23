use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Permission ticket for resource sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTicket {
    /// Unique identifier for the permission ticket
    pub id: Uuid,
    /// ID of the resource this ticket applies to
    pub resource_id: Uuid,
    /// ID of the scope this ticket applies to
    pub scope_id: Uuid,
    /// ID of the user who owns the resource (resource owner)
    pub owner: String,
    /// ID of the user who is requesting/granted permission
    pub requester: String,
    /// Whether this permission is granted
    pub granted: bool,
    /// Timestamp when the permission was granted
    pub granted_timestamp: Option<DateTime<Utc>>,
    /// ID of the realm this ticket belongs to
    pub realm_id: Uuid,
    /// ID of the resource server this ticket belongs to
    pub resource_server_id: Uuid,
    /// Timestamp when the ticket was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the ticket was last updated
    pub updated_at: DateTime<Utc>,
}

/// Permission ticket creation request
#[derive(Debug, Deserialize)]
pub struct CreatePermissionTicketRequest {
    /// ID of the resource this ticket applies to
    pub resource_id: Uuid,
    /// ID of the scope this ticket applies to
    pub scope_id: Uuid,
    /// ID of the user who is requesting permission
    pub requester: String,
}

/// Permission ticket response
#[derive(Debug, Serialize)]
pub struct PermissionTicketResponse {
    /// Unique identifier for the permission ticket
    pub id: Uuid,
    /// ID of the resource this ticket applies to
    pub resource_id: Uuid,
    /// ID of the scope this ticket applies to
    pub scope_id: Uuid,
    /// ID of the user who owns the resource (resource owner)
    pub owner: String,
    /// ID of the user who is requesting/granted permission
    pub requester: String,
    /// Whether this permission is granted
    pub granted: bool,
    /// Timestamp when the permission was granted
    pub granted_timestamp: Option<DateTime<Utc>>,
    /// ID of the realm this ticket belongs to
    pub realm_id: Uuid,
    /// ID of the resource server this ticket belongs to
    pub resource_server_id: Uuid,
    /// Timestamp when the ticket was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the ticket was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<PermissionTicket> for PermissionTicketResponse {
    fn from(ticket: PermissionTicket) -> Self {
        Self {
            id: ticket.id,
            resource_id: ticket.resource_id,
            scope_id: ticket.scope_id,
            owner: ticket.owner,
            requester: ticket.requester,
            granted: ticket.granted,
            granted_timestamp: ticket.granted_timestamp,
            realm_id: ticket.realm_id,
            resource_server_id: ticket.resource_server_id,
            created_at: ticket.created_at,
            updated_at: ticket.updated_at,
        }
    }
}

impl PermissionTicket {
    /// Create a new permission ticket
    pub fn new(
        resource_id: Uuid,
        scope_id: Uuid,
        owner: String,
        requester: String,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            resource_id,
            scope_id,
            owner,
            requester,
            granted: false,
            granted_timestamp: None,
            realm_id,
            resource_server_id,
            created_at: now,
            updated_at: now,
        }
    }

    /// Grant the permission
    pub fn grant(&mut self) {
        self.granted = true;
        self.granted_timestamp = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Revoke the permission
    pub fn revoke(&mut self) {
        self.granted = false;
        self.granted_timestamp = None;
        self.updated_at = Utc::now();
    }

    /// Check if permission is granted
    pub fn is_granted(&self) -> bool {
        self.granted
    }
}

/// Permission ticket filter options for querying
#[derive(Debug, Clone)]
pub enum PermissionTicketFilter {
    /// Filter by owner
    Owner(String),
    /// Filter by requester
    Requester(String),
    /// Filter by resource ID
    ResourceId(Uuid),
    /// Filter by granted status
    Granted(bool),
    /// Filter by resource server ID
    ResourceServerId(Uuid),
}
