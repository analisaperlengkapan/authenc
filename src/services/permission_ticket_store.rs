use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::database::Database;
use crate::error::AuthencError;
use crate::models::permission_ticket::{
    CreatePermissionTicketRequest, PermissionTicket, PermissionTicketFilter,
};

/// Permission ticket store for managing permission tickets in the database
#[derive(Debug, Clone)]
pub struct PermissionTicketStore {
    /// Database instance
    database: Arc<Database>,
}

impl PermissionTicketStore {
    /// Create a new permission ticket store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

/// Trait for permission ticket store operations
#[async_trait]
pub trait PermissionTicketStoreTrait: Send + Sync {
    /// Create a new permission ticket
    async fn create_ticket(
        &self,
        request: CreatePermissionTicketRequest,
        owner: String,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<PermissionTicket, AuthencError>;

    /// Get permission ticket by ID
    async fn get_ticket(&self, id: Uuid) -> Result<Option<PermissionTicket>, AuthencError>;

    /// Get permission tickets with filters
    async fn get_tickets(
        &self,
        filters: Vec<PermissionTicketFilter>,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<PermissionTicket>, AuthencError>;

    /// Get granted resources for a user
    async fn get_granted_resources(
        &self,
        user_id: &str,
        name_filter: Option<&str>,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<uuid::Uuid>, AuthencError>;

    /// Get granted owner resources
    async fn get_granted_owner_resources(
        &self,
        owner: &str,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<uuid::Uuid>, AuthencError>;

    /// Get permission tickets for resource
    async fn get_tickets_for_resource(
        &self,
        resource_id: Uuid,
        granted: Option<bool>,
    ) -> Result<Vec<PermissionTicket>, AuthencError>;

    /// Get permission tickets for requester
    async fn get_tickets_for_requester(
        &self,
        requester: &str,
        granted: Option<bool>,
    ) -> Result<Vec<PermissionTicket>, AuthencError>;

    /// Grant permission ticket
    async fn grant_ticket(&self, id: Uuid) -> Result<PermissionTicket, AuthencError>;

    /// Revoke permission ticket
    async fn revoke_ticket(&self, id: Uuid) -> Result<PermissionTicket, AuthencError>;

    /// Delete permission ticket
    async fn delete_ticket(&self, id: Uuid) -> Result<(), AuthencError>;

    /// Count permission tickets with filters
    async fn count_tickets(
        &self,
        filters: Vec<PermissionTicketFilter>,
    ) -> Result<i64, AuthencError>;
}

#[async_trait]
impl PermissionTicketStoreTrait for PermissionTicketStore {
    async fn create_ticket(
        &self,
        request: CreatePermissionTicketRequest,
        owner: String,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<PermissionTicket, AuthencError> {
        crate::database::operations::permission_tickets::create_permission_ticket(
            &self.database,
            request,
            owner,
            realm_id,
            resource_server_id,
        )
        .await
    }

    async fn get_ticket(&self, id: Uuid) -> Result<Option<PermissionTicket>, AuthencError> {
        crate::database::operations::permission_tickets::get_permission_ticket(&self.database, id)
            .await
    }

    async fn get_tickets(
        &self,
        filters: Vec<PermissionTicketFilter>,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<PermissionTicket>, AuthencError> {
        crate::database::operations::permission_tickets::get_permission_tickets(
            &self.database,
            filters,
            first,
            max,
        )
        .await
    }

    async fn get_granted_resources(
        &self,
        user_id: &str,
        name_filter: Option<&str>,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<uuid::Uuid>, AuthencError> {
        crate::database::operations::permission_tickets::get_granted_resources(
            &self.database,
            user_id,
            name_filter,
            first,
            max,
        )
        .await
    }

    async fn get_granted_owner_resources(
        &self,
        owner: &str,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<uuid::Uuid>, AuthencError> {
        crate::database::operations::permission_tickets::get_granted_owner_resources(
            &self.database,
            owner,
            first,
            max,
        )
        .await
    }

    async fn get_tickets_for_resource(
        &self,
        resource_id: Uuid,
        granted: Option<bool>,
    ) -> Result<Vec<PermissionTicket>, AuthencError> {
        crate::database::operations::permission_tickets::get_tickets_for_resource(
            &self.database,
            resource_id,
            granted,
        )
        .await
    }

    async fn get_tickets_for_requester(
        &self,
        requester: &str,
        granted: Option<bool>,
    ) -> Result<Vec<PermissionTicket>, AuthencError> {
        crate::database::operations::permission_tickets::get_tickets_for_requester(
            &self.database,
            requester,
            granted,
        )
        .await
    }

    async fn grant_ticket(&self, id: Uuid) -> Result<PermissionTicket, AuthencError> {
        crate::database::operations::permission_tickets::grant_permission_ticket(&self.database, id)
            .await
    }

    async fn revoke_ticket(&self, id: Uuid) -> Result<PermissionTicket, AuthencError> {
        crate::database::operations::permission_tickets::revoke_permission_ticket(
            &self.database,
            id,
        )
        .await
    }

    async fn delete_ticket(&self, id: Uuid) -> Result<(), AuthencError> {
        crate::database::operations::permission_tickets::delete_permission_ticket(
            &self.database,
            id,
        )
        .await
    }

    async fn count_tickets(
        &self,
        filters: Vec<PermissionTicketFilter>,
    ) -> Result<i64, AuthencError> {
        crate::database::operations::permission_tickets::count_permission_tickets(
            &self.database,
            filters,
        )
        .await
    }
}
