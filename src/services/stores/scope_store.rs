use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::database::Database;
use crate::error::AuthencError;
use crate::models::scope::{CreateScopeRequest, Scope, UpdateScopeRequest};

/// Scope store for managing scopes in the database
#[derive(Debug, Clone)]
pub struct ScopeStore {
    /// Database instance
    database: Arc<Database>,
}

impl ScopeStore {
    /// Create a new scope store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

/// Trait for scope store operations
#[async_trait]
pub trait ScopeStoreTrait: Send + Sync {
    /// Create a new scope
    async fn create_scope(
        &self,
        request: CreateScopeRequest,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<Scope, AuthencError>;

    /// Get scope by ID
    async fn get_scope(&self, id: Uuid) -> Result<Option<Scope>, AuthencError>;

    /// Get scope by name and resource server
    async fn get_scope_by_name(
        &self,
        name: &str,
        resource_server_id: Uuid,
    ) -> Result<Option<Scope>, AuthencError>;

    /// Get scopes by resource server
    async fn get_scopes_by_server(
        &self,
        resource_server_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>, AuthencError>;

    /// Get scopes by realm
    async fn get_scopes_by_realm(
        &self,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>, AuthencError>;

    /// Update scope
    async fn update_scope(
        &self,
        id: Uuid,
        request: UpdateScopeRequest,
    ) -> Result<Scope, AuthencError>;

    /// Delete scope
    async fn delete_scope(&self, id: Uuid) -> Result<(), AuthencError>;

    /// Search scopes by name
    async fn search_scopes(
        &self,
        name: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>, AuthencError>;

    /// Get scope count for resource server
    async fn count_scopes_by_server(&self, resource_server_id: Uuid) -> Result<i64, AuthencError>;
}

#[async_trait]
impl ScopeStoreTrait for ScopeStore {
    async fn create_scope(
        &self,
        request: CreateScopeRequest,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<Scope, AuthencError> {
        crate::database::operations::scopes::create_scope(
            &self.database,
            request,
            realm_id,
            resource_server_id,
        )
        .await
    }

    async fn get_scope(&self, id: Uuid) -> Result<Option<Scope>, AuthencError> {
        crate::database::operations::scopes::get_scope_by_id(&self.database, id).await
    }

    async fn get_scope_by_name(
        &self,
        name: &str,
        resource_server_id: Uuid,
    ) -> Result<Option<Scope>, AuthencError> {
        crate::database::operations::scopes::get_scope_by_name(
            &self.database,
            name,
            resource_server_id,
        )
        .await
    }

    async fn get_scopes_by_server(
        &self,
        resource_server_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>, AuthencError> {
        crate::database::operations::scopes::get_scopes_by_server(
            &self.database,
            resource_server_id,
            first,
            max,
        )
        .await
    }

    async fn get_scopes_by_realm(
        &self,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>, AuthencError> {
        crate::database::operations::scopes::get_scopes_by_realm(
            &self.database,
            realm_id,
            first,
            max,
        )
        .await
    }

    async fn update_scope(
        &self,
        id: Uuid,
        request: UpdateScopeRequest,
    ) -> Result<Scope, AuthencError> {
        crate::database::operations::scopes::update_scope(&self.database, id, request).await
    }

    async fn delete_scope(&self, id: Uuid) -> Result<(), AuthencError> {
        crate::database::operations::scopes::delete_scope(&self.database, id).await
    }

    async fn search_scopes(
        &self,
        name: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>, AuthencError> {
        crate::database::operations::scopes::search_scopes(
            &self.database,
            name,
            realm_id,
            first,
            max,
        )
        .await
    }

    async fn count_scopes_by_server(&self, resource_server_id: Uuid) -> Result<i64, AuthencError> {
        crate::database::operations::scopes::count_scopes_by_server(
            &self.database,
            resource_server_id,
        )
        .await
    }
}
