use crate::database::Database;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::models::resource::{CreateResourceRequest, Resource, UpdateResourceRequest};

/// Resource store for managing resources in the database
#[derive(Debug, Clone)]
pub struct ResourceStore {
    /// Database instance
    database: Arc<Database>,
}

impl ResourceStore {
    /// Create a new resource store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

/// Trait for resource store operations
#[async_trait]
pub trait ResourceStoreTrait: Send + Sync {
    /// Create a new resource
    async fn create_resource(
        &self,
        request: CreateResourceRequest,
        realm_id: Uuid,
        resource_server_id: Uuid,
        owner: String,
    ) -> Result<Resource, AuthencError>;

    /// Get resource by ID
    async fn get_resource(&self, id: Uuid) -> Result<Option<Resource>, AuthencError>;

    /// Get resource by name and resource server
    async fn get_resource_by_name(
        &self,
        name: &str,
        resource_server_id: Uuid,
    ) -> Result<Option<Resource>, AuthencError>;

    /// Get resources by owner
    async fn get_resources_by_owner(
        &self,
        owner: &str,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError>;

    /// Get resources by resource server
    async fn get_resources_by_server(
        &self,
        resource_server_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError>;

    /// Get resources by realm
    async fn get_resources_by_realm(
        &self,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError>;

    /// Update resource
    async fn update_resource(
        &self,
        id: Uuid,
        request: UpdateResourceRequest,
    ) -> Result<Resource, AuthencError>;

    /// Delete resource
    async fn delete_resource(&self, id: Uuid) -> Result<(), AuthencError>;

    /// Search resources by name
    async fn search_resources(
        &self,
        name: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError>;

    /// Get resource count for owner
    async fn count_resources_by_owner(&self, owner: &str) -> Result<i64, AuthencError>;
}

#[async_trait]
impl ResourceStoreTrait for ResourceStore {
    async fn create_resource(
        &self,
        request: CreateResourceRequest,
        realm_id: Uuid,
        resource_server_id: Uuid,
        owner: String,
    ) -> Result<Resource, AuthencError> {
        crate::database::operations::resources::create_resource(
            &self.database,
            request,
            owner,
            realm_id,
            resource_server_id,
        )
        .await
    }

    async fn get_resource(&self, id: Uuid) -> Result<Option<Resource>, AuthencError> {
        crate::database::operations::resources::get_resource_by_id(&self.database, id).await
    }

    async fn get_resource_by_name(
        &self,
        name: &str,
        resource_server_id: Uuid,
    ) -> Result<Option<Resource>, AuthencError> {
        crate::database::operations::resources::get_resource_by_name(
            &self.database,
            name,
            resource_server_id,
        )
        .await
    }

    async fn get_resources_by_owner(
        &self,
        owner: &str,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        crate::database::operations::resources::get_resources_by_owner(
            &self.database,
            owner,
            first,
            max,
        )
        .await
    }

    async fn get_resources_by_server(
        &self,
        resource_server_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        crate::database::operations::resources::get_resources_by_server(
            &self.database,
            resource_server_id,
            first,
            max,
        )
        .await
    }

    async fn get_resources_by_realm(
        &self,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        crate::database::operations::resources::get_resources_by_realm(
            &self.database,
            realm_id,
            first,
            max,
        )
        .await
    }

    async fn update_resource(
        &self,
        id: Uuid,
        request: UpdateResourceRequest,
    ) -> Result<Resource, AuthencError> {
        crate::database::operations::resources::update_resource(&self.database, id, request).await
    }

    async fn delete_resource(&self, id: Uuid) -> Result<(), AuthencError> {
        crate::database::operations::resources::delete_resource(&self.database, id).await
    }

    async fn search_resources(
        &self,
        name: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        crate::database::operations::resources::search_resources(
            &self.database,
            name,
            realm_id,
            first,
            max,
        )
        .await
    }

    async fn count_resources_by_owner(&self, owner: &str) -> Result<i64, AuthencError> {
        crate::database::operations::resources::count_resources_by_owner(&self.database, owner)
            .await
    }
}
