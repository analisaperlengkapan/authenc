use async_trait::async_trait;
use chrono::Utc;
use serde_json;
use std::sync::Arc;
use uuid::Uuid;

use crate::database::Database;
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
        let resource_value = serde_json::to_value(&request)
            .map_err(|e| AuthencError::validation(format!("Invalid resource data: {}", e)))?;
        crate::database::operations::resources::create_resource(&self.database, &resource_value)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))?;

        // For now, return a dummy resource since this is a stub
        Ok(Resource {
            id: Uuid::new_v4(),
            name: request.name,
            display_name: request.display_name,
            uris: request.uris.unwrap_or_default(),
            icon_uri: request.icon_uri,
            resource_type: request.resource_type,
            owner,
            enabled: true,
            realm_id,
            resource_server_id,
            scopes: request.scopes.unwrap_or_default(),
            attributes: std::collections::HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    async fn get_resource(&self, id: Uuid) -> Result<Option<Resource>, AuthencError> {
        // Stub implementation - return None
        Ok(None)
    }

    async fn get_resource_by_name(
        &self,
        _name: &str,
        _resource_server_id: Uuid,
    ) -> Result<Option<Resource>, AuthencError> {
        // Stub implementation - return None
        Ok(None)
    }

    async fn get_resources_by_owner(
        &self,
        _owner: &str,
        _first: Option<i32>,
        _max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        // Stub implementation - return empty vec
        Ok(Vec::new())
    }

    async fn get_resources_by_server(
        &self,
        _resource_server_id: Uuid,
        _first: Option<i32>,
        _max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        // Stub implementation - return empty vec
        Ok(Vec::new())
    }

    async fn get_resources_by_realm(
        &self,
        _realm_id: Uuid,
        _first: Option<i32>,
        _max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        // Stub implementation - return empty vec
        Ok(Vec::new())
    }

    async fn update_resource(
        &self,
        _id: Uuid,
        _request: UpdateResourceRequest,
    ) -> Result<Resource, AuthencError> {
        // Stub implementation - return error
        Err(AuthencError::resource_not_found("Resource not found"))
    }

    async fn delete_resource(&self, _id: Uuid) -> Result<(), AuthencError> {
        // Stub implementation - do nothing
        Ok(())
    }

    async fn search_resources(
        &self,
        _name: &str,
        _realm_id: Uuid,
        _first: Option<i32>,
        _max: Option<i32>,
    ) -> Result<Vec<Resource>, AuthencError> {
        // Stub implementation - return empty vec
        Ok(Vec::new())
    }

    async fn count_resources_by_owner(&self, _owner: &str) -> Result<i64, AuthencError> {
        // Stub implementation - return 0
        Ok(0)
    }
}
