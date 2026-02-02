use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use authenc_db::database::Database;
use authenc_api::error::AuthencError;
use authenc_api::models::resource_server::{
    CreateResourceServerRequest, ResourceServer, UpdateResourceServerRequest,
};

/// Resource server store for managing resource servers in the database
#[derive(Debug, Clone)]
pub struct ResourceServerStore {
    /// Database instance
    database: Arc<Database>,
}

impl ResourceServerStore {
    /// Create a new resource server store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

/// Trait for resource server store operations
#[async_trait]
pub trait ResourceServerStoreTrait: Send + Sync {
    /// Create a new resource server
    async fn create_resource_server(
        &self,
        request: CreateResourceServerRequest,
        realm_id: Uuid,
    ) -> Result<ResourceServer, AuthencError>;

    /// Get resource server by ID
    async fn get_resource_server(&self, id: Uuid) -> Result<Option<ResourceServer>, AuthencError>;

    /// Get resource server by client ID
    async fn get_resource_server_by_client(
        &self,
        client_id: &str,
        realm_id: Uuid,
    ) -> Result<Option<ResourceServer>, AuthencError>;

    /// Get resource servers by realm
    async fn get_resource_servers_by_realm(
        &self,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<ResourceServer>, AuthencError>;

    /// Update resource server
    async fn update_resource_server(
        &self,
        id: Uuid,
        request: UpdateResourceServerRequest,
    ) -> Result<ResourceServer, AuthencError>;

    /// Delete resource server
    async fn delete_resource_server(&self, id: Uuid) -> Result<(), AuthencError>;

    /// Search resource servers by name
    async fn search_resource_servers(
        &self,
        name: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<ResourceServer>, AuthencError>;

    /// Get resource server count for realm
    async fn count_resource_servers_by_realm(&self, realm_id: Uuid) -> Result<i64, AuthencError>;
}

#[async_trait]
impl ResourceServerStoreTrait for ResourceServerStore {
    async fn create_resource_server(
        &self,
        request: CreateResourceServerRequest,
        realm_id: Uuid,
    ) -> Result<ResourceServer, AuthencError> {
        authenc_db::database::operations::resource_servers::create_resource_server(
            &self.database,
            request,
            realm_id,
        )
        .await
    }

    async fn get_resource_server(&self, id: Uuid) -> Result<Option<ResourceServer>, AuthencError> {
        authenc_db::database::operations::resource_servers::get_resource_server_by_id(&self.database, id)
            .await
    }

    async fn get_resource_server_by_client(
        &self,
        client_id: &str,
        realm_id: Uuid,
    ) -> Result<Option<ResourceServer>, AuthencError> {
        authenc_db::database::operations::resource_servers::get_resource_server_by_client(
            &self.database,
            client_id,
            realm_id,
        )
        .await
    }

    async fn get_resource_servers_by_realm(
        &self,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<ResourceServer>, AuthencError> {
        authenc_db::database::operations::resource_servers::get_resource_servers_by_realm(
            &self.database,
            realm_id,
            first,
            max,
        )
        .await
    }

    async fn update_resource_server(
        &self,
        id: Uuid,
        request: UpdateResourceServerRequest,
    ) -> Result<ResourceServer, AuthencError> {
        authenc_db::database::operations::resource_servers::update_resource_server(
            &self.database,
            id,
            request,
        )
        .await
    }

    async fn delete_resource_server(&self, id: Uuid) -> Result<(), AuthencError> {
        authenc_db::database::operations::resource_servers::delete_resource_server(&self.database, id)
            .await
    }

    async fn search_resource_servers(
        &self,
        name: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<ResourceServer>, AuthencError> {
        authenc_db::database::operations::resource_servers::search_resource_servers(
            &self.database,
            name,
            realm_id,
            first,
            max,
        )
        .await
    }

    async fn count_resource_servers_by_realm(&self, realm_id: Uuid) -> Result<i64, AuthencError> {
        authenc_db::database::operations::resource_servers::count_resource_servers_by_realm(
            &self.database,
            realm_id,
        )
        .await
    }
}
