//! Authentication Flow Store
//!
//! Provides storage operations for authentication flows, executions, and sessions.

use async_trait::async_trait;
use serde_json;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    database::{Database, operations::auth_flows as db_ops},
    error::{AuthencError, Result},
    services::auth_flow::{
        AuthenticationExecutionModel, AuthenticationFlowModel, AuthenticationSessionModel,
    },
};

/// Authentication flow store trait
#[async_trait]
pub trait AuthFlowStoreTrait: Send + Sync {
    /// Create a new authentication flow
    async fn create_flow(&self, flow: &AuthenticationFlowModel) -> Result<AuthenticationFlowModel>;

    /// Get authentication flow by ID
    async fn get_flow(&self, flow_id: Uuid) -> Result<Option<AuthenticationFlowModel>>;

    /// List authentication flows for a realm
    async fn list_flows(&self, realm_id: Option<Uuid>) -> Result<Vec<AuthenticationFlowModel>>;

    /// Update authentication flow
    async fn update_flow(
        &self,
        flow_id: Uuid,
        flow: &AuthenticationFlowModel,
    ) -> Result<AuthenticationFlowModel>;

    /// Delete authentication flow
    async fn delete_flow(&self, flow_id: Uuid) -> Result<()>;

    /// Create authentication execution
    async fn create_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<AuthenticationExecutionModel>;

    /// Create authentication session
    async fn create_session(
        &self,
        session: &AuthenticationSessionModel,
    ) -> Result<AuthenticationSessionModel>;

    /// Get authentication session
    async fn get_session(&self, session_id: Uuid) -> Result<Option<AuthenticationSessionModel>>;

    /// Update authentication session
    async fn update_session(
        &self,
        session_id: Uuid,
        session: &AuthenticationSessionModel,
    ) -> Result<()>;

    /// Complete authentication session
    async fn complete_session(
        &self,
        session_id: Uuid,
        success: bool,
        error_message: Option<String>,
    ) -> Result<()>;

    /// Clean up expired authentication sessions
    async fn cleanup_expired_sessions(&self) -> Result<i64>;
}

/// PostgreSQL implementation of authentication flow store
pub struct AuthFlowStore {
    database: Arc<Database>,
}

impl AuthFlowStore {
    /// Create new authentication flow store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }
}

#[async_trait]
impl AuthFlowStoreTrait for AuthFlowStore {
    async fn create_flow(&self, flow: &AuthenticationFlowModel) -> Result<AuthenticationFlowModel> {
        let flow_value = serde_json::to_value(flow)
            .map_err(|e| AuthencError::validation(format!("Invalid flow data: {}", e)))?;
        db_ops::create_flow(&self.database, &flow_value).await?;
        Ok(flow.clone())
    }

    async fn get_flow(&self, flow_id: Uuid) -> Result<Option<AuthenticationFlowModel>> {
        let flow_data = db_ops::get_flow(&self.database, flow_id).await?;
        if let Some(data) = flow_data {
            let flow: AuthenticationFlowModel = serde_json::from_value(data)
                .map_err(|e| AuthencError::validation(format!("Invalid flow data: {}", e)))?;
            Ok(Some(flow))
        } else {
            Ok(None)
        }
    }

    async fn list_flows(&self, realm_id: Option<Uuid>) -> Result<Vec<AuthenticationFlowModel>> {
        let flows_data = db_ops::list_flows(&self.database, realm_id).await?;
        let mut flows = Vec::new();
        for data in flows_data {
            let flow: AuthenticationFlowModel = serde_json::from_value(data)
                .map_err(|e| AuthencError::validation(format!("Invalid flow data: {}", e)))?;
            flows.push(flow);
        }
        Ok(flows)
    }

    async fn update_flow(
        &self,
        flow_id: Uuid,
        flow: &AuthenticationFlowModel,
    ) -> Result<AuthenticationFlowModel> {
        let flow_value = serde_json::to_value(flow)
            .map_err(|e| AuthencError::validation(format!("Invalid flow data: {}", e)))?;
        let updated_data = db_ops::update_flow(&self.database, flow_id, &flow_value).await?;
        let updated_flow: AuthenticationFlowModel = serde_json::from_value(updated_data)
            .map_err(|e| AuthencError::validation(format!("Invalid flow data: {}", e)))?;
        Ok(updated_flow)
    }

    async fn delete_flow(&self, flow_id: Uuid) -> Result<()> {
        db_ops::delete_flow(&self.database, flow_id).await
    }

    async fn create_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<AuthenticationExecutionModel> {
        let execution_value = serde_json::to_value(execution)
            .map_err(|e| AuthencError::validation(format!("Invalid execution data: {}", e)))?;
        db_ops::create_execution(&self.database, &execution_value).await?;
        Ok(execution.clone())
    }

    async fn create_session(
        &self,
        session: &AuthenticationSessionModel,
    ) -> Result<AuthenticationSessionModel> {
        let session_value = serde_json::to_value(session)
            .map_err(|e| AuthencError::validation(format!("Invalid session data: {}", e)))?;
        db_ops::create_session(&self.database, &session_value).await?;
        Ok(session.clone())
    }

    async fn get_session(&self, session_id: Uuid) -> Result<Option<AuthenticationSessionModel>> {
        let session_data = db_ops::get_session(&self.database, session_id).await?;
        if let Some(data) = session_data {
            let session: AuthenticationSessionModel = serde_json::from_value(data)
                .map_err(|e| AuthencError::validation(format!("Invalid session data: {}", e)))?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn update_session(
        &self,
        session_id: Uuid,
        session: &AuthenticationSessionModel,
    ) -> Result<()> {
        let session_value = serde_json::to_value(session)
            .map_err(|e| AuthencError::validation(format!("Invalid session data: {}", e)))?;
        db_ops::update_session(&self.database, session_id, &session_value).await
    }

    async fn complete_session(
        &self,
        session_id: Uuid,
        success: bool,
        error_message: Option<String>,
    ) -> Result<()> {
        db_ops::complete_session(&self.database, session_id, success, error_message).await
    }

    async fn cleanup_expired_sessions(&self) -> Result<i64> {
        db_ops::cleanup_expired_sessions(&self.database).await
    }
}
