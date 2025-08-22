use crate::models::audit_log::AuditLog;
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait AuditLogStore: Send + Sync {
    async fn add_log(&self, log: &AuditLog) -> Result<()>;
    async fn all(&self) -> Result<Vec<AuditLog>>;
}
