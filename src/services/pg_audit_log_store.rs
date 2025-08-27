impl Clone for PgAuditLogStore {
    fn clone(&self) -> Self {
        PgAuditLogStore {
            pool: self.pool.clone(),
        }
    }
}
use crate::models::audit_log::AuditLog;
use crate::services::services::audit_log_store::AuditLogStore;
use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::{Manager, Pool};
use tokio_postgres::NoTls;

pub struct PgAuditLogStore {
    pool: Pool,
}

impl PgAuditLogStore {
    pub async fn new(conn_str: &str) -> Result<Self> {
        let parsed = conn_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse connection string: {e}"))?;
        let mgr = Manager::new(parsed, NoTls);
        let pool = Pool::builder(mgr).max_size(16).build()?;
        Ok(Self { pool })
    }

    pub async fn add_log(&self, log: &AuditLog) -> Result<()> {
        let client = self.pool.get().await?;
        let ts: std::time::SystemTime = log.timestamp.into();
        client.execute(
            "INSERT INTO audit_logs (timestamp, event, user_id, client_id, status, detail) VALUES ($1, $2, $3, $4, $5, $6)",
            &[&ts, &log.event, &log.user_id, &log.client_id, &log.status, &log.detail],
        ).await?;
        Ok(())
    }

    pub async fn all(&self) -> Result<Vec<AuditLog>> {
        let client = self.pool.get().await?;
        let rows = client.query("SELECT timestamp, event, user_id, client_id, status, detail FROM audit_logs ORDER BY timestamp DESC", &[]).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let ts: std::time::SystemTime = row.get(0);
                let timestamp: chrono::DateTime<chrono::Utc> = ts.into();
                AuditLog {
                    timestamp,
                    event: row.get(1),
                    user_id: row.get(2),
                    client_id: row.get(3),
                    status: row.get(4),
                    detail: row.get(5),
                }
            })
            .collect())
    }
}

#[async_trait]
impl AuditLogStore for PgAuditLogStore {
    async fn add_log(&self, log: &AuditLog) -> Result<()> {
        self.add_log(log).await
    }

    async fn all(&self) -> Result<Vec<AuditLog>> {
        self.all().await
    }
}
