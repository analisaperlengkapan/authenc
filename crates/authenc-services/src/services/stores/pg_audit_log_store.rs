impl Clone for PgAuditLogStore {
    fn clone(&self) -> Self {
        PgAuditLogStore {
            pool: self.pool.clone(),
        }
    }
}
use authenc_models::models::audit_log::{AuditLog, AuditLogFilter};
use crate::services::stores::audit_log_store::AuditLogStore;
use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::{Manager, Pool};
use tokio_postgres::types::ToSql;
use tokio_postgres::NoTls;

/// PostgreSQL-based audit log store implementation
pub struct PgAuditLogStore {
    /// Database connection pool
    pool: Pool,
}

impl PgAuditLogStore {
    /// Create new PostgreSQL audit log store
    ///
    /// # Arguments
    /// * `conn_str` - PostgreSQL connection string
    ///
    /// # Returns
    /// * `Ok(PgAuditLogStore)` on successful connection
    /// * `Err(anyhow::Error)` if connection fails
    pub async fn new(conn_str: &str) -> Result<Self> {
        let parsed = conn_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse connection string: {e}"))?;
        let mgr = Manager::new(parsed, NoTls);
        let pool = Pool::builder(mgr).max_size(16).build()?;
        Ok(Self { pool })
    }

    /// Create new PostgreSQL audit log store with existing pool
    pub fn with_pool(pool: Pool) -> Self {
        Self { pool }
    }

    /// Add audit log entry to database
    ///
    /// # Arguments
    /// * `log` - The audit log entry to store
    ///
    /// # Returns
    /// * `Ok(())` on successful insertion
    /// * `Err(anyhow::Error)` if database operation fails
    pub async fn add_log(&self, log: &AuditLog) -> Result<()> {
        let client = self.pool.get().await?;
        let ts: std::time::SystemTime = log.timestamp.into();
        client.execute(
            "INSERT INTO audit_logs (timestamp, event, user_id, client_id, status, detail) VALUES ($1, $2, $3, $4, $5, $6)",
            &[&ts, &log.event, &log.user_id, &log.client_id, &log.status, &log.detail],
        ).await?;
        Ok(())
    }

    /// Get all audit log entries ordered by timestamp descending
    ///
    /// # Returns
    /// * `Ok(Vec<AuditLog>)` containing all audit log entries
    /// * `Err(anyhow::Error)` if database query fails
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

    /// Query audit logs with filtering and pagination
    pub async fn query(&self, filter: &AuditLogFilter) -> Result<(Vec<AuditLog>, u64)> {
        let client = self.pool.get().await?;
        let mut query_str = "SELECT timestamp, event, user_id, client_id, status, detail, count(*) OVER() as total_count FROM audit_logs".to_string();
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx = 1;

        if let Some(ref event) = filter.event {
            conditions.push(format!("event = ${}", param_idx));
            params.push(event);
            param_idx += 1;
        }
        if let Some(ref user_id) = filter.user_id {
            conditions.push(format!("user_id = ${}", param_idx));
            params.push(user_id);
            param_idx += 1;
        }
        if let Some(ref client_id) = filter.client_id {
            conditions.push(format!("client_id = ${}", param_idx));
            params.push(client_id);
            param_idx += 1;
        }
        if let Some(ref status) = filter.status {
            conditions.push(format!("status = ${}", param_idx));
            params.push(status);
            param_idx += 1;
        }

        let from_ts_val: Option<std::time::SystemTime> = if let Some(ref from) = filter.from {
             if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(from) {
                 Some(dt.with_timezone(&chrono::Utc).into())
             } else {
                 None
             }
        } else {
            None
        };

        if let Some(ref ts) = from_ts_val {
            conditions.push(format!("timestamp >= ${}", param_idx));
            params.push(ts);
            param_idx += 1;
        }

        let to_ts_val: Option<std::time::SystemTime> = if let Some(ref to) = filter.to {
             if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(to) {
                 Some(dt.with_timezone(&chrono::Utc).into())
             } else {
                 None
             }
        } else {
            None
        };

        if let Some(ref ts) = to_ts_val {
            conditions.push(format!("timestamp <= ${}", param_idx));
            params.push(ts);
            param_idx += 1;
        }

        if !conditions.is_empty() {
            query_str.push_str(" WHERE ");
            query_str.push_str(&conditions.join(" AND "));
        }

        query_str.push_str(" ORDER BY timestamp DESC");

        // LIMIT and OFFSET
        let limit_val = filter.limit.map(|l| l as i64);
        let offset_val = filter.offset.map(|o| o as i64);

        if let Some(ref limit) = limit_val {
            query_str.push_str(&format!(" LIMIT ${}", param_idx));
            params.push(limit);
            param_idx += 1;
        }

        if let Some(ref offset) = offset_val {
            query_str.push_str(&format!(" OFFSET ${}", param_idx));
            params.push(offset);
            param_idx += 1;
        }

        let rows = client.query(&query_str, &params).await?;

        let mut total_count = 0;

        let logs = rows
            .into_iter()
            .map(|row| {
                if total_count == 0 {
                    let count: i64 = row.get(6);
                    total_count = count as u64;
                }

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
            .collect();

        Ok((logs, total_count))
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

    async fn query(&self, filter: &AuditLogFilter) -> Result<(Vec<AuditLog>, u64)> {
        self.query(filter).await
    }
}
