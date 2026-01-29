#![cfg(feature = "redis-store")]

use std::sync::Arc;
use async_trait::async_trait;
use deadpool_redis::{Config, Runtime, Pool};
use anyhow::{Result, anyhow};
use uuid::Uuid;
use redis::AsyncCommands;
use chrono::{DateTime, Utc};

use crate::models::session::Session;
use crate::services::session_store::{SessionStoreTrait, CreateSessionParams, CreateOfflineTokenParams};
use crate::database::Database;
use crate::database::operations as db_ops;
use crate::error::AuthencError;

/// Redis-backed session store
pub struct RedisSessionStore {
    pool: Pool,
    db: Arc<Database>,
}

impl RedisSessionStore {
    /// Create a new Redis session store
    pub fn new(url: &str, db: Arc<Database>) -> Result<Self> {
        let cfg = Config::from_url(url);
        let pool = cfg.create_pool(Some(Runtime::Tokio1))
            .map_err(|e| anyhow!("Failed to create Redis pool: {}", e))?;

        Ok(Self { pool, db })
    }

    fn session_key(&self, id: &Uuid) -> String {
        format!("session:{}", id)
    }

    fn user_sessions_key(&self, user_id: &Uuid) -> String {
        format!("user_sessions:{}", user_id)
    }
}

#[async_trait]
impl SessionStoreTrait for RedisSessionStore {
    fn add(&self, _token: &str, _user_id: &str) -> Result<(), String> {
        Err("Legacy token storage not supported in Redis store".to_string())
    }

    fn remove(&self, _token: &str) -> Result<(), String> {
        Err("Legacy token storage not supported in Redis store".to_string())
    }

    fn get_user_id(&self, _token: &str) -> Result<Option<String>, String> {
        // Return None to indicate miss/not found
        Ok(None)
    }

    fn all_for_user(&self, _user_id: &str) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    async fn create_session(
        &self,
        params: CreateSessionParams<'_>,
    ) -> Result<Uuid, AuthencError> {
        // 1. Create in Database
        let result = db_ops::sessions::create_user_session(
            &self.db,
            params.user_id,
            params.realm_id,
            params.client_id,
            params.token,
            params.refresh_token,
            params.expires_in,
            params.ip_address,
            params.user_agent,
            params.auth_method,
            params.protocol,
        )
        .await?;

        let session_id = result["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AuthencError::internal("Invalid session ID returned"))?;

        // 2. Cache in Redis
        // Construct session object from params and result to ensure token is present
        // (Sessions retrieved from DB have empty tokens, so we must cache the one we just created with the token)
        let created_at: DateTime<Utc> = result.get("started_at")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(Utc::now);

        let expires_at: DateTime<Utc> = result.get("expires_at")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(params.expires_in));

        let last_accessed: DateTime<Utc> = result.get("last_accessed")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(Utc::now);

        let session = Session {
            id: session_id,
            user_id: params.user_id,
            realm_id: params.realm_id,
            token: params.token.to_string(),
            refresh_token: params.refresh_token.map(|s| s.to_string()),
            expires_at,
            created_at,
            last_accessed,
            ip_address: params.ip_address.map(|s| s.to_string()),
            user_agent: params.user_agent.map(|s| s.to_string()),
            revoked: false,
        };

        let _ = self.cache_session(&session).await;

        Ok(session_id)
    }

    async fn get_session(&self, id: Uuid) -> Result<Option<Session>, AuthencError> {
        // 1. Try Redis
        if let Ok(Some(session)) = self.get_session_from_redis(id).await {
            return Ok(Some(session));
        }

        // 2. Try DB
        if let Ok(Some(session)) = self.get_session_from_db(id).await {
            // Populate cache ONLY if token is present (DB sessions have empty tokens)
            if !session.token.is_empty() {
                let _ = self.cache_session(&session).await;
            }
            return Ok(Some(session));
        }

        Ok(None)
    }

    async fn store_session(&self, session: Session) -> Result<(), AuthencError> {
        // 1. Write to DB
        db_ops::sessions::store_session(&self.db, &session).await?;

        // 2. Write to Redis
        let _ = self.cache_session(&session).await;

        Ok(())
    }

    async fn delete_session(&self, id: Uuid) -> Result<(), AuthencError> {
        // 1. Delete from Redis
        let _ = self.delete_session_from_redis(id).await;

        // 2. Revoke in DB to prevent resurrection
        db_ops::sessions::revoke_session(&self.db, id, Some("Deleted via RedisSessionStore")).await?;

        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthencError> {
        // 1. Delete from Redis
        // Need to find all sessions for user.
        // I'll implementation this using the user_sessions index in Redis.
        let mut conn = self.pool.get().await
            .map_err(|e| AuthencError::internal(format!("Redis pool error: {}", e)))?;

        let user_key = self.user_sessions_key(&user_id);
        let session_ids: Vec<String> = conn.smembers(&user_key).await
            .map_err(|e| AuthencError::internal(format!("Redis error: {}", e)))?;

        for sid_str in session_ids {
            if let Ok(sid) = Uuid::parse_str(&sid_str) {
                let key = self.session_key(&sid);
                let _: () = conn.del(&key).await.unwrap_or(());
            }
        }
        let _: () = conn.del(&user_key).await.unwrap_or(());

        // 2. Revoke in DB to prevent resurrection
        db_ops::sessions::revoke_user_sessions(&self.db, user_id, Some("Deleted via RedisSessionStore")).await?;

        Ok(())
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AuthencError> {
        // 1. Try Redis Index first
        let mut sessions = Vec::new();

        let mut conn = self.pool.get().await
            .map_err(|e| AuthencError::internal(format!("Redis pool error: {}", e)))?;

        let user_key = self.user_sessions_key(&user_id);
        let session_ids: Vec<String> = conn.smembers(&user_key).await
            .map_err(|e| AuthencError::internal(format!("Redis error: {}", e)))?;

        for sid_str in session_ids {
            if let Ok(sid) = Uuid::parse_str(&sid_str) {
                if let Ok(Some(session)) = self.get_session_from_redis(sid).await {
                    sessions.push(session);
                } else {
                    // Stale or missing from cache -> try DB
                    if let Ok(Some(session)) = self.get_session_from_db(sid).await {
                        sessions.push(session);
                        // Backfill? Maybe too expensive here.
                    }
                }
            }
        }

        // If Redis was empty or we want to be sure, should we query DB for *all* sessions?
        // Querying DB for all sessions by user_id ensures consistency if Redis was flushed.
        // Let's rely on DB as the source of truth for listing if Redis returns nothing, or just merge?
        // Merging is complex.
        // Simple strategy: If Redis yields sessions, return them. If not, fallback to DB query.

        if sessions.is_empty() {
             let query = r#"
                SELECT
                    s.id, s.user_id, u.realm_id,
                    s.started_at as created_at, s.expires_at, s.last_activity_at as last_accessed,
                    s.ip_address, s.user_agent, s.terminated as revoked
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.user_id = $1 AND s.terminated = false AND s.expires_at > NOW()
                ORDER BY s.last_activity_at DESC
             "#;
             let rows: Vec<tokio_postgres::Row> = self.db.query(query, &[&user_id]).await
                .map_err(|e| AuthencError::database(format!("DB query error: {}", e)))?;

             for row in rows {
                 if let Ok(session) = self.row_to_session(&row) {
                     // Optionally populate cache ONLY if token is present
                     if !session.token.is_empty() {
                         let _ = self.cache_session(&session).await;
                     }
                     sessions.push(session);
                 }
             }
        }

        Ok(sessions)
    }

    async fn get_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError> {
        db_ops::sessions::get_session_by_token(&self.db, token).await
    }

    async fn touch_session_db(&self, session_id: Uuid) -> Result<(), AuthencError> {
        // Update DB
        db_ops::sessions::touch_session(&self.db, session_id).await?;

        // Update Redis TTL
        if let Ok(Some(mut session)) = self.get_session(session_id).await {
            // Update last accessed
            session.last_accessed = chrono::Utc::now();
            let _ = self.cache_session(&session).await;
        }

        Ok(())
    }

    async fn rotate_refresh_token(
        &self,
        session_id: Uuid,
        old_refresh_token: &str,
        new_refresh_token: &str,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<bool, AuthencError> {
        let success = db_ops::sessions::rotate_refresh_token(
            &self.db,
            session_id,
            old_refresh_token,
            new_refresh_token,
            client_ip,
            user_agent,
        )
        .await?;

        if success {
            // Invalidate Redis cache to prevent storing empty tokens (from DB retrieval)
            let _ = self.delete_session_from_redis(session_id).await;
        }

        Ok(success)
    }

    async fn revoke_session_db(
        &self,
        session_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(), AuthencError> {
        db_ops::sessions::revoke_session(&self.db, session_id, reason).await?;

        // Remove from Redis to ensure subsequent lookups fail or hit DB (where it is now revoked)
        let _ = self.delete_session_from_redis(session_id).await;

        Ok(())
    }

    async fn create_offline_token(
        &self,
        params: CreateOfflineTokenParams<'_>,
    ) -> Result<Uuid, AuthencError> {
        let result = db_ops::sessions::create_offline_token(
            &self.db,
            params.user_id,
            params.realm_id,
            params.client_id,
            params.token,
            params.scope,
            params.expires_at,
            params.data,
        )
        .await?;

        let token_id = result["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AuthencError::internal("Invalid offline token ID returned"))?;

        Ok(token_id)
    }

    async fn get_offline_token(
        &self,
        token: &str,
    ) -> Result<Option<serde_json::Value>, AuthencError> {
        db_ops::sessions::get_offline_token(&self.db, token).await
    }

    async fn touch_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::touch_offline_token(&self.db, token_id).await
    }

    async fn revoke_offline_token(&self, token_id: Uuid) -> Result<(), AuthencError> {
        db_ops::sessions::revoke_offline_token(&self.db, token_id).await
    }

    async fn cleanup_expired(&self) -> Result<i64, AuthencError> {
        db_ops::sessions::cleanup_expired_sessions(&self.db).await
    }
}

// Helpers
impl RedisSessionStore {
    async fn cache_session(&self, session: &Session) -> Result<()> {
        let mut conn = self.pool.get().await
            .map_err(|e| anyhow!("Failed to get Redis connection: {}", e))?;

        let session_json = serde_json::to_string(session)?;
        let key = self.session_key(&session.id);

        let ttl = (session.expires_at - chrono::Utc::now()).num_seconds();
        if ttl > 0 {
            let _: () = conn.set_ex(&key, &session_json, ttl as u64).await
                .map_err(|e| anyhow!("Redis set error: {}", e))?;

            let user_key = self.user_sessions_key(&session.user_id);
            let _: () = conn.sadd(&user_key, session.id.to_string()).await
                .map_err(|e| anyhow!("Redis sadd error: {}", e))?;
            let _: () = conn.expire(&user_key, 2592000).await
                .map_err(|e| anyhow!("Redis expire error: {}", e))?;
        }
        Ok(())
    }

    async fn get_session_from_redis(&self, id: Uuid) -> Result<Option<Session>> {
        let mut conn = self.pool.get().await
            .map_err(|e| anyhow!("Failed to get Redis connection: {}", e))?;

        let key = self.session_key(&id);
        let data: Option<String> = conn.get(&key).await
            .map_err(|e| anyhow!("Redis get error: {}", e))?;

        match data {
            Some(json) => {
                let session: Session = serde_json::from_str(&json)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn delete_session_from_redis(&self, id: Uuid) -> Result<()> {
        let mut conn = self.pool.get().await
            .map_err(|e| anyhow!("Failed to get Redis connection: {}", e))?;

        // Try to get user_id to clean index
        if let Ok(Some(session)) = self.get_session_from_redis(id).await {
             let user_key = self.user_sessions_key(&session.user_id);
             let _: () = conn.srem(&user_key, id.to_string()).await.unwrap_or(());
        }

        let key = self.session_key(&id);
        let _: () = conn.del(&key).await
            .map_err(|e| anyhow!("Redis del error: {}", e))?;
        Ok(())
    }

    async fn get_session_from_db(&self, id: Uuid) -> Result<Option<Session>> {
        // Filter out revoked sessions for safety and consistency
        let query = r#"
            SELECT
                s.id, s.user_id, u.realm_id,
                s.started_at as created_at, s.expires_at, s.last_activity_at as last_accessed,
                s.ip_address, s.user_agent, s.terminated as revoked
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = $1 AND s.terminated = false
        "#;
        let rows: Vec<tokio_postgres::Row> = self.db.query(query, &[&id]).await
            .map_err(|e| anyhow!("DB error: {}", e))?;

        if let Some(row) = rows.first() {
            match self.row_to_session(row) {
                Ok(session) => Ok(Some(session)),
                Err(e) => {
                    tracing::error!("Failed to map session row: {}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    fn row_to_session(&self, row: &tokio_postgres::Row) -> Result<Session> {
        // Note: DB doesn't store the cleartext token, so we return empty strings.
        // This means sessions retrieved from DB cannot be used where token is required,
        // but are valid for existence checks.
        let ip_addr: Option<std::net::IpAddr> = row.try_get("ip_address")?;

        Ok(Session {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            realm_id: row.try_get("realm_id")?,
            token: String::new(), // Token not available in DB
            refresh_token: None,  // Refresh token not available in DB
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
            last_accessed: row.try_get("last_accessed")?,
            ip_address: ip_addr.map(|ip| ip.to_string()),
            user_agent: row.try_get("user_agent")?,
            revoked: row.try_get("revoked")?,
        })
    }
}
