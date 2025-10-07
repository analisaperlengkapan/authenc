use crate::database::Database;
use crate::error::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Stored access token data
#[derive(Debug, Clone)]
pub struct AccessTokenData {
    pub id: Uuid,
    pub token_hash: String,
    pub refresh_token_hash: Option<String>,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Create new access token in database
#[allow(clippy::too_many_arguments)]
pub async fn create_access_token(
    db: &Database,
    token_hash: &str,
    refresh_token_hash: Option<&str>,
    client_id: Uuid,
    user_id: Option<Uuid>,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
    refresh_expires_at: Option<DateTime<Utc>>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();

    let query = "
        INSERT INTO oauth2_access_tokens (
            id, token_hash, refresh_token_hash, client_id, user_id, scopes,
            expires_at, refresh_expires_at, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    ";

    db.execute(
        query,
        &[
            &id,
            &token_hash,
            &refresh_token_hash,
            &client_id,
            &user_id,
            &scopes,
            &expires_at,
            &refresh_expires_at,
        ],
    )
    .await?;

    Ok(id)
}

/// Get access token by hash
pub async fn get_access_token(db: &Database, token_hash: &str) -> Result<Option<AccessTokenData>> {
    let query = "
        SELECT id, token_hash, refresh_token_hash, client_id, user_id, scopes,
               expires_at, refresh_expires_at, revoked, revoked_at, created_at, last_used_at
        FROM oauth2_access_tokens
        WHERE token_hash = $1
    ";

    let rows = db.query(query, &[&token_hash]).await?;

    if rows.is_empty() {
        return Ok(None);
    }

    let row = &rows[0];
    Ok(Some(AccessTokenData {
        id: row.get(0),
        token_hash: row.get(1),
        refresh_token_hash: row.get(2),
        client_id: row.get(3),
        user_id: row.get(4),
        scopes: row.get(5),
        expires_at: row.get(6),
        refresh_expires_at: row.get(7),
        revoked: row.get(8),
        revoked_at: row.get(9),
        created_at: row.get(10),
        last_used_at: row.get(11),
    }))
}

/// Get access token by refresh token hash
pub async fn get_token_by_refresh(
    db: &Database,
    refresh_token_hash: &str,
) -> Result<Option<AccessTokenData>> {
    let query = "
        SELECT id, token_hash, refresh_token_hash, client_id, user_id, scopes,
               expires_at, refresh_expires_at, revoked, revoked_at, created_at, last_used_at
        FROM oauth2_access_tokens
        WHERE refresh_token_hash = $1
    ";

    let rows = db.query(query, &[&refresh_token_hash]).await?;

    if rows.is_empty() {
        return Ok(None);
    }

    let row = &rows[0];
    Ok(Some(AccessTokenData {
        id: row.get(0),
        token_hash: row.get(1),
        refresh_token_hash: row.get(2),
        client_id: row.get(3),
        user_id: row.get(4),
        scopes: row.get(5),
        expires_at: row.get(6),
        refresh_expires_at: row.get(7),
        revoked: row.get(8),
        revoked_at: row.get(9),
        created_at: row.get(10),
        last_used_at: row.get(11),
    }))
}

/// Update last_used_at timestamp for token
pub async fn update_token_last_used(db: &Database, token_hash: &str) -> Result<()> {
    let query = "
        UPDATE oauth2_access_tokens
        SET last_used_at = NOW()
        WHERE token_hash = $1
    ";

    db.execute(query, &[&token_hash]).await?;
    Ok(())
}

/// Revoke access token
pub async fn revoke_access_token(db: &Database, token_hash: &str) -> Result<()> {
    let query = "
        UPDATE oauth2_access_tokens
        SET revoked = true, revoked_at = NOW()
        WHERE token_hash = $1 AND revoked = false
    ";

    db.execute(query, &[&token_hash]).await?;
    Ok(())
}

/// Revoke all tokens for a user
pub async fn revoke_user_tokens(db: &Database, user_id: Uuid) -> Result<u64> {
    let query = "
        UPDATE oauth2_access_tokens
        SET revoked = true, revoked_at = NOW()
        WHERE user_id = $1 AND revoked = false
    ";

    let rows_affected = db.execute(query, &[&user_id]).await?;
    Ok(rows_affected)
}

/// Revoke all tokens for a client
pub async fn revoke_client_tokens(db: &Database, client_id: Uuid) -> Result<u64> {
    let query = "
        UPDATE oauth2_access_tokens
        SET revoked = true, revoked_at = NOW()
        WHERE client_id = $1 AND revoked = false
    ";

    let rows_affected = db.execute(query, &[&client_id]).await?;
    Ok(rows_affected)
}

/// Get active tokens for a user
pub async fn get_user_active_tokens(db: &Database, user_id: Uuid) -> Result<Vec<AccessTokenData>> {
    let query = "
        SELECT id, token_hash, refresh_token_hash, client_id, user_id, scopes,
               expires_at, refresh_expires_at, revoked, revoked_at, created_at, last_used_at
        FROM oauth2_access_tokens
        WHERE user_id = $1
          AND revoked = false
          AND expires_at > NOW()
        ORDER BY created_at DESC
    ";

    let rows = db.query(query, &[&user_id]).await?;

    let mut tokens = Vec::new();
    for row in rows {
        tokens.push(AccessTokenData {
            id: row.get(0),
            token_hash: row.get(1),
            refresh_token_hash: row.get(2),
            client_id: row.get(3),
            user_id: row.get(4),
            scopes: row.get(5),
            expires_at: row.get(6),
            refresh_expires_at: row.get(7),
            revoked: row.get(8),
            revoked_at: row.get(9),
            created_at: row.get(10),
            last_used_at: row.get(11),
        });
    }

    Ok(tokens)
}

/// Delete expired tokens (cleanup operation)
pub async fn delete_expired_tokens(db: &Database) -> Result<u64> {
    let query = "
        DELETE FROM oauth2_access_tokens
        WHERE expires_at < NOW()
          AND (refresh_expires_at IS NULL OR refresh_expires_at < NOW())
    ";

    let rows_affected = db.execute(query, &[]).await?;
    Ok(rows_affected)
}

/// Get token count statistics
pub async fn get_token_statistics(db: &Database) -> Result<TokenStatistics> {
    let query = "
        SELECT
            COUNT(*) FILTER (WHERE revoked = false AND expires_at > NOW()) as active_tokens,
            COUNT(*) FILTER (WHERE revoked = true) as revoked_tokens,
            COUNT(*) FILTER (WHERE expires_at < NOW()) as expired_tokens,
            COUNT(*) as total_tokens
        FROM oauth2_access_tokens
    ";

    let rows = db.query(query, &[]).await?;
    if rows.is_empty() {
        return Ok(TokenStatistics {
            active_tokens: 0,
            revoked_tokens: 0,
            expired_tokens: 0,
            total_tokens: 0,
        });
    }

    let row = &rows[0];
    Ok(TokenStatistics {
        active_tokens: row.get::<_, i64>(0) as u64,
        revoked_tokens: row.get::<_, i64>(1) as u64,
        expired_tokens: row.get::<_, i64>(2) as u64,
        total_tokens: row.get::<_, i64>(3) as u64,
    })
}

/// Token statistics
#[derive(Debug, Clone)]
pub struct TokenStatistics {
    pub active_tokens: u64,
    pub revoked_tokens: u64,
    pub expired_tokens: u64,
    pub total_tokens: u64,
}
