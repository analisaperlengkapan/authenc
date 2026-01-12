//! Batch operations for efficient bulk database operations
//!
//! Provides optimized batch insert, update, and delete operations to reduce
//! database round-trips and improve performance for bulk data operations.

use crate::error::{AuthencError, Result};
use tokio_postgres::Client;
use tracing::{debug, error};

/// Batch operation builder for efficient bulk operations
pub struct BatchOperations<'a> {
    client: &'a Client,
    batch_size: usize,
}

impl<'a> BatchOperations<'a> {
    /// Create a new batch operations builder
    pub fn new(client: &'a Client) -> Self {
        Self {
            client,
            batch_size: 1000, // Default batch size
        }
    }

    /// Set custom batch size
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Batch insert operation
    ///
    /// Inserts multiple rows in a single optimized query using PostgreSQL's
    /// VALUES clause with multiple rows.
    ///
    /// # Example SQL Generated:
    /// ```sql
    /// INSERT INTO table (col1, col2) VALUES ($1, $2), ($3, $4), ($5, $6)
    /// ```
    pub async fn batch_insert<T: BatchInsertable>(
        &self,
        table: &str,
        columns: &[&str],
        items: &[T],
    ) -> Result<u64> {
        if items.is_empty() {
            return Ok(0);
        }

        let mut total_inserted = 0u64;

        // Process in batches
        for chunk in items.chunks(self.batch_size) {
            let inserted = self.batch_insert_chunk(table, columns, chunk).await?;
            total_inserted += inserted;
        }

        debug!(
            "Batch inserted {} rows into {} in {} batch(es)",
            total_inserted,
            table,
            items.len().div_ceil(self.batch_size)
        );

        Ok(total_inserted)
    }

    /// Insert a single chunk of items
    async fn batch_insert_chunk<T: BatchInsertable>(
        &self,
        table: &str,
        columns: &[&str],
        items: &[T],
    ) -> Result<u64> {
        if items.is_empty() {
            return Ok(0);
        }

        let num_cols = columns.len();
        let num_rows = items.len();

        // Build VALUES clause: ($1, $2), ($3, $4), ...
        let mut value_placeholders = Vec::with_capacity(num_rows);
        for row_idx in 0..num_rows {
            let start_param = row_idx * num_cols + 1;
            let end_param = start_param + num_cols;
            let params: Vec<String> = (start_param..end_param)
                .map(|i| format!("${}", i))
                .collect();
            value_placeholders.push(format!("({})", params.join(", ")));
        }

        // Build complete INSERT statement
        let sql = format!(
            "INSERT INTO {} ({}) VALUES {}",
            table,
            columns.join(", "),
            value_placeholders.join(", ")
        );

        // Collect all parameters
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        for item in items {
            item.collect_params(&mut params);
        }

        // Execute batch insert
        self.client.execute(&sql, &params).await.map_err(|e| {
            error!("Batch insert failed: {}", e);
            AuthencError::database(format!("Batch insert failed: {}", e))
        })
    }

    /// Batch update operation using CASE WHEN
    ///
    /// Updates multiple rows efficiently using a single UPDATE statement with CASE expressions.
    ///
    /// # Example SQL Generated:
    /// ```sql
    /// UPDATE table SET
    ///   col1 = CASE id WHEN $1 THEN $2 WHEN $3 THEN $4 END,
    ///   col2 = CASE id WHEN $1 THEN $5 WHEN $3 THEN $6 END
    /// WHERE id IN ($1, $3)
    /// ```
    pub async fn batch_update<T: BatchUpdateable>(
        &self,
        table: &str,
        id_column: &str,
        update_columns: &[&str],
        items: &[T],
    ) -> Result<u64> {
        if items.is_empty() {
            return Ok(0);
        }

        let mut total_updated = 0u64;

        // Process in batches
        for chunk in items.chunks(self.batch_size) {
            let updated = self
                .batch_update_chunk(table, id_column, update_columns, chunk)
                .await?;
            total_updated += updated;
        }

        debug!(
            "Batch updated {} rows in {} in {} batch(es)",
            total_updated,
            table,
            items.len().div_ceil(self.batch_size)
        );

        Ok(total_updated)
    }

    /// Update a single chunk of items
    async fn batch_update_chunk<T: BatchUpdateable>(
        &self,
        table: &str,
        id_column: &str,
        update_columns: &[&str],
        items: &[T],
    ) -> Result<u64> {
        if items.is_empty() {
            return Ok(0);
        }

        // Build CASE expressions for each column
        let mut case_expressions = Vec::new();
        let mut param_idx = 1;

        for col in update_columns {
            let mut when_clauses = Vec::new();
            for _ in 0..items.len() {
                when_clauses.push(format!("WHEN ${} THEN ${}", param_idx, param_idx + 1));
                param_idx += 2;
            }
            case_expressions.push(format!(
                "{} = CASE {} {} END",
                col,
                id_column,
                when_clauses.join(" ")
            ));
        }

        // Build IN clause for WHERE
        let id_params: Vec<String> = (1..=items.len())
            .step_by(2)
            .map(|i| format!("${}", i))
            .collect();

        let sql = format!(
            "UPDATE {} SET {} WHERE {} IN ({})",
            table,
            case_expressions.join(", "),
            id_column,
            id_params.join(", ")
        );

        // Collect parameters
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        for item in items {
            item.collect_update_params(&mut params);
        }

        self.client.execute(&sql, &params).await.map_err(|e| {
            error!("Batch update failed: {}", e);
            AuthencError::database(format!("Batch update failed: {}", e))
        })
    }

    /// Batch delete operation
    ///
    /// Deletes multiple rows using IN clause.
    pub async fn batch_delete<T>(&self, table: &str, id_column: &str, ids: &[T]) -> Result<u64>
    where
        T: tokio_postgres::types::ToSql + Sync,
    {
        if ids.is_empty() {
            return Ok(0);
        }

        let mut total_deleted = 0u64;

        // Process in batches
        for chunk in ids.chunks(self.batch_size) {
            let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("${}", i)).collect();

            let sql = format!(
                "DELETE FROM {} WHERE {} IN ({})",
                table,
                id_column,
                placeholders.join(", ")
            );

            let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = chunk
                .iter()
                .map(|id| id as &(dyn tokio_postgres::types::ToSql + Sync))
                .collect();

            let deleted = self.client.execute(&sql, &params).await.map_err(|e| {
                error!("Batch delete failed: {}", e);
                AuthencError::database(format!("Batch delete failed: {}", e))
            })?;

            total_deleted += deleted;
        }

        debug!(
            "Batch deleted {} rows from {} in {} batch(es)",
            total_deleted,
            table,
            ids.len().div_ceil(self.batch_size)
        );

        Ok(total_deleted)
    }
}

/// Trait for types that can be batch inserted
pub trait BatchInsertable {
    /// Collect parameters for this item into the params vector
    fn collect_params<'a>(
        &'a self,
        params: &mut Vec<&'a (dyn tokio_postgres::types::ToSql + Sync)>,
    );
}

/// Trait for types that can be batch updated
pub trait BatchUpdateable {
    /// Collect update parameters (id, then all update values) into the params vector
    fn collect_update_params<'a>(
        &'a self,
        params: &mut Vec<&'a (dyn tokio_postgres::types::ToSql + Sync)>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_operations_creation() {
        // This is a conceptual test - requires real database connection
        // Demonstrates expected usage pattern
    }
}
