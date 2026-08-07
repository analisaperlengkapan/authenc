//! Realms.

use authenc_contract::{AppError, RealmId, Result, model::Realm, validate};

use crate::db::Db;

/// Look a realm up by its slug.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if no realm has that name, or an internal
/// error if the query fails.
pub async fn by_name(db: &Db, name: &str) -> Result<Realm> {
    let row = sqlx::query!(
        r#"
        SELECT id, name, display_name, enabled, created_at
        FROM realms
        WHERE name = $1
        "#,
        name,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up realm by name", e))?
    .ok_or(AppError::NotFound("realm"))?;

    Ok(Realm {
        id: RealmId(row.id),
        name: row.name,
        display_name: row.display_name,
        enabled: row.enabled,
        created_at: row.created_at,
    })
}

/// Create a realm.
///
/// # Errors
///
/// Returns a field error if the name is not a valid slug, [`AppError::Conflict`]
/// if the name is taken, or an internal error if the insert fails.
pub async fn create(db: &Db, name: &str, display_name: &str) -> Result<Realm> {
    validate::realm_name(name)?;

    let row = sqlx::query!(
        r#"
        INSERT INTO realms (name, display_name)
        VALUES ($1, $2)
        RETURNING id, name, display_name, enabled, created_at
        "#,
        name,
        display_name,
    )
    .fetch_one(db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_error) if db_error.is_unique_violation() => {
            AppError::conflict(format!("a realm named {name} already exists"))
        }
        _ => AppError::internal_from("creating realm", e),
    })?;

    Ok(Realm {
        id: RealmId(row.id),
        name: row.name,
        display_name: row.display_name,
        enabled: row.enabled,
        created_at: row.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_created_realm_can_be_found_again(db: Db) {
        let created = create(&db, "acme", "Acme Corp").await.unwrap();
        let found = by_name(&db, "acme").await.unwrap();

        assert_eq!(created.id, found.id);
        assert_eq!(found.display_name, "Acme Corp");
        assert!(found.enabled, "realms are enabled on creation");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_realm_is_not_found(db: Db) {
        let error = by_name(&db, "nope").await.unwrap_err();
        assert_eq!(error.status(), 404);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_duplicate_name_is_a_conflict_not_an_internal_error(db: Db) {
        create(&db, "acme", "Acme").await.unwrap();
        let error = create(&db, "acme", "Acme Again").await.unwrap_err();

        // 409, not 500: the caller can act on this, and it is not our fault.
        assert_eq!(error.status(), 409);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_invalid_slug_is_rejected_before_it_reaches_the_database(db: Db) {
        for bad in ["Acme", "acme corp", "-acme", "acme_corp"] {
            let error = create(&db, bad, "x").await.unwrap_err();
            assert_eq!(error.status(), 400, "{bad:?} should be a validation error");
        }
    }
}
