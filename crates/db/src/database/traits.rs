use authenc_api::error::Result;
use tokio_postgres::Row;

/// Trait for converting Postgres rows to domain models
pub trait FromPostgresRow: Sized {
    /// Convert a Postgres row to a domain model
    fn from_row(row: Row) -> Result<Self>;
}

/// Extension trait for Row to convert to model easily
pub trait RowExt {
    fn to_model<T: FromPostgresRow>(self) -> Result<T>;
}

impl RowExt for Row {
    fn to_model<T: FromPostgresRow>(self) -> Result<T> {
        T::from_row(self)
    }
}
