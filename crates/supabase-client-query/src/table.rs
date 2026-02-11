use crate::sql::SqlParam;

/// Trait for typed table mapping. Implemented by `#[derive(Table)]` or manually.
///
/// Provides metadata about the table structure and methods for binding values
/// to SQL parameters for insert/update/primary-key operations.
#[cfg(feature = "direct-sql")]
pub trait Table: Sized + Send + Unpin + serde::de::DeserializeOwned + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> {
    /// The database table name (e.g. "cities").
    fn table_name() -> &'static str;

    /// The schema name (defaults to "public").
    fn schema_name() -> &'static str {
        "public"
    }

    /// Primary key column names.
    fn primary_key_columns() -> &'static [&'static str];

    /// All column names (including primary key).
    fn column_names() -> &'static [&'static str];

    /// Columns that can be inserted (excludes auto-generated columns).
    fn insertable_columns() -> &'static [&'static str];

    /// Map a Rust field name to its database column name.
    fn field_to_column(field: &str) -> Option<&'static str>;

    /// Map a database column name to its Rust field name.
    fn column_to_field(column: &str) -> Option<&'static str>;

    /// Extract insert values as SqlParam in the order of `insertable_columns()`.
    fn bind_insert(&self) -> Vec<SqlParam>;

    /// Extract all non-primary-key values as SqlParam for UPDATE SET clauses.
    fn bind_update(&self) -> Vec<SqlParam>;

    /// Extract primary key values as SqlParam.
    fn bind_primary_key(&self) -> Vec<SqlParam>;
}

/// Trait for typed table mapping (REST-only mode, no sqlx::FromRow required).
#[cfg(not(feature = "direct-sql"))]
pub trait Table: Sized + Send + serde::de::DeserializeOwned {
    /// The database table name (e.g. "cities").
    fn table_name() -> &'static str;

    /// The schema name (defaults to "public").
    fn schema_name() -> &'static str {
        "public"
    }

    /// Primary key column names.
    fn primary_key_columns() -> &'static [&'static str];

    /// All column names (including primary key).
    fn column_names() -> &'static [&'static str];

    /// Columns that can be inserted (excludes auto-generated columns).
    fn insertable_columns() -> &'static [&'static str];

    /// Map a Rust field name to its database column name.
    fn field_to_column(field: &str) -> Option<&'static str>;

    /// Map a database column name to its Rust field name.
    fn column_to_field(column: &str) -> Option<&'static str>;

    /// Extract insert values as SqlParam in the order of `insertable_columns()`.
    fn bind_insert(&self) -> Vec<SqlParam>;

    /// Extract all non-primary-key values as SqlParam for UPDATE SET clauses.
    fn bind_update(&self) -> Vec<SqlParam>;

    /// Extract primary key values as SqlParam.
    fn bind_primary_key(&self) -> Vec<SqlParam>;
}
