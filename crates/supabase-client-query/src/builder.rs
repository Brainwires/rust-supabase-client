use std::marker::PhantomData;
use std::sync::Arc;

use serde_json::Value as JsonValue;
use sqlx::PgPool;

use supabase_client_core::Row;

use crate::delete::DeleteBuilder;
use crate::insert::InsertBuilder;
use crate::select::SelectBuilder;
use crate::sql::{ParamStore, SqlOperation, SqlParts};
use crate::table::Table;
use crate::update::UpdateBuilder;
use crate::upsert::UpsertBuilder;

/// Entry point query builder created by `client.from("table")`.
///
/// Call `.select()`, `.insert()`, `.update()`, `.delete()`, or `.upsert()` to
/// specialize into the appropriate builder type.
pub struct QueryBuilder {
    pool: Arc<PgPool>,
    schema: String,
    table: String,
}

impl QueryBuilder {
    pub fn new(pool: Arc<PgPool>, schema: String, table: String) -> Self {
        Self {
            pool,
            schema,
            table,
        }
    }

    /// Start a SELECT query.
    /// Pass column expressions like "name, country_id" or "*".
    pub fn select(self, columns: &str) -> SelectBuilder<Row> {
        let mut parts = SqlParts::new(SqlOperation::Select, &self.schema, &self.table);

        // Parse and quote column names
        if columns == "*" || columns.is_empty() {
            parts.select_columns = None; // will become SELECT *
        } else {
            let quoted = columns
                .split(',')
                .map(|c| {
                    let c = c.trim();
                    if c.contains('(') || c.contains('*') || c.contains('"') || c.contains(' ') {
                        // Already complex expression, pass through
                        c.to_string()
                    } else {
                        format!("\"{}\"", c)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            parts.select_columns = Some(quoted);
        }

        SelectBuilder {
            pool: self.pool,
            parts,
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    /// Start an INSERT query with a single row.
    pub fn insert(self, row: Row) -> InsertBuilder<Row> {
        let mut parts = SqlParts::new(SqlOperation::Insert, &self.schema, &self.table);
        let mut params = ParamStore::new();

        let mut entries: Vec<_> = row.into_inner().into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (col, val) in entries {
            let idx = params.push(json_to_sql_param(val));
            parts.set_clauses.push((col, idx));
        }

        InsertBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start an INSERT query with multiple rows.
    pub fn insert_many(self, rows: Vec<Row>) -> InsertBuilder<Row> {
        let mut parts = SqlParts::new(SqlOperation::Insert, &self.schema, &self.table);
        let mut params = ParamStore::new();

        // Determine canonical column order from the first row
        let column_order: Vec<String> = if let Some(first) = rows.first() {
            let mut cols: Vec<String> = first.columns().iter().map(|c| c.to_string()).collect();
            cols.sort();
            cols
        } else {
            Vec::new()
        };

        for row in rows {
            let inner = row.into_inner();
            let mut row_pairs = Vec::new();
            for col in &column_order {
                let val = inner.get(col).cloned().unwrap_or(serde_json::Value::Null);
                let idx = params.push(json_to_sql_param(val));
                row_pairs.push((col.clone(), idx));
            }
            parts.many_rows.push(row_pairs);
        }

        InsertBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start an UPDATE query.
    pub fn update(self, row: Row) -> UpdateBuilder<Row> {
        let mut parts = SqlParts::new(SqlOperation::Update, &self.schema, &self.table);
        let mut params = ParamStore::new();

        let mut entries: Vec<_> = row.into_inner().into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (col, val) in entries {
            let idx = params.push(json_to_sql_param(val));
            parts.set_clauses.push((col, idx));
        }

        UpdateBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start a DELETE query.
    pub fn delete(self) -> DeleteBuilder<Row> {
        let parts = SqlParts::new(SqlOperation::Delete, &self.schema, &self.table);
        DeleteBuilder {
            pool: self.pool,
            parts,
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    /// Start an UPSERT (INSERT ... ON CONFLICT DO UPDATE) query with a single row.
    pub fn upsert(self, row: Row) -> UpsertBuilder<Row> {
        let mut parts = SqlParts::new(SqlOperation::Upsert, &self.schema, &self.table);
        let mut params = ParamStore::new();

        let mut entries: Vec<_> = row.into_inner().into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (col, val) in entries {
            let idx = params.push(json_to_sql_param(val));
            parts.set_clauses.push((col, idx));
        }

        UpsertBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start an UPSERT query with multiple rows.
    pub fn upsert_many(self, rows: Vec<Row>) -> UpsertBuilder<Row> {
        let mut parts = SqlParts::new(SqlOperation::Upsert, &self.schema, &self.table);
        let mut params = ParamStore::new();

        let column_order: Vec<String> = if let Some(first) = rows.first() {
            let mut cols: Vec<String> = first.columns().iter().map(|c| c.to_string()).collect();
            cols.sort();
            cols
        } else {
            Vec::new()
        };

        for row in rows {
            let inner = row.into_inner();
            let mut row_pairs = Vec::new();
            for col in &column_order {
                let val = inner.get(col).cloned().unwrap_or(serde_json::Value::Null);
                let idx = params.push(json_to_sql_param(val));
                row_pairs.push((col.clone(), idx));
            }
            parts.many_rows.push(row_pairs);
        }

        UpsertBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }
}

/// Entry point for typed queries created by `client.from_typed::<T>()`.
pub struct TypedQueryBuilder<T: Table> {
    pool: Arc<PgPool>,
    schema: String,
    _marker: PhantomData<T>,
}

impl<T: Table> TypedQueryBuilder<T> {
    pub fn new(pool: Arc<PgPool>, schema: String) -> Self {
        Self {
            pool,
            schema,
            _marker: PhantomData,
        }
    }

    /// Start a typed SELECT query (selects all columns by default).
    pub fn select(self) -> SelectBuilder<T> {
        let parts = SqlParts::new(SqlOperation::Select, &self.schema, T::table_name());
        SelectBuilder {
            pool: self.pool,
            parts,
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    /// Start a typed SELECT with specific columns.
    pub fn select_columns(self, columns: &str) -> SelectBuilder<T> {
        let mut parts = SqlParts::new(SqlOperation::Select, &self.schema, T::table_name());
        if columns != "*" && !columns.is_empty() {
            let quoted = columns
                .split(',')
                .map(|c| {
                    let c = c.trim();
                    if c.contains('(') || c.contains('*') || c.contains('"') || c.contains(' ') {
                        c.to_string()
                    } else {
                        format!("\"{}\"", c)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            parts.select_columns = Some(quoted);
        }
        SelectBuilder {
            pool: self.pool,
            parts,
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    /// Start a typed INSERT from a struct instance.
    pub fn insert(self, value: &T) -> InsertBuilder<T> {
        let mut parts = SqlParts::new(SqlOperation::Insert, &self.schema, T::table_name());
        let mut params = ParamStore::new();

        let columns = T::insertable_columns();
        let values = value.bind_insert();

        for (col, val) in columns.iter().zip(values.into_iter()) {
            let idx = params.push(val);
            parts.set_clauses.push((col.to_string(), idx));
        }

        InsertBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start a typed UPDATE from a struct instance (updates non-PK columns).
    pub fn update(self, value: &T) -> UpdateBuilder<T> {
        let mut parts = SqlParts::new(SqlOperation::Update, &self.schema, T::table_name());
        let mut params = ParamStore::new();

        // SET clauses: all non-PK columns
        let pk_cols = T::primary_key_columns();
        let all_cols = T::column_names();
        let update_vals = value.bind_update();

        let update_cols: Vec<&&str> = all_cols
            .iter()
            .filter(|c| !pk_cols.contains(c))
            .collect();

        for (col, val) in update_cols.iter().zip(update_vals.into_iter()) {
            let idx = params.push(val);
            parts.set_clauses.push((col.to_string(), idx));
        }

        // WHERE clause: primary key match
        let pk_vals = value.bind_primary_key();
        for (col, val) in pk_cols.iter().zip(pk_vals.into_iter()) {
            let idx = params.push(val);
            parts.filters.push(crate::sql::FilterCondition::Comparison {
                column: col.to_string(),
                operator: crate::sql::FilterOperator::Eq,
                param_index: idx,
            });
        }

        UpdateBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start a typed DELETE.
    pub fn delete(self) -> DeleteBuilder<T> {
        let parts = SqlParts::new(SqlOperation::Delete, &self.schema, T::table_name());
        DeleteBuilder {
            pool: self.pool,
            parts,
            params: ParamStore::new(),
            _marker: PhantomData,
        }
    }

    /// Start a typed UPSERT from a struct instance.
    pub fn upsert(self, value: &T) -> UpsertBuilder<T> {
        let mut parts = SqlParts::new(SqlOperation::Upsert, &self.schema, T::table_name());
        let mut params = ParamStore::new();

        let pk_cols = T::primary_key_columns();
        let insertable_cols = T::insertable_columns();

        // First add PK columns
        let pk_vals = value.bind_primary_key();
        for (col, val) in pk_cols.iter().zip(pk_vals.into_iter()) {
            let idx = params.push(val);
            parts.set_clauses.push((col.to_string(), idx));
        }

        // Then add insertable columns
        let insert_vals = value.bind_insert();
        for (col, val) in insertable_cols.iter().zip(insert_vals.into_iter()) {
            let idx = params.push(val);
            parts.set_clauses.push((col.to_string(), idx));
        }

        parts.conflict_columns = pk_cols.iter().map(|c| c.to_string()).collect();

        UpsertBuilder {
            pool: self.pool,
            parts,
            params,
            _marker: PhantomData,
        }
    }
}

/// Convert a serde_json::Value into an SqlParam.
fn json_to_sql_param(value: JsonValue) -> crate::sql::SqlParam {
    match value {
        JsonValue::Null => crate::sql::SqlParam::Null,
        JsonValue::Bool(b) => crate::sql::SqlParam::Bool(b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                    crate::sql::SqlParam::I32(i as i32)
                } else {
                    crate::sql::SqlParam::I64(i)
                }
            } else if let Some(f) = n.as_f64() {
                crate::sql::SqlParam::F64(f)
            } else {
                crate::sql::SqlParam::Text(n.to_string())
            }
        }
        JsonValue::String(s) => {
            // Try to parse as UUID
            if let Ok(uuid) = uuid::Uuid::parse_str(&s) {
                crate::sql::SqlParam::Uuid(uuid)
            } else {
                crate::sql::SqlParam::Text(s)
            }
        }
        other => crate::sql::SqlParam::Json(other),
    }
}
