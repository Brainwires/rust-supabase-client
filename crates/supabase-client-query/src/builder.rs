use std::marker::PhantomData;

use serde_json::Value as JsonValue;

use supabase_client_core::Row;

use crate::backend::QueryBackend;
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
    backend: QueryBackend,
    schema: String,
    table: String,
}

impl QueryBuilder {
    pub fn new(backend: QueryBackend, schema: String, table: String) -> Self {
        Self {
            backend,
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
            backend: self.backend,
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
            backend: self.backend,
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
            backend: self.backend,
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
            backend: self.backend,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start a DELETE query.
    pub fn delete(self) -> DeleteBuilder<Row> {
        let parts = SqlParts::new(SqlOperation::Delete, &self.schema, &self.table);
        DeleteBuilder {
            backend: self.backend,
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
            backend: self.backend,
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
            backend: self.backend,
            parts,
            params,
            _marker: PhantomData,
        }
    }
}

/// Entry point for typed queries created by `client.from_typed::<T>()`.
pub struct TypedQueryBuilder<T: Table> {
    backend: QueryBackend,
    schema: String,
    _marker: PhantomData<T>,
}

impl<T: Table> TypedQueryBuilder<T> {
    pub fn new(backend: QueryBackend, schema: String) -> Self {
        Self {
            backend,
            schema,
            _marker: PhantomData,
        }
    }

    /// Start a typed SELECT query (selects all columns by default).
    pub fn select(self) -> SelectBuilder<T> {
        let parts = SqlParts::new(SqlOperation::Select, &self.schema, T::table_name());
        SelectBuilder {
            backend: self.backend,
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
            backend: self.backend,
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
            backend: self.backend,
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
            backend: self.backend,
            parts,
            params,
            _marker: PhantomData,
        }
    }

    /// Start a typed DELETE.
    pub fn delete(self) -> DeleteBuilder<T> {
        let parts = SqlParts::new(SqlOperation::Delete, &self.schema, T::table_name());
        DeleteBuilder {
            backend: self.backend,
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
            backend: self.backend,
            parts,
            params,
            _marker: PhantomData,
        }
    }
}

/// Convert a serde_json::Value into an SqlParam (visible for testing).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::QueryBackend;
    use crate::sql::*;
    use serde_json::json;
    use std::sync::Arc;
    use supabase_client_core::Row;

    fn make_backend() -> QueryBackend {
        QueryBackend::Rest {
            http: reqwest::Client::new(),
            base_url: Arc::from("http://localhost"),
            api_key: Arc::from("key"),
            schema: "public".to_string(),
        }
    }

    fn make_query_builder() -> QueryBuilder {
        QueryBuilder::new(make_backend(), "public".to_string(), "test".to_string())
    }

    // ---- select() ----

    #[test]
    fn test_select_star() {
        let builder = make_query_builder().select("*");
        assert!(builder.parts.select_columns.is_none());
    }

    #[test]
    fn test_select_empty() {
        let builder = make_query_builder().select("");
        assert!(builder.parts.select_columns.is_none());
    }

    #[test]
    fn test_select_named_columns() {
        let builder = make_query_builder().select("name, age");
        let cols = builder.parts.select_columns.unwrap();
        assert_eq!(cols, "\"name\", \"age\"");
    }

    #[test]
    fn test_select_count_expression_passes_through() {
        let builder = make_query_builder().select("count(*)");
        let cols = builder.parts.select_columns.unwrap();
        assert_eq!(cols, "count(*)");
    }

    #[test]
    fn test_select_quoted_column_passes_through() {
        let builder = make_query_builder().select("\"my_col\"");
        let cols = builder.parts.select_columns.unwrap();
        // Contains quote, passed through unchanged
        assert_eq!(cols, "\"my_col\"");
    }

    // ---- insert() ----

    #[test]
    fn test_insert_sets_up_clauses() {
        let mut row = Row::new();
        row.set("name", json!("Alice"));
        row.set("age", json!(30));

        let builder = make_query_builder().insert(row);
        assert_eq!(builder.parts.operation, SqlOperation::Insert);
        assert_eq!(builder.parts.set_clauses.len(), 2);
        // Sorted by column name: "age" before "name"
        assert_eq!(builder.parts.set_clauses[0].0, "age");
        assert_eq!(builder.parts.set_clauses[1].0, "name");
    }

    // ---- insert_many() ----

    #[test]
    fn test_insert_many_sets_up_many_rows() {
        let mut row1 = Row::new();
        row1.set("name", json!("Alice"));
        row1.set("age", json!(30));

        let mut row2 = Row::new();
        row2.set("name", json!("Bob"));
        row2.set("age", json!(25));

        let builder = make_query_builder().insert_many(vec![row1, row2]);
        assert_eq!(builder.parts.operation, SqlOperation::Insert);
        assert_eq!(builder.parts.many_rows.len(), 2);
        // Each row should have 2 column entries
        assert_eq!(builder.parts.many_rows[0].len(), 2);
        assert_eq!(builder.parts.many_rows[1].len(), 2);
    }

    #[test]
    fn test_insert_many_empty() {
        let builder = make_query_builder().insert_many(vec![]);
        assert!(builder.parts.many_rows.is_empty());
    }

    // ---- delete() ----

    #[test]
    fn test_delete_creates_builder() {
        let builder = make_query_builder().delete();
        assert_eq!(builder.parts.operation, SqlOperation::Delete);
        assert!(builder.params.is_empty());
        assert!(builder.parts.filters.is_empty());
    }

    // ---- update() ----

    #[test]
    fn test_update_sets_up_clauses() {
        let mut row = Row::new();
        row.set("name", json!("Updated"));

        let builder = make_query_builder().update(row);
        assert_eq!(builder.parts.operation, SqlOperation::Update);
        assert_eq!(builder.parts.set_clauses.len(), 1);
        assert_eq!(builder.parts.set_clauses[0].0, "name");
    }

    // ---- upsert() ----

    #[test]
    fn test_upsert_sets_up_clauses() {
        let mut row = Row::new();
        row.set("id", json!(1));
        row.set("name", json!("Alice"));

        let builder = make_query_builder().upsert(row);
        assert_eq!(builder.parts.operation, SqlOperation::Upsert);
        assert_eq!(builder.parts.set_clauses.len(), 2);
    }

    // ---- upsert_many() ----

    #[test]
    fn test_upsert_many_sets_up_many_rows() {
        let mut row1 = Row::new();
        row1.set("id", json!(1));
        row1.set("name", json!("Alice"));

        let mut row2 = Row::new();
        row2.set("id", json!(2));
        row2.set("name", json!("Bob"));

        let builder = make_query_builder().upsert_many(vec![row1, row2]);
        assert_eq!(builder.parts.operation, SqlOperation::Upsert);
        assert_eq!(builder.parts.many_rows.len(), 2);
    }

    // ---- json_to_sql_param (tested through insert) ----

    #[test]
    fn test_json_to_sql_param_null() {
        let param = json_to_sql_param(json!(null));
        assert!(matches!(param, SqlParam::Null));
    }

    #[test]
    fn test_json_to_sql_param_bool() {
        let param = json_to_sql_param(json!(true));
        assert!(matches!(param, SqlParam::Bool(true)));
        let param = json_to_sql_param(json!(false));
        assert!(matches!(param, SqlParam::Bool(false)));
    }

    #[test]
    fn test_json_to_sql_param_int_small() {
        // Small integer fits in i32
        let param = json_to_sql_param(json!(42));
        assert!(matches!(param, SqlParam::I32(42)));
    }

    #[test]
    fn test_json_to_sql_param_int_large() {
        // Large integer that exceeds i32 range
        let big = i64::MAX;
        let param = json_to_sql_param(json!(big));
        assert!(matches!(param, SqlParam::I64(_)));
    }

    #[test]
    fn test_json_to_sql_param_float() {
        let param = json_to_sql_param(json!(3.14));
        match param {
            SqlParam::F64(v) => assert!((v - 3.14).abs() < 0.001),
            _ => panic!("expected F64"),
        }
    }

    #[test]
    fn test_json_to_sql_param_string() {
        let param = json_to_sql_param(json!("hello world"));
        match param {
            SqlParam::Text(s) => assert_eq!(s, "hello world"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_json_to_sql_param_uuid_string() {
        let param = json_to_sql_param(json!("550e8400-e29b-41d4-a716-446655440000"));
        match param {
            SqlParam::Uuid(u) => assert_eq!(u.to_string(), "550e8400-e29b-41d4-a716-446655440000"),
            _ => panic!("expected Uuid, got {:?}", param),
        }
    }

    #[test]
    fn test_json_to_sql_param_json_object() {
        let param = json_to_sql_param(json!({"key": "value"}));
        assert!(matches!(param, SqlParam::Json(_)));
    }

    #[test]
    fn test_json_to_sql_param_json_array() {
        let param = json_to_sql_param(json!([1, 2, 3]));
        assert!(matches!(param, SqlParam::Json(_)));
    }

    // ---- TypedQueryBuilder ----

    // Minimal Table implementation for testing
    #[derive(Debug, Clone, serde::Deserialize)]
    struct TestTable {
        id: i32,
        name: String,
    }

    impl crate::table::Table for TestTable {
        fn table_name() -> &'static str {
            "test_table"
        }

        fn primary_key_columns() -> &'static [&'static str] {
            &["id"]
        }

        fn column_names() -> &'static [&'static str] {
            &["id", "name"]
        }

        fn insertable_columns() -> &'static [&'static str] {
            &["name"]
        }

        fn field_to_column(field: &str) -> Option<&'static str> {
            match field {
                "id" => Some("id"),
                "name" => Some("name"),
                _ => None,
            }
        }

        fn column_to_field(column: &str) -> Option<&'static str> {
            match column {
                "id" => Some("id"),
                "name" => Some("name"),
                _ => None,
            }
        }

        fn bind_insert(&self) -> Vec<SqlParam> {
            vec![SqlParam::Text(self.name.clone())]
        }

        fn bind_update(&self) -> Vec<SqlParam> {
            vec![SqlParam::Text(self.name.clone())]
        }

        fn bind_primary_key(&self) -> Vec<SqlParam> {
            vec![SqlParam::I32(self.id)]
        }
    }

    #[test]
    fn test_typed_query_builder_select() {
        let typed_builder: TypedQueryBuilder<TestTable> =
            TypedQueryBuilder::new(make_backend(), "public".to_string());
        let select_builder = typed_builder.select();
        assert_eq!(select_builder.parts.table, "test_table");
        assert!(select_builder.parts.select_columns.is_none());
    }

    #[test]
    fn test_typed_query_builder_select_columns() {
        let typed_builder: TypedQueryBuilder<TestTable> =
            TypedQueryBuilder::new(make_backend(), "public".to_string());
        let select_builder = typed_builder.select_columns("id, name");
        let cols = select_builder.parts.select_columns.unwrap();
        assert_eq!(cols, "\"id\", \"name\"");
    }

    #[test]
    fn test_typed_query_builder_delete() {
        let typed_builder: TypedQueryBuilder<TestTable> =
            TypedQueryBuilder::new(make_backend(), "public".to_string());
        let delete_builder = typed_builder.delete();
        assert_eq!(delete_builder.parts.operation, SqlOperation::Delete);
        assert_eq!(delete_builder.parts.table, "test_table");
    }

    #[test]
    fn test_typed_query_builder_insert() {
        let typed_builder: TypedQueryBuilder<TestTable> =
            TypedQueryBuilder::new(make_backend(), "public".to_string());
        let value = TestTable {
            id: 1,
            name: "Alice".to_string(),
        };
        let insert_builder = typed_builder.insert(&value);
        assert_eq!(insert_builder.parts.operation, SqlOperation::Insert);
        assert_eq!(insert_builder.parts.set_clauses.len(), 1);
        assert_eq!(insert_builder.parts.set_clauses[0].0, "name");
    }

    #[test]
    fn test_typed_query_builder_update() {
        let typed_builder: TypedQueryBuilder<TestTable> =
            TypedQueryBuilder::new(make_backend(), "public".to_string());
        let value = TestTable {
            id: 1,
            name: "Updated".to_string(),
        };
        let update_builder = typed_builder.update(&value);
        assert_eq!(update_builder.parts.operation, SqlOperation::Update);
        // Should have 1 set clause (name, excluding PK)
        assert_eq!(update_builder.parts.set_clauses.len(), 1);
        // Should have 1 filter for PK
        assert_eq!(update_builder.parts.filters.len(), 1);
    }

    #[test]
    fn test_typed_query_builder_upsert() {
        let typed_builder: TypedQueryBuilder<TestTable> =
            TypedQueryBuilder::new(make_backend(), "public".to_string());
        let value = TestTable {
            id: 1,
            name: "Alice".to_string(),
        };
        let upsert_builder = typed_builder.upsert(&value);
        assert_eq!(upsert_builder.parts.operation, SqlOperation::Upsert);
        // Should have PK + insertable columns in set_clauses
        assert_eq!(upsert_builder.parts.set_clauses.len(), 2);
        // Conflict columns should be set to PK
        assert_eq!(upsert_builder.parts.conflict_columns, vec!["id"]);
    }
}
