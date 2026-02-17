//! # supabase-client-query
//!
//! Query builder, filters, modifiers, and SQL/PostgREST execution for
//! the `supabase-client` crate family.
//!
//! Provides a fluent API for SELECT, INSERT, UPDATE, DELETE, UPSERT, and RPC
//! queries against Supabase, with 20+ filter methods and full modifier support.
//!
//! **Most users should depend on [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk)
//! instead** and enable the `query` feature (on by default), which re-exports
//! this crate.
//!
//! ## Features
//!
//! - `direct-sql` — Execute queries directly against PostgreSQL via sqlx
//!   instead of going through PostgREST.

pub mod sql;
pub mod table;
pub mod filter;
pub mod modifier;
pub mod backend;
pub mod postgrest;
pub mod postgrest_execute;
pub mod builder;
pub mod select;
pub mod csv_select;
pub mod geojson_select;
pub mod insert;
pub mod update;
pub mod delete;
pub mod upsert;
pub mod rpc;

#[cfg(feature = "direct-sql")]
pub mod generate;
#[cfg(feature = "direct-sql")]
pub mod execute;

pub use sql::*;
pub use table::Table;
pub use filter::{Filterable, FilterCollector};
pub use modifier::Modifiable;
pub use backend::QueryBackend;
pub use builder::{QueryBuilder, TypedQueryBuilder};
pub use select::SelectBuilder;
pub use insert::InsertBuilder;
pub use update::UpdateBuilder;
pub use delete::DeleteBuilder;
pub use upsert::UpsertBuilder;
pub use rpc::{RpcBuilder, TypedRpcBuilder};
pub use csv_select::CsvSelectBuilder;
pub use geojson_select::GeoJsonSelectBuilder;

// Re-export Phase 10 types for convenience
pub use sql::{ExplainOptions, ExplainFormat, CountOption};

use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use supabase_client_core::SupabaseClient;

/// Extension trait adding query builder methods to SupabaseClient.
pub trait SupabaseClientQueryExt {
    /// Start a dynamic (string-based) query on a table.
    fn from(&self, table: &str) -> QueryBuilder;

    /// Start a typed query on a table using the Table trait.
    fn from_typed<T: Table>(&self) -> TypedQueryBuilder<T>;

    /// Call a stored procedure/function with dynamic return.
    fn rpc(&self, function: &str, args: JsonValue) -> Result<RpcBuilder, supabase_client_core::SupabaseError>;

    /// Call a stored procedure/function with typed return.
    fn rpc_typed<T>(&self, function: &str, args: JsonValue) -> Result<TypedRpcBuilder<T>, supabase_client_core::SupabaseError>
    where
        T: DeserializeOwned + Send;
}

impl SupabaseClientQueryExt for SupabaseClient {
    fn from(&self, table: &str) -> QueryBuilder {
        let backend = make_backend(self);
        QueryBuilder::new(backend, self.schema().to_string(), table.to_string())
    }

    fn from_typed<T: Table>(&self) -> TypedQueryBuilder<T> {
        let backend = make_backend(self);
        let schema = if T::schema_name() != "public" {
            T::schema_name().to_string()
        } else {
            self.schema().to_string()
        };
        TypedQueryBuilder::new(backend, schema)
    }

    fn rpc(&self, function: &str, args: JsonValue) -> Result<RpcBuilder, supabase_client_core::SupabaseError> {
        let backend = make_backend(self);
        RpcBuilder::new(backend, self.schema().to_string(), function.to_string(), args)
    }

    fn rpc_typed<T>(&self, function: &str, args: JsonValue) -> Result<TypedRpcBuilder<T>, supabase_client_core::SupabaseError>
    where
        T: DeserializeOwned + Send,
    {
        let backend = make_backend(self);
        TypedRpcBuilder::new(backend, self.schema().to_string(), function.to_string(), args)
    }
}

/// Create a QueryBackend from a SupabaseClient.
///
/// If the `direct-sql` feature is enabled and a pool is available, uses DirectSql.
/// Otherwise, uses the REST backend (PostgREST).
fn make_backend(client: &SupabaseClient) -> QueryBackend {
    #[cfg(feature = "direct-sql")]
    {
        if let Some(pool) = client.pool_arc() {
            return QueryBackend::DirectSql { pool };
        }
    }

    QueryBackend::Rest {
        http: client.http().clone(),
        base_url: Arc::from(client.supabase_url()),
        api_key: Arc::from(client.api_key()),
        schema: client.schema().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supabase_client_core::SupabaseConfig;

    fn make_client() -> SupabaseClient {
        let config = SupabaseConfig {
            supabase_url: "http://localhost:54321".to_string(),
            supabase_key: "test-key".to_string(),
            schema: "public".to_string(),
            #[cfg(feature = "direct-sql")]
            database_url: None,
            #[cfg(feature = "direct-sql")]
            pool: Default::default(),
        };
        SupabaseClient::new(config).unwrap()
    }

    #[test]
    fn test_from_returns_query_builder() {
        let client = make_client();
        // client.from() should return a QueryBuilder which we can call select on
        let select_builder = client.from("users").select("*");
        assert_eq!(select_builder.parts.table, "users");
        assert_eq!(select_builder.parts.schema, "public");
        assert!(select_builder.parts.select_columns.is_none());
    }

    #[test]
    fn test_from_typed_returns_typed_query_builder() {
        // Minimal Table implementation for testing
        #[derive(Debug, Clone, serde::Deserialize)]
        struct MyTable {
            id: i32,
        }

        impl crate::table::Table for MyTable {
            fn table_name() -> &'static str {
                "my_table"
            }

            fn primary_key_columns() -> &'static [&'static str] {
                &["id"]
            }

            fn column_names() -> &'static [&'static str] {
                &["id"]
            }

            fn insertable_columns() -> &'static [&'static str] {
                &[]
            }

            fn field_to_column(field: &str) -> Option<&'static str> {
                match field {
                    "id" => Some("id"),
                    _ => None,
                }
            }

            fn column_to_field(column: &str) -> Option<&'static str> {
                match column {
                    "id" => Some("id"),
                    _ => None,
                }
            }

            fn bind_insert(&self) -> Vec<SqlParam> {
                vec![]
            }

            fn bind_update(&self) -> Vec<SqlParam> {
                vec![]
            }

            fn bind_primary_key(&self) -> Vec<SqlParam> {
                vec![SqlParam::I32(self.id)]
            }
        }

        let client = make_client();
        let select_builder = client.from_typed::<MyTable>().select();
        assert_eq!(select_builder.parts.table, "my_table");
        assert_eq!(select_builder.parts.schema, "public");
    }

    #[test]
    fn test_make_backend_creates_rest() {
        let client = make_client();
        let backend = make_backend(&client);
        match &backend {
            QueryBackend::Rest { base_url, schema, .. } => {
                assert_eq!(base_url.as_ref(), "http://localhost:54321");
                assert_eq!(schema, "public");
            }
            #[cfg(feature = "direct-sql")]
            _ => panic!("expected Rest backend"),
        }
    }
}
