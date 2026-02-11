pub mod sql;
pub mod table;
pub mod filter;
pub mod modifier;
pub mod backend;
pub mod postgrest;
pub mod postgrest_execute;
pub mod builder;
pub mod select;
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

// Re-export Phase 10 types for convenience
pub use sql::{ExplainOptions, ExplainFormat};

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
