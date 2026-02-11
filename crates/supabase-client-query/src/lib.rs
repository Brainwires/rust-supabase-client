pub mod sql;
pub mod table;
pub mod filter;
pub mod modifier;
pub mod generate;
pub mod execute;
pub mod builder;
pub mod select;
pub mod insert;
pub mod update;
pub mod delete;
pub mod upsert;
pub mod rpc;

pub use sql::*;
pub use table::Table;
pub use filter::{Filterable, FilterCollector};
pub use modifier::Modifiable;
pub use builder::{QueryBuilder, TypedQueryBuilder};
pub use select::SelectBuilder;
pub use insert::InsertBuilder;
pub use update::UpdateBuilder;
pub use delete::DeleteBuilder;
pub use upsert::UpsertBuilder;
pub use rpc::{RpcBuilder, TypedRpcBuilder};

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
        T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>;
}

impl SupabaseClientQueryExt for SupabaseClient {
    fn from(&self, table: &str) -> QueryBuilder {
        QueryBuilder::new(self.pool_arc(), self.schema().to_string(), table.to_string())
    }

    fn from_typed<T: Table>(&self) -> TypedQueryBuilder<T> {
        let schema = if T::schema_name() != "public" {
            T::schema_name().to_string()
        } else {
            self.schema().to_string()
        };
        TypedQueryBuilder::new(self.pool_arc(), schema)
    }

    fn rpc(&self, function: &str, args: JsonValue) -> Result<RpcBuilder, supabase_client_core::SupabaseError> {
        RpcBuilder::new(self.pool_arc(), self.schema().to_string(), function.to_string(), args)
    }

    fn rpc_typed<T>(&self, function: &str, args: JsonValue) -> Result<TypedRpcBuilder<T>, supabase_client_core::SupabaseError>
    where
        T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
    {
        TypedRpcBuilder::new(self.pool_arc(), self.schema().to_string(), function.to_string(), args)
    }
}
