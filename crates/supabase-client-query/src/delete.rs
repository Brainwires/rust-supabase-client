use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use supabase_client_core::SupabaseResponse;

use crate::backend::QueryBackend;
use crate::filter::Filterable;
use crate::modifier::Modifiable;
use crate::sql::{FilterCondition, ParamStore, SqlParts};

/// Builder for DELETE queries. Implements Filterable and Modifiable.
/// Call `.select()` to add RETURNING clause.
pub struct DeleteBuilder<T> {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Filterable for DeleteBuilder<T> {
    fn filters_mut(&mut self) -> &mut Vec<FilterCondition> {
        &mut self.parts.filters
    }
    fn params_mut(&mut self) -> &mut ParamStore {
        &mut self.params
    }
}

impl<T> Modifiable for DeleteBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> DeleteBuilder<T> {
    /// Override the schema for this query.
    ///
    /// Generates `"schema"."table"` instead of the default schema.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Add RETURNING * clause.
    pub fn select(mut self) -> Self {
        self.parts.returning = Some("*".to_string());
        self
    }

    /// Add RETURNING with specific columns.
    pub fn select_columns(mut self, columns: &str) -> Self {
        if columns == "*" || columns.is_empty() {
            self.parts.returning = Some("*".to_string());
        } else {
            let quoted = columns
                .split(',')
                .map(|c| {
                    let c = c.trim();
                    if c.contains('(') || c.contains('*') || c.contains('"') {
                        c.to_string()
                    } else {
                        format!("\"{}\"", c)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            self.parts.returning = Some(quoted);
        }
        self
    }
}

// REST-only mode: only DeserializeOwned + Send needed
#[cfg(not(feature = "direct-sql"))]
impl<T> DeleteBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the DELETE query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let (url, headers) = match crate::postgrest::build_postgrest_delete(
            base_url, &self.parts, &self.params,
        ) {
            Ok(r) => r,
            Err(e) => return SupabaseResponse::error(
                supabase_client_core::SupabaseError::QueryBuilder(e),
            ),
        };
        crate::postgrest_execute::execute_rest(
            http, reqwest::Method::DELETE, &url, headers, None, api_key, schema, &self.parts,
        ).await
    }
}

// Direct-SQL mode: additional FromRow + Unpin bounds
#[cfg(feature = "direct-sql")]
impl<T> DeleteBuilder<T>
where
    T: DeserializeOwned + Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the DELETE query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, headers) = match crate::postgrest::build_postgrest_delete(
                    base_url, &self.parts, &self.params,
                ) {
                    Ok(r) => r,
                    Err(e) => return SupabaseResponse::error(
                        supabase_client_core::SupabaseError::QueryBuilder(e),
                    ),
                };
                crate::postgrest_execute::execute_rest(
                    http, reqwest::Method::DELETE, &url, headers, None, api_key, schema, &self.parts,
                ).await
            }
            QueryBackend::DirectSql { pool } => {
                crate::execute::execute_typed::<T>(pool, &self.parts, &self.params).await
            }
        }
    }
}
