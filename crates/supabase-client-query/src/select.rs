use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use supabase_client_core::SupabaseResponse;

use crate::backend::QueryBackend;
use crate::filter::Filterable;
use crate::modifier::Modifiable;
use crate::sql::{ExplainOptions, FilterCondition, ParamStore, SqlParts};

/// Builder for SELECT queries. Implements both Filterable and Modifiable.
pub struct SelectBuilder<T> {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Filterable for SelectBuilder<T> {
    fn filters_mut(&mut self) -> &mut Vec<FilterCondition> {
        &mut self.parts.filters
    }
    fn params_mut(&mut self) -> &mut ParamStore {
        &mut self.params
    }
}

impl<T> Modifiable for SelectBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> SelectBuilder<T> {
    /// Override the schema for this query.
    pub fn schema(mut self, schema: &str) -> Self {
        self.parts.schema_override = Some(schema.to_string());
        self
    }

    /// Wrap the SELECT in `EXPLAIN (ANALYZE, FORMAT JSON)`.
    pub fn explain(mut self) -> Self {
        self.parts.explain = Some(ExplainOptions::default());
        self
    }

    /// Wrap the SELECT in EXPLAIN with custom options.
    pub fn explain_with(mut self, options: ExplainOptions) -> Self {
        self.parts.explain = Some(options);
        self
    }

    /// Switch to head/count-only mode.
    pub fn head(mut self) -> Self {
        self.parts.head = true;
        self
    }
}

// REST-only mode: only DeserializeOwned + Send needed
#[cfg(not(feature = "direct-sql"))]
impl<T> SelectBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the SELECT query and return results.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let method = if self.parts.head {
            reqwest::Method::HEAD
        } else {
            reqwest::Method::GET
        };
        let (url, headers) = match crate::postgrest::build_postgrest_select(
            base_url, &self.parts, &self.params,
        ) {
            Ok(r) => r,
            Err(e) => return SupabaseResponse::error(
                supabase_client_core::SupabaseError::QueryBuilder(e),
            ),
        };
        crate::postgrest_execute::execute_rest(
            http, method, &url, headers, None, api_key, schema, &self.parts,
        ).await
    }
}

// Direct-SQL mode: additional FromRow + Unpin bounds
#[cfg(feature = "direct-sql")]
impl<T> SelectBuilder<T>
where
    T: DeserializeOwned + Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the SELECT query and return results.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let method = if self.parts.head {
                    reqwest::Method::HEAD
                } else {
                    reqwest::Method::GET
                };
                let (url, headers) = match crate::postgrest::build_postgrest_select(
                    base_url, &self.parts, &self.params,
                ) {
                    Ok(r) => r,
                    Err(e) => return SupabaseResponse::error(
                        supabase_client_core::SupabaseError::QueryBuilder(e),
                    ),
                };
                crate::postgrest_execute::execute_rest(
                    http, method, &url, headers, None, api_key, schema, &self.parts,
                ).await
            }
            QueryBackend::DirectSql { pool } => {
                crate::execute::execute_typed::<T>(pool, &self.parts, &self.params).await
            }
        }
    }
}
