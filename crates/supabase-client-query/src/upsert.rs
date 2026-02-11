use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use supabase_client_core::SupabaseResponse;

use crate::backend::QueryBackend;
use crate::modifier::Modifiable;
use crate::sql::{ParamStore, SqlParts};

/// Builder for UPSERT (INSERT ... ON CONFLICT DO UPDATE) queries.
/// Implements Modifiable. Call `.select()` for RETURNING clause.
pub struct UpsertBuilder<T> {
    pub(crate) backend: QueryBackend,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Modifiable for UpsertBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> UpsertBuilder<T> {
    /// Set the conflict columns for ON CONFLICT.
    pub fn on_conflict(mut self, columns: &[&str]) -> Self {
        self.parts.conflict_columns = columns.iter().map(|c| c.to_string()).collect();
        self
    }

    /// Set a constraint name for ON CONFLICT ON CONSTRAINT.
    pub fn on_conflict_constraint(mut self, constraint: &str) -> Self {
        self.parts.conflict_constraint = Some(constraint.to_string());
        self
    }

    /// Use ON CONFLICT DO NOTHING instead of DO UPDATE.
    ///
    /// When set, duplicate rows are silently ignored instead of updated.
    pub fn ignore_duplicates(mut self) -> Self {
        self.parts.ignore_duplicates = true;
        self
    }

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
impl<T> UpsertBuilder<T>
where
    T: DeserializeOwned + Send,
{
    /// Execute the UPSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        let QueryBackend::Rest { ref http, ref base_url, ref api_key, ref schema } = self.backend;
        let (url, headers, body) = match crate::postgrest::build_postgrest_upsert(
            base_url, &self.parts, &self.params,
        ) {
            Ok(r) => r,
            Err(e) => return SupabaseResponse::error(
                supabase_client_core::SupabaseError::QueryBuilder(e),
            ),
        };
        crate::postgrest_execute::execute_rest(
            http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &self.parts,
        ).await
    }
}

// Direct-SQL mode: additional FromRow + Unpin bounds
#[cfg(feature = "direct-sql")]
impl<T> UpsertBuilder<T>
where
    T: DeserializeOwned + Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the UPSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        match &self.backend {
            QueryBackend::Rest { http, base_url, api_key, schema } => {
                let (url, headers, body) = match crate::postgrest::build_postgrest_upsert(
                    base_url, &self.parts, &self.params,
                ) {
                    Ok(r) => r,
                    Err(e) => return SupabaseResponse::error(
                        supabase_client_core::SupabaseError::QueryBuilder(e),
                    ),
                };
                crate::postgrest_execute::execute_rest(
                    http, reqwest::Method::POST, &url, headers, Some(body), api_key, schema, &self.parts,
                ).await
            }
            QueryBackend::DirectSql { pool } => {
                crate::execute::execute_typed::<T>(pool, &self.parts, &self.params).await
            }
        }
    }
}
