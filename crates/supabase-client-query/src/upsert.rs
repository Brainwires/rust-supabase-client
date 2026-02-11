use std::marker::PhantomData;
use std::sync::Arc;

use sqlx::PgPool;

use supabase_client_core::SupabaseResponse;

use crate::execute;
use crate::modifier::Modifiable;
use crate::sql::{ParamStore, SqlParts};

/// Builder for UPSERT (INSERT ... ON CONFLICT DO UPDATE) queries.
/// Implements Modifiable. Call `.select()` for RETURNING clause.
pub struct UpsertBuilder<T> {
    pub(crate) pool: Arc<PgPool>,
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

impl<T> UpsertBuilder<T>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the UPSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        execute::execute_typed::<T>(&self.pool, &self.parts, &self.params).await
    }
}
