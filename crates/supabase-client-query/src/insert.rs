use std::marker::PhantomData;
use std::sync::Arc;

use sqlx::PgPool;

use supabase_client_core::SupabaseResponse;

use crate::execute;
use crate::modifier::Modifiable;
use crate::sql::{ParamStore, SqlParts};

/// Builder for INSERT queries. Implements Modifiable (for count).
/// Call `.select()` to add RETURNING clause.
pub struct InsertBuilder<T> {
    pub(crate) pool: Arc<PgPool>,
    pub(crate) parts: SqlParts,
    pub(crate) params: ParamStore,
    pub(crate) _marker: PhantomData<T>,
}

impl<T> Modifiable for InsertBuilder<T> {
    fn parts_mut(&mut self) -> &mut SqlParts {
        &mut self.parts
    }
}

impl<T> InsertBuilder<T> {
    /// Add RETURNING clause to get inserted rows back.
    pub fn select(mut self) -> Self {
        self.parts.returning = Some("*".to_string());
        self
    }

    /// Add RETURNING clause with specific columns.
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

impl<T> InsertBuilder<T>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the INSERT query.
    pub async fn execute(self) -> SupabaseResponse<T> {
        execute::execute_typed::<T>(&self.pool, &self.parts, &self.params).await
    }
}
