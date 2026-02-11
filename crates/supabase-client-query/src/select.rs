use std::marker::PhantomData;
use std::sync::Arc;

use sqlx::PgPool;

use supabase_client_core::SupabaseResponse;

use crate::execute;
use crate::filter::Filterable;
use crate::modifier::Modifiable;
use crate::sql::{FilterCondition, ParamStore, SqlParts};

/// Builder for SELECT queries. Implements both Filterable and Modifiable.
pub struct SelectBuilder<T> {
    pub(crate) pool: Arc<PgPool>,
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

impl<T> SelectBuilder<T>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    /// Execute the SELECT query and return results.
    pub async fn execute(self) -> SupabaseResponse<T> {
        execute::execute_typed::<T>(&self.pool, &self.parts, &self.params).await
    }
}
