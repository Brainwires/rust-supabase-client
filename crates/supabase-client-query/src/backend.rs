use std::sync::Arc;

#[cfg(feature = "direct-sql")]
use sqlx::PgPool;

/// Backend for query execution.
///
/// By default, queries are executed via the PostgREST REST API.
/// With the `direct-sql` feature, queries can be executed directly via sqlx.
#[derive(Clone)]
pub enum QueryBackend {
    /// PostgREST REST API backend (default).
    Rest {
        http: reqwest::Client,
        base_url: Arc<str>,
        api_key: Arc<str>,
        schema: String,
    },
    /// Direct SQL via sqlx (opt-in with `direct-sql` feature).
    #[cfg(feature = "direct-sql")]
    DirectSql {
        pool: Arc<PgPool>,
    },
}

impl std::fmt::Debug for QueryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rest { base_url, schema, .. } => {
                f.debug_struct("Rest")
                    .field("base_url", base_url)
                    .field("schema", schema)
                    .finish()
            }
            #[cfg(feature = "direct-sql")]
            Self::DirectSql { .. } => f.debug_struct("DirectSql").finish(),
        }
    }
}
