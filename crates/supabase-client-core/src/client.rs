use std::sync::Arc;

#[cfg(feature = "direct-sql")]
use sqlx::postgres::PgPoolOptions;
#[cfg(feature = "direct-sql")]
use sqlx::PgPool;

use crate::config::SupabaseConfig;
use crate::error::SupabaseResult;

/// The main client for interacting with Supabase.
///
/// By default, uses the PostgREST REST API. Enable the `direct-sql` feature
/// and call `with_database()` to also get a direct PostgreSQL connection pool.
#[derive(Debug, Clone)]
pub struct SupabaseClient {
    config: Arc<SupabaseConfig>,
    http: reqwest::Client,
    #[cfg(feature = "direct-sql")]
    pool: Option<Arc<PgPool>>,
}

impl SupabaseClient {
    /// Create a new REST-only client (no database connection needed).
    ///
    /// This is the primary constructor. Queries go through PostgREST.
    pub fn new(config: SupabaseConfig) -> SupabaseResult<Self> {
        let http = reqwest::Client::new();
        Ok(Self {
            config: Arc::new(config),
            http,
            #[cfg(feature = "direct-sql")]
            pool: None,
        })
    }

    /// Create a client with a direct database connection pool.
    ///
    /// Requires the `direct-sql` feature and a `database_url` in config.
    #[cfg(feature = "direct-sql")]
    pub async fn with_database(config: SupabaseConfig) -> SupabaseResult<Self> {
        let db_url = config
            .database_url
            .as_ref()
            .ok_or_else(|| crate::error::SupabaseError::Config(
                "database_url is required for direct-sql mode".into(),
            ))?;

        let pool = PgPoolOptions::new()
            .max_connections(config.pool.max_connections)
            .min_connections(config.pool.min_connections)
            .acquire_timeout(config.pool.acquire_timeout)
            .idle_timeout(config.pool.idle_timeout)
            .max_lifetime(config.pool.max_lifetime)
            .connect(db_url)
            .await?;

        let http = reqwest::Client::new();

        Ok(Self {
            config: Arc::new(config),
            http,
            pool: Some(Arc::new(pool)),
        })
    }

    /// Create a client from an existing pool (direct-sql mode).
    #[cfg(feature = "direct-sql")]
    pub fn from_pool(pool: PgPool, config: SupabaseConfig) -> Self {
        Self {
            config: Arc::new(config),
            http: reqwest::Client::new(),
            pool: Some(Arc::new(pool)),
        }
    }

    /// Get a reference to the HTTP client.
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Get the Supabase project URL.
    pub fn supabase_url(&self) -> &str {
        &self.config.supabase_url
    }

    /// Get the Supabase API key.
    pub fn api_key(&self) -> &str {
        &self.config.supabase_key
    }

    /// Get the default schema.
    pub fn schema(&self) -> &str {
        &self.config.schema
    }

    /// Get the full config.
    pub fn config(&self) -> &SupabaseConfig {
        &self.config
    }

    /// Get a reference to the underlying connection pool (if available).
    #[cfg(feature = "direct-sql")]
    pub fn pool(&self) -> Option<&PgPool> {
        self.pool.as_deref()
    }

    /// Get an Arc to the pool (for passing to builders).
    #[cfg(feature = "direct-sql")]
    pub fn pool_arc(&self) -> Option<Arc<PgPool>> {
        self.pool.clone()
    }

    /// Check if direct-sql pool is available.
    #[cfg(feature = "direct-sql")]
    pub fn has_pool(&self) -> bool {
        self.pool.is_some()
    }

    /// Close the connection pool gracefully (if available).
    #[cfg(feature = "direct-sql")]
    pub async fn close(&self) {
        if let Some(pool) = &self.pool {
            pool.close().await;
        }
    }

    /// Check if the pool is closed (if available).
    #[cfg(feature = "direct-sql")]
    pub fn is_closed(&self) -> bool {
        self.pool.as_ref().map_or(true, |p| p.is_closed())
    }
}
