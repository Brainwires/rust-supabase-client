use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::SupabaseConfig;
use crate::error::SupabaseResult;

/// The main client for interacting with Supabase/PostgreSQL.
///
/// Wraps a connection pool and provides the entry points for building queries.
#[derive(Debug, Clone)]
pub struct SupabaseClient {
    pool: Arc<PgPool>,
    config: Arc<SupabaseConfig>,
}

impl SupabaseClient {
    /// Create a new client from a configuration, establishing the connection pool.
    pub async fn new(config: SupabaseConfig) -> SupabaseResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.pool.max_connections)
            .min_connections(config.pool.min_connections)
            .acquire_timeout(config.pool.acquire_timeout)
            .idle_timeout(config.pool.idle_timeout)
            .max_lifetime(config.pool.max_lifetime)
            .connect(&config.database_url)
            .await?;

        Ok(Self {
            pool: Arc::new(pool),
            config: Arc::new(config),
        })
    }

    /// Create a client from an existing pool.
    pub fn from_pool(pool: PgPool, config: SupabaseConfig) -> Self {
        Self {
            pool: Arc::new(pool),
            config: Arc::new(config),
        }
    }

    /// Get a reference to the underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get an Arc to the pool (for passing to builders).
    pub fn pool_arc(&self) -> Arc<PgPool> {
        Arc::clone(&self.pool)
    }

    /// Get the default schema.
    pub fn schema(&self) -> &str {
        &self.config.schema
    }

    /// Get the full config.
    pub fn config(&self) -> &SupabaseConfig {
        &self.config
    }

    /// Close the connection pool gracefully.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Check if the pool is closed.
    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }
}
