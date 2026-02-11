use std::time::Duration;

/// Configuration for connecting to a Supabase/PostgreSQL instance.
#[derive(Debug, Clone)]
pub struct SupabaseConfig {
    /// PostgreSQL connection string (e.g. "postgres://user:pass@host/db")
    pub database_url: String,
    /// Optional Supabase project URL (for auth/storage/realtime)
    pub supabase_url: Option<String>,
    /// Optional Supabase anon/service key
    pub supabase_key: Option<String>,
    /// Default schema (defaults to "public")
    pub schema: String,
    /// Connection pool configuration
    pub pool: PoolConfig,
}

/// Connection pool settings.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
        }
    }
}

impl SupabaseConfig {
    /// Create a new config with just a database URL.
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            supabase_url: None,
            supabase_key: None,
            schema: "public".to_string(),
            pool: PoolConfig::default(),
        }
    }

    /// Set the Supabase project URL.
    pub fn supabase_url(mut self, url: impl Into<String>) -> Self {
        self.supabase_url = Some(url.into());
        self
    }

    /// Set the Supabase API key.
    pub fn supabase_key(mut self, key: impl Into<String>) -> Self {
        self.supabase_key = Some(key.into());
        self
    }

    /// Set the default schema.
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = schema.into();
        self
    }

    /// Set maximum number of pool connections.
    pub fn max_connections(mut self, n: u32) -> Self {
        self.pool.max_connections = n;
        self
    }

    /// Set minimum number of pool connections.
    pub fn min_connections(mut self, n: u32) -> Self {
        self.pool.min_connections = n;
        self
    }

    /// Set pool acquire timeout.
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.pool.acquire_timeout = timeout;
        self
    }
}
