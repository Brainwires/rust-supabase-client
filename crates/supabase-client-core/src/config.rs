#[cfg(feature = "direct-sql")]
use std::time::Duration;

/// Configuration for connecting to a Supabase instance.
///
/// By default, uses the PostgREST REST API (no database connection needed).
/// Enable the `direct-sql` feature and call `.database_url()` to use direct SQL via sqlx.
#[derive(Debug, Clone)]
pub struct SupabaseConfig {
    /// Supabase project URL (e.g. "http://localhost:64321")
    pub supabase_url: String,
    /// Supabase API key (anon or service_role)
    pub supabase_key: String,
    /// Optional PostgreSQL connection string (for direct-sql feature)
    #[cfg(feature = "direct-sql")]
    pub database_url: Option<String>,
    /// Default schema (defaults to "public")
    pub schema: String,
    /// Connection pool configuration (only used with direct-sql)
    #[cfg(feature = "direct-sql")]
    pub pool: PoolConfig,
}

/// Connection pool settings (only available with `direct-sql` feature).
#[cfg(feature = "direct-sql")]
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
}

#[cfg(feature = "direct-sql")]
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
    /// Create a new REST-first config with Supabase URL and API key.
    ///
    /// This is the primary constructor. No database connection is needed.
    pub fn new(supabase_url: impl Into<String>, supabase_key: impl Into<String>) -> Self {
        Self {
            supabase_url: supabase_url.into(),
            supabase_key: supabase_key.into(),
            #[cfg(feature = "direct-sql")]
            database_url: None,
            schema: "public".to_string(),
            #[cfg(feature = "direct-sql")]
            pool: PoolConfig::default(),
        }
    }

    /// Set the default schema.
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = schema.into();
        self
    }

    /// Set the PostgreSQL database URL for direct SQL access.
    #[cfg(feature = "direct-sql")]
    pub fn database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = Some(url.into());
        self
    }

    /// Set maximum number of pool connections.
    #[cfg(feature = "direct-sql")]
    pub fn max_connections(mut self, n: u32) -> Self {
        self.pool.max_connections = n;
        self
    }

    /// Set minimum number of pool connections.
    #[cfg(feature = "direct-sql")]
    pub fn min_connections(mut self, n: u32) -> Self {
        self.pool.min_connections = n;
        self
    }

    /// Set pool acquire timeout.
    #[cfg(feature = "direct-sql")]
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.pool.acquire_timeout = timeout;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_sets_url_and_key() {
        let config = SupabaseConfig::new("http://localhost:54321", "my-anon-key");
        assert_eq!(config.supabase_url, "http://localhost:54321");
        assert_eq!(config.supabase_key, "my-anon-key");
    }

    #[test]
    fn test_new_defaults_schema_to_public() {
        let config = SupabaseConfig::new("http://localhost:54321", "key");
        assert_eq!(config.schema, "public");
    }

    #[test]
    fn test_schema_builder_changes_schema() {
        let config = SupabaseConfig::new("http://localhost:54321", "key").schema("private");
        assert_eq!(config.schema, "private");
    }

    #[test]
    fn test_schema_builder_with_custom_schema() {
        let config = SupabaseConfig::new("http://localhost:54321", "key").schema("my_schema");
        assert_eq!(config.schema, "my_schema");
    }

    #[test]
    fn test_accessor_fields() {
        let config =
            SupabaseConfig::new("https://project.supabase.co", "service-role-key").schema("api");
        assert_eq!(config.supabase_url, "https://project.supabase.co");
        assert_eq!(config.supabase_key, "service-role-key");
        assert_eq!(config.schema, "api");
    }

    #[test]
    fn test_new_with_string_owned() {
        let url = String::from("http://example.com");
        let key = String::from("secret");
        let config = SupabaseConfig::new(url, key);
        assert_eq!(config.supabase_url, "http://example.com");
        assert_eq!(config.supabase_key, "secret");
    }

    #[test]
    fn test_config_clone() {
        let config = SupabaseConfig::new("http://localhost:54321", "key").schema("custom");
        let cloned = config.clone();
        assert_eq!(cloned.supabase_url, config.supabase_url);
        assert_eq!(cloned.supabase_key, config.supabase_key);
        assert_eq!(cloned.schema, config.schema);
    }
}
