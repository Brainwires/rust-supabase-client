use std::sync::Arc;

#[cfg(feature = "direct-sql")]
use sqlx::postgres::PgPoolOptions;
#[cfg(feature = "direct-sql")]
use sqlx::PgPool;

use crate::auth_token::AccessToken;
use crate::config::SupabaseConfig;
use crate::error::SupabaseResult;
use crate::SupabaseError;

/// The main client for interacting with Supabase.
///
/// By default, uses the PostgREST REST API. Enable the `direct-sql` feature
/// and call `with_database()` to also get a direct PostgreSQL connection pool.
#[derive(Debug, Clone)]
pub struct SupabaseClient {
    config: Arc<SupabaseConfig>,
    http: reqwest::Client,
    /// The signed-in user's access token, shared by every clone and by the
    /// service clients created from this client.
    access_token: AccessToken,
    #[cfg(feature = "direct-sql")]
    pool: Option<Arc<PgPool>>,
}

impl SupabaseClient {
    /// Create a new REST-only client (no database connection needed).
    ///
    /// This is the primary constructor. Queries go through PostgREST.
    pub fn new(config: SupabaseConfig) -> SupabaseResult<Self> {
        validate_config(&config)?;
        let http = build_http_client()?;
        Ok(Self {
            config: Arc::new(config),
            http,
            access_token: AccessToken::new(),
            #[cfg(feature = "direct-sql")]
            pool: None,
        })
    }

    /// Create a client with a direct database connection pool.
    ///
    /// Requires the `direct-sql` feature and a `database_url` in config.
    #[cfg(feature = "direct-sql")]
    pub async fn with_database(config: SupabaseConfig) -> SupabaseResult<Self> {
        validate_config(&config)?;
        let db_url = config.database_url.as_ref().ok_or_else(|| {
            crate::error::SupabaseError::Config(
                "database_url is required for direct-sql mode".into(),
            )
        })?;

        let pool = PgPoolOptions::new()
            .max_connections(config.pool.max_connections)
            .min_connections(config.pool.min_connections)
            .acquire_timeout(config.pool.acquire_timeout)
            .idle_timeout(config.pool.idle_timeout)
            .max_lifetime(config.pool.max_lifetime)
            .connect(db_url)
            .await?;

        let http = build_http_client()?;

        Ok(Self {
            config: Arc::new(config),
            http,
            access_token: AccessToken::new(),
            pool: Some(Arc::new(pool)),
        })
    }

    /// Create a client from an existing pool (direct-sql mode).
    #[cfg(feature = "direct-sql")]
    pub fn from_pool(pool: PgPool, config: SupabaseConfig) -> Self {
        Self {
            config: Arc::new(config),
            http: reqwest::Client::new(),
            access_token: AccessToken::new(),
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

    /// Use `token` (a user JWT) as the bearer token for requests made through
    /// this client and the service clients created from it.
    ///
    /// The `apikey` header still carries the project API key. The auth client
    /// created by `client.auth()` calls this on sign-in and token refresh, so
    /// you only need it when the session comes from somewhere else.
    pub fn set_access_token(&self, token: impl Into<String>) {
        self.access_token.set(token);
    }

    /// Stop sending a user JWT; requests fall back to the API key.
    pub fn clear_access_token(&self) {
        self.access_token.clear();
    }

    /// The user JWT currently in use, if any.
    pub fn access_token(&self) -> Option<String> {
        self.access_token.get()
    }

    /// The shared token slot, for service clients that need to follow
    /// sign-in, refresh and sign-out.
    pub fn access_token_handle(&self) -> AccessToken {
        self.access_token.clone()
    }

    /// The token to send as `Authorization: Bearer ...`: the user JWT when
    /// one is set, otherwise the API key.
    pub fn bearer_token(&self) -> String {
        self.access_token
            .get()
            .unwrap_or_else(|| self.config.supabase_key.clone())
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

/// Reject configuration values that cannot be sent as HTTP headers, so the
/// problem surfaces here as `SupabaseError::Config` instead of as a panic or
/// a failed request when the first query is built.
fn validate_config(config: &SupabaseConfig) -> SupabaseResult<()> {
    reqwest::header::HeaderValue::from_str(&config.supabase_key).map_err(|err| {
        SupabaseError::Config(format!(
            "supabase_key is not a valid HTTP header value: {}",
            err
        ))
    })?;
    check_privileged_key(config, cfg!(target_arch = "wasm32"))
}

/// Refuse a service_role/secret key on wasm32 unless explicitly allowed.
fn check_privileged_key(config: &SupabaseConfig, is_wasm: bool) -> SupabaseResult<()> {
    use crate::keys::{classify_key, KeyKind, PRIVILEGED_KEY_ON_WASM};
    if is_wasm
        && !config.allow_privileged_key_on_wasm
        && classify_key(&config.supabase_key) == KeyKind::Privileged
    {
        return Err(SupabaseError::Config(PRIVILEGED_KEY_ON_WASM.into()));
    }
    Ok(())
}

/// Time allowed to establish a TCP connection. Native targets only: reqwest's
/// wasm backend has no connect timeout. No total request timeout is set, since
/// long-running requests (edge functions, large transfers) are legitimate.
#[cfg(not(target_arch = "wasm32"))]
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Build the shared HTTP client with the crate's default settings.
fn build_http_client() -> SupabaseResult<reqwest::Client> {
    let builder = reqwest::Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder.connect_timeout(CONNECT_TIMEOUT);
    builder
        .build()
        .map_err(|err| SupabaseError::Http(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SupabaseConfig;

    fn test_config() -> SupabaseConfig {
        SupabaseConfig::new("http://localhost:54321", "test-anon-key")
    }

    #[test]
    fn test_new_succeeds_with_valid_config() {
        let client = SupabaseClient::new(test_config());
        assert!(client.is_ok());
    }

    #[test]
    fn test_new_rejects_key_that_is_not_a_valid_header_value() {
        let config = SupabaseConfig::new("http://localhost:54321", "test-anon-key\n");
        match SupabaseClient::new(config) {
            Err(SupabaseError::Config(msg)) => assert!(msg.contains("supabase_key"), "{}", msg),
            other => panic!("expected Config error, got {:?}", other),
        }
    }

    #[test]
    fn test_supabase_url_returns_correct_url() {
        let client = SupabaseClient::new(test_config()).unwrap();
        assert_eq!(client.supabase_url(), "http://localhost:54321");
    }

    #[test]
    fn test_api_key_returns_correct_key() {
        let client = SupabaseClient::new(test_config()).unwrap();
        assert_eq!(client.api_key(), "test-anon-key");
    }

    #[test]
    fn test_schema_returns_public_by_default() {
        let client = SupabaseClient::new(test_config()).unwrap();
        assert_eq!(client.schema(), "public");
    }

    #[test]
    fn test_schema_returns_custom_schema() {
        let config = SupabaseConfig::new("http://localhost:54321", "key").schema("custom");
        let client = SupabaseClient::new(config).unwrap();
        assert_eq!(client.schema(), "custom");
    }

    #[test]
    fn test_http_returns_client_reference() {
        let client = SupabaseClient::new(test_config()).unwrap();
        // Verify we can get a reference to the HTTP client (non-null check)
        let _http: &reqwest::Client = client.http();
    }

    #[test]
    fn test_config_returns_config_reference() {
        let client = SupabaseClient::new(test_config()).unwrap();
        let config = client.config();
        assert_eq!(config.supabase_url, "http://localhost:54321");
        assert_eq!(config.supabase_key, "test-anon-key");
        assert_eq!(config.schema, "public");
    }

    #[test]
    fn test_access_token_is_shared_by_clones() {
        let client = SupabaseClient::new(test_config()).unwrap();
        let cloned = client.clone();
        assert_eq!(client.bearer_token(), "test-anon-key");
        client.set_access_token("user-jwt");
        assert_eq!(cloned.access_token().as_deref(), Some("user-jwt"));
        assert_eq!(cloned.bearer_token(), "user-jwt");
        assert!(client
            .access_token_handle()
            .ptr_eq(&cloned.access_token_handle()));
        cloned.clear_access_token();
        assert_eq!(client.bearer_token(), "test-anon-key");
    }

    fn service_role_jwt() -> String {
        use base64::Engine;
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"role":"service_role"}"#);
        format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", p)
    }

    #[test]
    fn test_privileged_key_refused_on_wasm_unless_allowed() {
        let config = SupabaseConfig::new("http://localhost:54321", service_role_jwt());
        assert!(matches!(
            check_privileged_key(&config, true),
            Err(SupabaseError::Config(_))
        ));
        assert!(check_privileged_key(&config, false).is_ok());
        let allowed = config.allow_privileged_key_on_wasm(true);
        assert!(check_privileged_key(&allowed, true).is_ok());
        let secret = SupabaseConfig::new("http://localhost:54321", "sb_secret_x");
        assert!(check_privileged_key(&secret, true).is_err());
        let anon = SupabaseConfig::new("http://localhost:54321", "sb_publishable_x");
        assert!(check_privileged_key(&anon, true).is_ok());
    }

    #[test]
    fn test_debug_does_not_leak_access_token() {
        let client = SupabaseClient::new(test_config()).unwrap();
        client.set_access_token("user-jwt-secret");
        let dbg = format!("{:?}", client);
        assert!(!dbg.contains("user-jwt-secret"), "{}", dbg);
        assert!(!dbg.contains("test-anon-key"), "{}", dbg);
    }

    #[test]
    fn test_client_is_clone() {
        let client = SupabaseClient::new(test_config()).unwrap();
        let cloned = client.clone();
        assert_eq!(cloned.supabase_url(), client.supabase_url());
        assert_eq!(cloned.api_key(), client.api_key());
        assert_eq!(cloned.schema(), client.schema());
    }
}
