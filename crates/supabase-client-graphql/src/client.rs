use std::fmt;

use reqwest::header::{HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::Value;
use supabase_client_core::http::{bearer_header, sensitive_header};
use supabase_client_core::AccessToken;
use tracing::debug;
use url::Url;

use crate::error::GraphqlError;
use crate::mutation::{MutationBuilder, MutationKind as BuilderMutationKind};
use crate::query::QueryBuilder;
use crate::types::GraphqlResponse;

/// HTTP client for the Supabase GraphQL endpoint (`/graphql/v1`).
///
/// Provides both raw query execution and fluent builder methods for
/// collection queries and mutations.
///
/// # Example
/// ```ignore
/// use supabase_client_graphql::GraphqlClient;
///
/// let client = GraphqlClient::new("https://your-project.supabase.co", "your-anon-key")?;
///
/// // Raw query
/// let response = client.execute("query { blogCollection { edges { node { id } } } }", None, None).await?;
///
/// // Builder API
/// let connection = client.collection("blogCollection")
///     .select(&["id", "title"])
///     .first(10)
///     .execute::<BlogRow>().await?;
/// ```
///
/// `Debug` output never includes the API key or tokens.
#[derive(Clone)]
pub struct GraphqlClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
    /// Overridden auth token (if set via `set_auth`).
    auth_override: AccessToken,
    /// Shared session slot (from `SupabaseClient::access_token_handle`).
    session_token: Option<AccessToken>,
}

impl fmt::Debug for GraphqlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphqlClient")
            .field("base_url", &self.base_url.as_str())
            .field("api_key", &"[redacted]")
            .field("auth_override", &self.auth_override)
            .field("session_token", &self.session_token)
            .finish()
    }
}

impl GraphqlClient {
    /// Create a new GraphQL client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon or service_role key.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, GraphqlError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/graphql/v1", base))?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            sensitive_header(api_key).map_err(|e| {
                GraphqlError::InvalidConfig(format!("Invalid API key header: {}", e))
            })?,
        );
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            bearer_header(api_key)
                .map_err(|e| GraphqlError::InvalidConfig(format!("Invalid auth header: {}", e)))?,
        );
        default_headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let builder = reqwest::Client::builder().default_headers(default_headers);
        // reqwest's wasm backend has no connect timeout
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.connect_timeout(std::time::Duration::from_secs(10));
        let http = builder.build().map_err(GraphqlError::Http)?;

        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
            auth_override: AccessToken::new(),
            session_token: None,
        })
    }

    /// Follow a shared session token (see `SupabaseClient::access_token_handle`).
    ///
    /// While the slot holds a user JWT, requests use it as the bearer token
    /// (unless [`set_auth`](Self::set_auth) overrides it). `client.graphql()`
    /// does this, so the signed-in user's JWT is used automatically.
    pub fn with_session_token(mut self, token: AccessToken) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Get the GraphQL endpoint URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Get the API key used by this client.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Update the default auth token for GraphQL requests.
    ///
    /// Subsequent requests will use `Bearer <token>` instead of the API key
    /// (and instead of the session token, if one is followed). Clones of
    /// this client share the setting.
    pub fn set_auth(&self, token: &str) {
        self.auth_override.set(token);
    }

    /// Remove a token set with [`set_auth`](Self::set_auth).
    pub fn clear_auth(&self) {
        self.auth_override.clear();
    }

    /// The token requests currently send as `Authorization: Bearer`, if it
    /// is not the API key.
    fn bearer_override(&self) -> Option<String> {
        self.auth_override
            .get()
            .or_else(|| self.session_token.as_ref().and_then(|t| t.get()))
    }

    /// Execute a raw GraphQL query/mutation.
    ///
    /// # Arguments
    /// * `query` - The GraphQL query or mutation string.
    /// * `variables` - Optional variables as a JSON value.
    /// * `operation_name` - Optional operation name.
    ///
    /// # Returns
    /// The parsed `GraphqlResponse<T>` where `T` is the shape of the `data` field.
    pub async fn execute<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: Option<Value>,
        operation_name: Option<&str>,
    ) -> Result<GraphqlResponse<T>, GraphqlError> {
        let mut body = serde_json::json!({ "query": query });

        if let Some(vars) = variables {
            body["variables"] = vars;
        }
        if let Some(op) = operation_name {
            body["operationName"] = Value::String(op.to_string());
        }

        debug!(query = query, "Executing GraphQL query");

        let mut request = self.http.post(self.base_url.as_str()).json(&body);

        // The user JWT (set_auth, or the shared session) replaces the
        // default `Bearer <api key>`; `apikey` stays the API key.
        if let Some(token) = self.bearer_override() {
            request = request.header(
                reqwest::header::AUTHORIZATION,
                bearer_header(&token).map_err(|e| {
                    GraphqlError::InvalidConfig(format!("Invalid auth override header: {}", e))
                })?,
            );
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        if status >= 400 {
            let body_text = response.text().await.unwrap_or_default();
            debug!(status, body = %body_text, "GraphQL HTTP error");
            return Err(GraphqlError::HttpError {
                status,
                message: body_text,
            });
        }

        let gql_response: GraphqlResponse<T> = response.json().await?;

        // If there are errors and no data, return them as an error
        if !gql_response.errors.is_empty() && gql_response.data.is_none() {
            return Err(GraphqlError::GraphqlErrors(gql_response.errors));
        }

        Ok(gql_response)
    }

    /// Execute a raw GraphQL query and return the full `data` JSON value.
    ///
    /// This is a convenience wrapper around [`execute`](Self::execute) that returns
    /// the data as an untyped `serde_json::Value`.
    pub async fn execute_raw(
        &self,
        query: &str,
        variables: Option<Value>,
        operation_name: Option<&str>,
    ) -> Result<GraphqlResponse<Value>, GraphqlError> {
        self.execute(query, variables, operation_name).await
    }

    /// Start building a collection query.
    ///
    /// # Example
    /// ```ignore
    /// let connection = client.collection("blogCollection")
    ///     .select(&["id", "title"])
    ///     .first(10)
    ///     .execute::<BlogRow>().await?;
    /// ```
    pub fn collection(&self, name: &str) -> QueryBuilder {
        QueryBuilder::new(self.clone(), name.to_string())
    }

    /// Start building an insert mutation.
    ///
    /// # Example
    /// ```ignore
    /// let result = client.insert_into("blogCollection")
    ///     .objects(vec![json!({"title": "New Post"})])
    ///     .returning(&["id", "title"])
    ///     .execute::<BlogRow>().await?;
    /// ```
    pub fn insert_into(&self, collection: &str) -> MutationBuilder {
        MutationBuilder::new(
            self.clone(),
            collection.to_string(),
            BuilderMutationKind::Insert,
        )
    }

    /// Start building an update mutation.
    ///
    /// # Example
    /// ```ignore
    /// let result = client.update("blogCollection")
    ///     .set(json!({"title": "Updated"}))
    ///     .filter(GqlFilter::eq("id", 1))
    ///     .at_most(1)
    ///     .returning(&["id", "title"])
    ///     .execute::<BlogRow>().await?;
    /// ```
    pub fn update(&self, collection: &str) -> MutationBuilder {
        MutationBuilder::new(
            self.clone(),
            collection.to_string(),
            BuilderMutationKind::Update,
        )
    }

    /// Start building a delete mutation.
    ///
    /// # Example
    /// ```ignore
    /// let result = client.delete_from("blogCollection")
    ///     .filter(GqlFilter::eq("id", 1))
    ///     .at_most(1)
    ///     .returning(&["id"])
    ///     .execute::<BlogRow>().await?;
    /// ```
    pub fn delete_from(&self, collection: &str) -> MutationBuilder {
        MutationBuilder::new(
            self.clone(),
            collection.to_string(),
            BuilderMutationKind::Delete,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_ok() {
        let client = GraphqlClient::new("https://example.supabase.co", "test-key");
        assert!(client.is_ok());
    }

    #[test]
    fn client_base_url() {
        let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/graphql/v1");
    }

    #[test]
    fn client_base_url_trailing_slash() {
        let client = GraphqlClient::new("https://example.supabase.co/", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/graphql/v1");
    }

    #[test]
    fn client_api_key() {
        let client = GraphqlClient::new("https://example.supabase.co", "my-key").unwrap();
        assert_eq!(client.api_key(), "my-key");
    }

    #[test]
    fn set_auth_updates_override() {
        let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
        assert!(client.auth_override.get().is_none());
        client.set_auth("new-token");
        assert_eq!(client.auth_override.get().as_deref(), Some("new-token"));
        client.clear_auth();
        assert!(client.bearer_override().is_none());
    }

    #[test]
    fn session_token_is_followed_and_set_auth_wins() {
        let slot = AccessToken::new();
        let client = GraphqlClient::new("https://example.supabase.co", "test-key")
            .unwrap()
            .with_session_token(slot.clone());
        assert!(client.bearer_override().is_none());
        slot.set("session-jwt");
        assert_eq!(client.bearer_override().as_deref(), Some("session-jwt"));
        client.set_auth("explicit");
        assert_eq!(client.bearer_override().as_deref(), Some("explicit"));
        client.clear_auth();
        slot.clear();
        assert!(client.bearer_override().is_none());
    }

    #[test]
    fn debug_redacts_keys_and_tokens() {
        let client = GraphqlClient::new("https://example.supabase.co", "secret-key").unwrap();
        client.set_auth("secret-jwt");
        let out = format!("{:?}", client);
        assert!(!out.contains("secret-key"), "{out}");
        assert!(!out.contains("secret-jwt"), "{out}");
    }

    #[test]
    fn set_auth_clone_shares_state() {
        let client = GraphqlClient::new("https://example.supabase.co", "test-key").unwrap();
        let clone = client.clone();
        client.set_auth("shared-token");
        assert_eq!(clone.auth_override.get().as_deref(), Some("shared-token"));
    }
}
