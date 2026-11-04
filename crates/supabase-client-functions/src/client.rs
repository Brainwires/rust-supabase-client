use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use supabase_client_core::http::{
    bearer_header, read_body_limited, read_error_body, sensitive_header, BodyReadError,
};
use supabase_client_core::AccessToken;
use tracing::debug;
use url::Url;

use crate::error::{FunctionsApiErrorResponse, FunctionsError};
use crate::types::*;

/// HTTP client for Supabase Edge Functions.
///
/// Communicates with Edge Functions at `/functions/v1/{function_name}`.
///
/// Requests are authorized with, in order of preference: the per-request
/// [`InvokeOptions::authorization`], the token passed to
/// [`set_auth`](FunctionsClient::set_auth), the signed-in user's JWT (when the
/// client was created from a `SupabaseClient` whose auth client has a
/// session), or the API key.
///
/// `Debug` output never includes the API key or tokens.
///
/// # Example
/// ```ignore
/// use supabase_client_functions::{FunctionsClient, InvokeOptions};
/// use serde_json::json;
///
/// let client = FunctionsClient::new("https://your-project.supabase.co", "your-anon-key")?;
/// let response = client.invoke("hello", InvokeOptions::new()
///     .body(json!({"name": "World"}))
/// ).await?;
/// let data: serde_json::Value = response.json()?;
/// ```
#[derive(Clone)]
pub struct FunctionsClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
    /// Overridden auth token (if set via `set_auth`). Shared by clones.
    auth_override: AccessToken,
    /// Session token shared with a `SupabaseClient`, if wired up.
    session_token: Option<AccessToken>,
    max_response_bytes: Option<u64>,
    timeout: Option<Duration>,
}

impl fmt::Debug for FunctionsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionsClient")
            .field("base_url", &self.base_url.as_str())
            .field("api_key", &"[redacted]")
            .field("auth_override", &self.auth_override)
            .field("session_token", &self.session_token)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl FunctionsClient {
    /// Create a new Edge Functions client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon or service_role key.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, FunctionsError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/functions/v1", base))?;
        if base_url.cannot_be_a_base() {
            return Err(FunctionsError::InvalidConfig(format!(
                "supabase_url cannot be used as a base URL: {}",
                supabase_url
            )));
        }
        supabase_client_core::keys::warn_if_privileged_on_wasm(api_key, "functions");

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            sensitive_header(api_key).map_err(|e| {
                FunctionsError::InvalidConfig(format!("Invalid API key header: {}", e))
            })?,
        );
        default_headers.insert(
            AUTHORIZATION,
            bearer_header(api_key).map_err(|e| {
                FunctionsError::InvalidConfig(format!("Invalid auth header: {}", e))
            })?,
        );

        let builder = reqwest::Client::builder().default_headers(default_headers);
        // reqwest's wasm backend has no connect timeout
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.connect_timeout(std::time::Duration::from_secs(10));
        let http = builder.build().map_err(FunctionsError::Http)?;

        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
            auth_override: AccessToken::new(),
            session_token: None,
            max_response_bytes: None,
            timeout: None,
        })
    }

    /// Follow a shared session token (see `SupabaseClient::access_token_handle`).
    pub fn with_session_token(mut self, token: AccessToken) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Fail invocations whose response body is larger than `max_bytes` with
    /// [`FunctionsError::ResponseTooLarge`]. `None` (the default) means no
    /// limit. Error bodies are always truncated to 64 KiB.
    pub fn with_max_response_size(mut self, max_bytes: Option<u64>) -> Self {
        self.max_response_bytes = max_bytes;
        self
    }

    /// Set a total timeout for each invocation (native targets only; ignored
    /// on wasm32). There is no total timeout by default, only a 10 s connect
    /// timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Get the base URL for the functions endpoint.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Get the API key used by this client.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Update the default auth token for function invocations.
    ///
    /// Subsequent invocations will use `Bearer <token>` unless overridden per-request.
    ///
    /// Mirrors `supabase.functions.setAuth(token)`.
    pub fn set_auth(&self, token: &str) {
        self.auth_override.set(token);
    }

    /// Remove a token set with [`set_auth`](Self::set_auth).
    pub fn clear_auth(&self) {
        self.auth_override.clear();
    }

    /// Build `base_url/<name segments>`.
    ///
    /// The name may contain `/` (nested routes); each piece is pushed as its
    /// own percent-encoded segment so `?` and `#` cannot start a query or
    /// fragment, and empty, `.` and `..` segments are rejected.
    fn function_url(&self, function_name: &str) -> Result<Url, FunctionsError> {
        let segments: Vec<&str> = function_name.split('/').collect();
        if segments
            .iter()
            .any(|s| s.is_empty() || *s == "." || *s == "..")
        {
            return Err(FunctionsError::InvalidFunctionName(function_name.to_string()));
        }
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .expect("base_url is checked to be a base in new()");
            path.pop_if_empty();
            for seg in segments {
                path.push(seg);
            }
        }
        Ok(url)
    }

    /// Invoke an Edge Function.
    ///
    /// # Arguments
    /// * `function_name` - The name of the deployed function. May contain `/`
    ///   for sub-paths; `.`, `..` and empty segments are rejected.
    /// * `options` - Invocation options (body, method, headers, region, etc.).
    ///
    /// # Errors
    /// * [`FunctionsError::InvalidFunctionName`] if the name cannot be used in a URL.
    /// * [`FunctionsError::RelayError`] if Supabase infrastructure returned an error (x-relay-error: true).
    /// * [`FunctionsError::HttpError`] if the function returned a non-2xx status.
    /// * [`FunctionsError::ResponseTooLarge`] if a size limit is set and exceeded.
    /// * [`FunctionsError::Http`] on network failure.
    pub async fn invoke(
        &self,
        function_name: &str,
        options: InvokeOptions,
    ) -> Result<FunctionResponse, FunctionsError> {
        let url = self.function_url(function_name)?;
        debug!(function = function_name, method = %options.method, "Invoking edge function");

        // Build the request with the correct HTTP method
        let method = match options.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Options => reqwest::Method::OPTIONS,
            HttpMethod::Head => reqwest::Method::HEAD,
        };
        let mut request = self.http.request(method, url);
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(t) = self.timeout {
            request = request.timeout(t);
        }

        // Override Authorization: per-request first, then client-level set_auth,
        // then the shared session token, then default (from reqwest default headers)
        if let Some(ref auth) = options.authorization {
            request = request.header(
                AUTHORIZATION,
                sensitive_header(auth).map_err(|e| {
                    FunctionsError::InvalidConfig(format!("Invalid authorization header: {}", e))
                })?,
            );
        } else if let Some(token) = self
            .auth_override
            .get()
            .or_else(|| self.session_token.as_ref().and_then(|t| t.get()))
        {
            request = request.header(
                AUTHORIZATION,
                bearer_header(&token).map_err(|e| {
                    FunctionsError::InvalidConfig(format!("Invalid auth override header: {}", e))
                })?,
            );
        }

        // Set region header if specified
        if let Some(ref region) = options.region {
            request = request.header("x-region", region.to_string());
        }

        // Add custom headers
        for (key, value) in &options.headers {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                FunctionsError::InvalidConfig(format!("Invalid header name '{}': {}", key, e))
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                FunctionsError::InvalidConfig(format!("Invalid header value for '{}': {}", key, e))
            })?;
            request = request.header(header_name, header_value);
        }

        // Set Content-Type and body
        match options.body {
            InvokeBody::Json(value) => {
                let ct = options.content_type.as_deref().unwrap_or("application/json");
                request = request
                    .header(reqwest::header::CONTENT_TYPE, ct)
                    .body(serde_json::to_vec(&value)?);
            }
            InvokeBody::Bytes(bytes) => {
                let ct = options
                    .content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream");
                request = request
                    .header(reqwest::header::CONTENT_TYPE, ct)
                    .body(bytes);
            }
            InvokeBody::Text(text) => {
                let ct = options.content_type.as_deref().unwrap_or("text/plain");
                request = request
                    .header(reqwest::header::CONTENT_TYPE, ct)
                    .body(text);
            }
            InvokeBody::None => {
                if let Some(ct) = options.content_type {
                    request = request.header(reqwest::header::CONTENT_TYPE, ct);
                }
            }
        }

        // Send the request
        let response = request.send().await?;

        // Collect response headers (lowercased keys)
        let status = response.status().as_u16();
        let is_relay_error = response
            .headers()
            .get("x-relay-error")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        let mut resp_headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                resp_headers.insert(name.as_str().to_string(), v.to_string());
            }
        }

        // Check for errors (error bodies are truncated to 64 KiB)
        if is_relay_error || status >= 400 {
            let body = read_error_body(response).await;
            let message = parse_error_message(&body);
            if is_relay_error {
                debug!(status, message = %message, "Relay error from edge function");
                return Err(FunctionsError::RelayError { status, message });
            }
            debug!(status, message = %message, "HTTP error from edge function");
            return Err(FunctionsError::HttpError { status, message });
        }

        let body = read_body_limited(response, self.max_response_bytes)
            .await
            .map_err(|e| match e {
                BodyReadError::Http(e) => FunctionsError::Http(e),
                BodyReadError::TooLarge { limit } => FunctionsError::ResponseTooLarge { limit },
            })?;

        Ok(FunctionResponse::new(status, resp_headers, body))
    }
}

/// Try to parse an error message from the response body (JSON first, then plain text).
fn parse_error_message(body: &[u8]) -> String {
    if let Ok(api_err) = serde_json::from_slice::<FunctionsApiErrorResponse>(body) {
        return api_err.error_message();
    }
    String::from_utf8_lossy(body).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_ok() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key");
        assert!(client.is_ok());
    }

    #[test]
    fn client_base_url() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/functions/v1");
    }

    #[test]
    fn client_base_url_trailing_slash() {
        let client = FunctionsClient::new("https://example.supabase.co/", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/functions/v1");
    }

    #[test]
    fn client_api_key() {
        let client = FunctionsClient::new("https://example.supabase.co", "my-key").unwrap();
        assert_eq!(client.api_key(), "my-key");
    }

    #[test]
    fn parse_error_message_json() {
        let body = br#"{"message":"Function not found"}"#;
        assert_eq!(parse_error_message(body), "Function not found");
    }

    #[test]
    fn parse_error_message_plain_text() {
        let body = b"Something went wrong";
        assert_eq!(parse_error_message(body), "Something went wrong");
    }

    #[test]
    fn set_auth_updates_override() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key").unwrap();
        assert!(client.auth_override.get().is_none());
        client.set_auth("new-token");
        assert_eq!(client.auth_override.get().as_deref(), Some("new-token"));
        client.clear_auth();
        assert!(client.auth_override.get().is_none());
    }

    #[test]
    fn set_auth_clone_shares_state() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key").unwrap();
        let clone = client.clone();
        client.set_auth("shared-token");
        assert_eq!(clone.auth_override.get().as_deref(), Some("shared-token"));
    }

    // ─── Wiremock Tests ──────────────────────────────────────

    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: create a FunctionsClient pointing at the given mock server.
    fn mock_client(server: &MockServer) -> FunctionsClient {
        FunctionsClient::new(&server.uri(), "test-anon-key").unwrap()
    }

    #[tokio::test]
    async fn wiremock_invoke_json_body_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/hello"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "ok"})),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().body(serde_json::json!({"name": "World"}));
        let resp = client.invoke("hello", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
        let val: serde_json::Value = resp.json().unwrap();
        assert_eq!(val["message"], "ok");
    }

    #[tokio::test]
    async fn wiremock_invoke_relay_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/broken"))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("x-relay-error", "true")
                    .set_body_json(serde_json::json!({"message": "Function not found"})),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let err = client
            .invoke("broken", InvokeOptions::new())
            .await
            .unwrap_err();
        match err {
            FunctionsError::RelayError { status, message } => {
                assert_eq!(status, 500);
                assert_eq!(message, "Function not found");
            }
            other => panic!("Expected RelayError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wiremock_invoke_http_4xx_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/missing"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"message": "Not Found"})),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let err = client
            .invoke("missing", InvokeOptions::new())
            .await
            .unwrap_err();
        match err {
            FunctionsError::HttpError { status, message } => {
                assert_eq!(status, 404);
                assert_eq!(message, "Not Found");
            }
            other => panic!("Expected HttpError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wiremock_invoke_auth_override_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/secure"))
            .and(header("authorization", "Bearer user-jwt-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().authorization("Bearer user-jwt-token");
        let resp = client.invoke("secure", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_region_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/regional"))
            .and(header("x-region", "us-east-1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().region(FunctionRegion::UsEast1);
        let resp = client.invoke("regional", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_custom_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/custom"))
            .and(header("x-custom-one", "alpha"))
            .and(header("x-custom-two", "beta"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new()
            .header("x-custom-one", "alpha")
            .header("x-custom-two", "beta");
        let resp = client.invoke("custom", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_body_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/echo"))
            .and(header("content-type", "application/json"))
            .and(body_string_contains("\"key\""))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().body(serde_json::json!({"key": "value"}));
        let resp = client.invoke("echo", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_body_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/upload"))
            .and(header("content-type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().body_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let resp = client.invoke("upload", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_body_text() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/text"))
            .and(header("content-type", "text/plain"))
            .and(body_string_contains("hello world"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().body_text("hello world");
        let resp = client.invoke("text", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_body_none() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/empty"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new(); // body is None by default
        let resp = client.invoke("empty", opts).await.unwrap();
        assert_eq!(resp.status(), 204);
    }

    #[tokio::test]
    async fn wiremock_invoke_method_get() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/functions/v1/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": []})))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().method(HttpMethod::Get);
        let resp = client.invoke("data", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_method_put() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/functions/v1/update"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().method(HttpMethod::Put);
        let resp = client.invoke("update", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_method_delete() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/functions/v1/remove"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().method(HttpMethod::Delete);
        let resp = client.invoke("remove", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn wiremock_invoke_method_patch() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/functions/v1/patch"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let opts = InvokeOptions::new().method(HttpMethod::Patch);
        let resp = client.invoke("patch", opts).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    // ─── Regression tests (security audit) ───────────────────

    use wiremock::matchers::any;

    async fn catch_all() -> MockServer {
        let s = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&s)
            .await;
        s
    }

    #[tokio::test]
    async fn regression_function_name_traversal_is_rejected() {
        let s = catch_all().await;
        let f = FunctionsClient::new(&s.uri(), "SERVICE_ROLE_KEY").unwrap();
        for bad in [
            "../../rest/v1/profiles?id=not.is.null",
            "a/../b",
            "./a",
            "",
            "a//b",
            "a/",
        ] {
            let err = f
                .invoke(bad, InvokeOptions::new().method(HttpMethod::Delete))
                .await
                .unwrap_err();
            assert!(
                matches!(err, FunctionsError::InvalidFunctionName(_)),
                "{bad}: {err:?}"
            );
        }
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn regression_function_name_query_and_fragment_are_encoded() {
        let s = catch_all().await;
        let f = FunctionsClient::new(&s.uri(), "k").unwrap();
        f.invoke("hello/world?x=1#frag", InvokeOptions::new())
            .await
            .unwrap();
        let reqs = s.received_requests().await.unwrap();
        let r = reqs.last().unwrap();
        assert_eq!(r.url.path(), "/functions/v1/hello/world%3Fx=1%23frag");
        assert!(r.url.query().is_none());
    }

    #[test]
    fn regression_debug_does_not_leak_keys() {
        let f = FunctionsClient::new("https://x.supabase.co", "SECRET-SERVICE-KEY").unwrap();
        f.set_auth("USER-JWT-SECRET");
        let df = format!("{:?}", f);
        assert!(!df.contains("SECRET-SERVICE-KEY"), "{}", df);
        assert!(!df.contains("USER-JWT-SECRET"), "{}", df);
        let opts = InvokeOptions::new()
            .authorization("Bearer PER-REQUEST-SECRET")
            .header("x-api-secret", "HEADER-SECRET");
        let dopts = format!("{:?}", opts);
        assert!(!dopts.contains("PER-REQUEST-SECRET"), "{}", dopts);
        assert!(!dopts.contains("HEADER-SECRET"), "{}", dopts);
        assert!(dopts.contains("x-api-secret"), "{}", dopts);
    }

    #[tokio::test]
    async fn session_token_is_followed_and_overridable() {
        let s = catch_all().await;
        let slot = supabase_client_core::AccessToken::new();
        let f = FunctionsClient::new(&s.uri(), "anon")
            .unwrap()
            .with_session_token(slot.clone());
        f.invoke("a", InvokeOptions::new()).await.unwrap();
        slot.set("session-jwt");
        f.invoke("a", InvokeOptions::new()).await.unwrap();
        f.set_auth("explicit");
        f.invoke("a", InvokeOptions::new()).await.unwrap();
        f.invoke("a", InvokeOptions::new().authorization("Bearer per-request"))
            .await
            .unwrap();
        let reqs = s.received_requests().await.unwrap();
        let auth: Vec<&str> = reqs
            .iter()
            .map(|r| r.headers.get("authorization").unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            auth,
            vec![
                "Bearer anon",
                "Bearer session-jwt",
                "Bearer explicit",
                "Bearer per-request"
            ]
        );
    }

    #[tokio::test]
    async fn response_size_cap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1u8; 2048]))
            .mount(&server)
            .await;
        let f = mock_client(&server).with_max_response_size(Some(100));
        let err = f.invoke("big", InvokeOptions::new()).await.unwrap_err();
        assert!(
            matches!(err, FunctionsError::ResponseTooLarge { limit: 100 }),
            "{:?}",
            err
        );
    }

    #[tokio::test]
    async fn error_body_is_truncated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/functions/v1/huge-error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("e".repeat(1 << 20)))
            .mount(&server)
            .await;
        let err = mock_client(&server)
            .invoke("huge-error", InvokeOptions::new())
            .await
            .unwrap_err();
        match err {
            FunctionsError::HttpError { status, message } => {
                assert_eq!(status, 500);
                assert_eq!(
                    message.len(),
                    supabase_client_core::http::MAX_ERROR_BODY_BYTES
                );
            }
            other => panic!("{:?}", other),
        }
    }
}
