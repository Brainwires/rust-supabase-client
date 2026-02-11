use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tracing::debug;
use url::Url;

use crate::error::{FunctionsApiErrorResponse, FunctionsError};
use crate::types::*;

/// HTTP client for Supabase Edge Functions.
///
/// Communicates with Edge Functions at `/functions/v1/{function_name}`.
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
#[derive(Debug, Clone)]
pub struct FunctionsClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
    /// Overridden auth token (if set via `set_auth`).
    auth_override: Arc<RwLock<Option<String>>>,
}

impl FunctionsClient {
    /// Create a new Edge Functions client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon or service_role key.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, FunctionsError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/functions/v1", base))?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            HeaderValue::from_str(api_key)
                .map_err(|e| FunctionsError::InvalidConfig(format!("Invalid API key header: {}", e)))?,
        );
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))
                .map_err(|e| FunctionsError::InvalidConfig(format!("Invalid auth header: {}", e)))?,
        );

        let http = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .map_err(FunctionsError::Http)?;

        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
            auth_override: Arc::new(RwLock::new(None)),
        })
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
        let mut auth = self.auth_override.write().unwrap();
        *auth = Some(token.to_string());
    }

    /// Invoke an Edge Function.
    ///
    /// # Arguments
    /// * `function_name` - The name of the deployed function.
    /// * `options` - Invocation options (body, method, headers, region, etc.).
    ///
    /// # Errors
    /// * [`FunctionsError::RelayError`] if Supabase infrastructure returned an error (x-relay-error: true).
    /// * [`FunctionsError::HttpError`] if the function returned a non-2xx status.
    /// * [`FunctionsError::Http`] on network failure.
    pub async fn invoke(
        &self,
        function_name: &str,
        options: InvokeOptions,
    ) -> Result<FunctionResponse, FunctionsError> {
        let url = format!("{}/{}", self.base_url, function_name);
        debug!(function = function_name, method = %options.method, "Invoking edge function");

        // Build the request with the correct HTTP method
        let mut request = match options.method {
            HttpMethod::Get => self.http.get(&url),
            HttpMethod::Post => self.http.post(&url),
            HttpMethod::Put => self.http.put(&url),
            HttpMethod::Patch => self.http.patch(&url),
            HttpMethod::Delete => self.http.delete(&url),
            HttpMethod::Options => self.http.request(reqwest::Method::OPTIONS, &url),
            HttpMethod::Head => self.http.head(&url),
        };

        // Override Authorization: per-request first, then client-level set_auth, then default (from reqwest default headers)
        if let Some(ref auth) = options.authorization {
            request = request.header(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(auth)
                    .map_err(|e| FunctionsError::InvalidConfig(format!("Invalid authorization header: {}", e)))?,
            );
        } else if let Some(ref token) = *self.auth_override.read().unwrap() {
            request = request.header(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|e| FunctionsError::InvalidConfig(format!("Invalid auth override header: {}", e)))?,
            );
        }

        // Set region header if specified
        if let Some(ref region) = options.region {
            request = request.header("x-region", region.to_string());
        }

        // Add custom headers
        for (key, value) in &options.headers {
            let header_name = HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| FunctionsError::InvalidConfig(format!("Invalid header name '{}': {}", key, e)))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|e| FunctionsError::InvalidConfig(format!("Invalid header value for '{}': {}", key, e)))?;
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

        // Read response body
        let body = response.bytes().await?.to_vec();

        // Check for errors
        if is_relay_error {
            let message = parse_error_message(&body);
            debug!(status, message = %message, "Relay error from edge function");
            return Err(FunctionsError::RelayError { status, message });
        }

        if status >= 400 {
            let message = parse_error_message(&body);
            debug!(status, message = %message, "HTTP error from edge function");
            return Err(FunctionsError::HttpError { status, message });
        }

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
        assert!(client.auth_override.read().unwrap().is_none());
        client.set_auth("new-token");
        assert_eq!(
            client.auth_override.read().unwrap().as_deref(),
            Some("new-token")
        );
    }

    #[test]
    fn set_auth_clone_shares_state() {
        let client = FunctionsClient::new("https://example.supabase.co", "test-key").unwrap();
        let clone = client.clone();
        client.set_auth("shared-token");
        assert_eq!(
            clone.auth_override.read().unwrap().as_deref(),
            Some("shared-token")
        );
    }
}
