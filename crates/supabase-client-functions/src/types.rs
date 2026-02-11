use std::collections::HashMap;
use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::FunctionsError;

/// HTTP methods supported for Edge Function invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Head => write!(f, "HEAD"),
        }
    }
}

/// Supabase Edge Function deployment regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionRegion {
    UsEast1,
    UsWest1,
    UsCentral1,
    EuWest1,
    EuWest2,
    EuWest3,
    EuCentral1,
    EuCentral2,
    ApSoutheast1,
    ApSoutheast2,
    ApNortheast1,
    ApNortheast2,
    ApSouth1,
    SaEast1,
    CaCentral1,
    MeSouth1,
    AfSouth1,
    Any,
    Custom(String),
}

impl fmt::Display for FunctionRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsEast1 => write!(f, "us-east-1"),
            Self::UsWest1 => write!(f, "us-west-1"),
            Self::UsCentral1 => write!(f, "us-central-1"),
            Self::EuWest1 => write!(f, "eu-west-1"),
            Self::EuWest2 => write!(f, "eu-west-2"),
            Self::EuWest3 => write!(f, "eu-west-3"),
            Self::EuCentral1 => write!(f, "eu-central-1"),
            Self::EuCentral2 => write!(f, "eu-central-2"),
            Self::ApSoutheast1 => write!(f, "ap-southeast-1"),
            Self::ApSoutheast2 => write!(f, "ap-southeast-2"),
            Self::ApNortheast1 => write!(f, "ap-northeast-1"),
            Self::ApNortheast2 => write!(f, "ap-northeast-2"),
            Self::ApSouth1 => write!(f, "ap-south-1"),
            Self::SaEast1 => write!(f, "sa-east-1"),
            Self::CaCentral1 => write!(f, "ca-central-1"),
            Self::MeSouth1 => write!(f, "me-south-1"),
            Self::AfSouth1 => write!(f, "af-south-1"),
            Self::Any => write!(f, "any"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Body types for Edge Function invocation.
#[derive(Debug, Clone)]
pub enum InvokeBody {
    Json(Value),
    Bytes(Vec<u8>),
    Text(String),
    None,
}

/// Options for invoking an Edge Function.
///
/// # Example
/// ```
/// use supabase_client_functions::InvokeOptions;
/// use serde_json::json;
///
/// let opts = InvokeOptions::new()
///     .body(json!({"name": "World"}))
///     .header("x-custom", "value");
/// ```
#[derive(Debug, Clone)]
pub struct InvokeOptions {
    pub(crate) body: InvokeBody,
    pub(crate) method: HttpMethod,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) region: Option<FunctionRegion>,
    pub(crate) content_type: Option<String>,
    pub(crate) authorization: Option<String>,
}

impl Default for InvokeOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl InvokeOptions {
    /// Create new invoke options with defaults (POST, no body).
    pub fn new() -> Self {
        Self {
            body: InvokeBody::None,
            method: HttpMethod::Post,
            headers: HashMap::new(),
            region: None,
            content_type: None,
            authorization: None,
        }
    }

    /// Set a JSON body (serialized from a `serde_json::Value`).
    pub fn body(mut self, value: Value) -> Self {
        self.body = InvokeBody::Json(value);
        self
    }

    /// Set a raw binary body.
    pub fn body_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.body = InvokeBody::Bytes(bytes);
        self
    }

    /// Set a text body.
    pub fn body_text(mut self, text: impl Into<String>) -> Self {
        self.body = InvokeBody::Text(text.into());
        self
    }

    /// Set the HTTP method.
    pub fn method(mut self, method: HttpMethod) -> Self {
        self.method = method;
        self
    }

    /// Add a custom header.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Add multiple custom headers.
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Set the deployment region.
    pub fn region(mut self, region: FunctionRegion) -> Self {
        self.region = Some(region);
        self
    }

    /// Override the Content-Type header explicitly.
    pub fn content_type(mut self, ct: impl Into<String>) -> Self {
        self.content_type = Some(ct.into());
        self
    }

    /// Override the Authorization header (e.g., `"Bearer <user-jwt>"`).
    pub fn authorization(mut self, auth: impl Into<String>) -> Self {
        self.authorization = Some(auth.into());
        self
    }
}

/// Response from an Edge Function invocation.
#[derive(Debug, Clone)]
pub struct FunctionResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl FunctionResponse {
    pub(crate) fn new(status: u16, headers: HashMap<String, String>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// All response headers (keys are lowercased).
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Get a specific response header (case-insensitive lookup).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers.get(&lower).map(|s| s.as_str())
    }

    /// Deserialize the response body as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, FunctionsError> {
        serde_json::from_slice(&self.body).map_err(FunctionsError::from)
    }

    /// Get the response body as a UTF-8 string.
    pub fn text(&self) -> Result<String, FunctionsError> {
        String::from_utf8(self.body.clone()).map_err(|e| {
            FunctionsError::InvalidConfig(format!("Response body is not valid UTF-8: {}", e))
        })
    }

    /// Get the raw response body bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response and return the body bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.body
    }

    /// Get the Content-Type header value.
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Put.to_string(), "PUT");
        assert_eq!(HttpMethod::Patch.to_string(), "PATCH");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
        assert_eq!(HttpMethod::Options.to_string(), "OPTIONS");
        assert_eq!(HttpMethod::Head.to_string(), "HEAD");
    }

    #[test]
    fn function_region_display() {
        assert_eq!(FunctionRegion::UsEast1.to_string(), "us-east-1");
        assert_eq!(FunctionRegion::EuWest1.to_string(), "eu-west-1");
        assert_eq!(FunctionRegion::ApNortheast1.to_string(), "ap-northeast-1");
        assert_eq!(FunctionRegion::Any.to_string(), "any");
        assert_eq!(
            FunctionRegion::Custom("my-region".into()).to_string(),
            "my-region"
        );
    }

    #[test]
    fn invoke_options_defaults() {
        let opts = InvokeOptions::new();
        assert!(matches!(opts.body, InvokeBody::None));
        assert_eq!(opts.method, HttpMethod::Post);
        assert!(opts.headers.is_empty());
        assert!(opts.region.is_none());
        assert!(opts.content_type.is_none());
        assert!(opts.authorization.is_none());
    }

    #[test]
    fn invoke_options_builder() {
        let opts = InvokeOptions::new()
            .body(serde_json::json!({"key": "value"}))
            .method(HttpMethod::Put)
            .header("x-custom", "test")
            .region(FunctionRegion::UsEast1)
            .content_type("text/plain")
            .authorization("Bearer token123");

        assert!(matches!(opts.body, InvokeBody::Json(_)));
        assert_eq!(opts.method, HttpMethod::Put);
        assert_eq!(opts.headers.get("x-custom"), Some(&"test".to_string()));
        assert_eq!(opts.region, Some(FunctionRegion::UsEast1));
        assert_eq!(opts.content_type, Some("text/plain".to_string()));
        assert_eq!(
            opts.authorization,
            Some("Bearer token123".to_string())
        );
    }

    #[test]
    fn invoke_options_body_bytes() {
        let opts = InvokeOptions::new().body_bytes(vec![1, 2, 3]);
        assert!(matches!(opts.body, InvokeBody::Bytes(ref b) if b == &[1, 2, 3]));
    }

    #[test]
    fn invoke_options_body_text() {
        let opts = InvokeOptions::new().body_text("hello");
        assert!(matches!(opts.body, InvokeBody::Text(ref s) if s == "hello"));
    }

    #[test]
    fn invoke_options_multiple_headers() {
        let mut extra = HashMap::new();
        extra.insert("a".into(), "1".into());
        extra.insert("b".into(), "2".into());
        let opts = InvokeOptions::new().header("x", "y").headers(extra);
        assert_eq!(opts.headers.len(), 3);
        assert_eq!(opts.headers.get("x"), Some(&"y".to_string()));
        assert_eq!(opts.headers.get("a"), Some(&"1".to_string()));
    }

    #[test]
    fn function_response_json() {
        let resp = FunctionResponse::new(
            200,
            HashMap::new(),
            br#"{"message":"hello"}"#.to_vec(),
        );
        let val: serde_json::Value = resp.json().unwrap();
        assert_eq!(val["message"], "hello");
    }

    #[test]
    fn function_response_text() {
        let resp = FunctionResponse::new(200, HashMap::new(), b"hello world".to_vec());
        assert_eq!(resp.text().unwrap(), "hello world");
    }

    #[test]
    fn function_response_bytes() {
        let data = vec![0, 1, 2, 255];
        let resp = FunctionResponse::new(200, HashMap::new(), data.clone());
        assert_eq!(resp.bytes(), &data);
    }

    #[test]
    fn function_response_header_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        headers.insert("x-custom".into(), "value".into());
        let resp = FunctionResponse::new(200, headers, vec![]);
        assert_eq!(resp.header("Content-Type"), Some("application/json"));
        assert_eq!(resp.header("X-Custom"), Some("value"));
        assert_eq!(resp.header("missing"), None);
    }

    #[test]
    fn function_response_content_type() {
        let mut headers = HashMap::new();
        headers.insert("content-type".into(), "text/plain".into());
        let resp = FunctionResponse::new(200, headers, vec![]);
        assert_eq!(resp.content_type(), Some("text/plain"));
    }

    #[test]
    fn function_response_status() {
        let resp = FunctionResponse::new(201, HashMap::new(), vec![]);
        assert_eq!(resp.status(), 201);
    }

    #[test]
    fn function_response_into_bytes() {
        let data = vec![10, 20, 30];
        let resp = FunctionResponse::new(200, HashMap::new(), data.clone());
        assert_eq!(resp.into_bytes(), data);
    }
}
