use std::fmt;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde_json::json;
use supabase_client_core::http::{
    bearer_header, read_body_limited, read_error_body, sensitive_header, BodyReadError,
};
use supabase_client_core::AccessToken;
use url::Url;

use crate::bucket_api::StorageBucketApi;
use crate::error::{StorageApiErrorResponse, StorageError};
use crate::path::bucket_segment;
use crate::types::*;

/// HTTP client for Supabase Storage API.
///
/// Communicates with Storage REST endpoints at `/storage/v1/...`.
///
/// Requests are authorized with, in order of preference: the token passed to
/// [`set_auth`](StorageClient::set_auth), the signed-in user's JWT (when the
/// client was created from a `SupabaseClient` whose auth client has a
/// session), or the API key.
///
/// `Debug` output never includes the API key or tokens.
///
/// # Example
/// ```ignore
/// use supabase_client_storage::StorageClient;
///
/// let storage = StorageClient::new("https://your-project.supabase.co", "your-anon-key")?;
/// let buckets = storage.list_buckets().await?;
/// let file_api = storage.from("avatars");
/// ```
#[derive(Clone)]
pub struct StorageClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
    /// Token set with `set_auth`. Shared by clones (and bucket APIs).
    auth_override: AccessToken,
    /// Session token shared with a `SupabaseClient`, if wired up.
    session_token: Option<AccessToken>,
    max_download_bytes: Option<u64>,
    timeout: Option<Duration>,
}

impl fmt::Debug for StorageClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageClient")
            .field("base_url", &self.base_url.as_str())
            .field("api_key", &"[redacted]")
            .field("auth_override", &self.auth_override)
            .field("session_token", &self.session_token)
            .field("max_download_bytes", &self.max_download_bytes)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl StorageClient {
    /// Create a new storage client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon or service_role key.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, StorageError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/storage/v1", base))?;
        if base_url.cannot_be_a_base() {
            return Err(StorageError::InvalidConfig(format!(
                "supabase_url cannot be used as a base URL: {}",
                supabase_url
            )));
        }
        supabase_client_core::keys::warn_if_privileged_on_wasm(api_key, "storage");

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            sensitive_header(api_key).map_err(|e| {
                StorageError::InvalidConfig(format!("Invalid API key header: {}", e))
            })?,
        );
        default_headers.insert(
            AUTHORIZATION,
            bearer_header(api_key)
                .map_err(|e| StorageError::InvalidConfig(format!("Invalid auth header: {}", e)))?,
        );
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let builder = reqwest::Client::builder().default_headers(default_headers);
        // reqwest's wasm backend has no connect timeout
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.connect_timeout(std::time::Duration::from_secs(10));
        let http = builder.build().map_err(StorageError::Http)?;

        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
            auth_override: AccessToken::new(),
            session_token: None,
            max_download_bytes: None,
            timeout: None,
        })
    }

    /// Follow a shared session token (see `SupabaseClient::access_token_handle`).
    ///
    /// While the slot holds a user JWT, requests use it as the bearer token
    /// (unless [`set_auth`](Self::set_auth) overrides it).
    pub fn with_session_token(mut self, token: AccessToken) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Use `token` (normally a user JWT) as the bearer token for subsequent
    /// requests, so storage policies see the user instead of the API key.
    ///
    /// Clones of this client, and bucket APIs created with [`from`](Self::from),
    /// share the setting.
    ///
    /// Mirrors `supabase.storage.setAuth(token)` (`new StorageClient(url, { Authorization })` in JS).
    pub fn set_auth(&self, token: &str) {
        self.auth_override.set(token);
    }

    /// Remove a token set with [`set_auth`](Self::set_auth).
    pub fn clear_auth(&self) {
        self.auth_override.clear();
    }

    /// Fail downloads larger than `max_bytes` with
    /// [`StorageError::ResponseTooLarge`] instead of buffering them. `None`
    /// (the default) means no limit.
    pub fn with_max_download_size(mut self, max_bytes: Option<u64>) -> Self {
        self.max_download_bytes = max_bytes;
        self
    }

    /// Set a total timeout for each request (native targets only; ignored on
    /// wasm32). There is no total timeout by default, only a 10 s connect
    /// timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Get the base URL for the storage API.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ─── Bucket Operations ───────────────────────────────────────

    /// List all buckets.
    pub async fn list_buckets(&self) -> Result<Vec<Bucket>, StorageError> {
        let url = self.endpoint(&["bucket"]);
        let resp = self.request(Method::GET, url).send().await?;
        self.handle_response(resp).await
    }

    /// Get a bucket by ID.
    pub async fn get_bucket(&self, id: &str) -> Result<Bucket, StorageError> {
        let url = self.endpoint(&["bucket", bucket_segment(id)?]);
        let resp = self.request(Method::GET, url).send().await?;
        self.handle_response(resp).await
    }

    /// Create a new bucket.
    pub async fn create_bucket(
        &self,
        id: &str,
        options: BucketOptions,
    ) -> Result<CreateBucketResponse, StorageError> {
        let url = self.endpoint(&["bucket"]);
        let body = bucket_body(id, options);
        let resp = self.request(Method::POST, url).json(&body).send().await?;
        self.handle_response(resp).await
    }

    /// Update a bucket.
    pub async fn update_bucket(&self, id: &str, options: BucketOptions) -> Result<(), StorageError> {
        let url = self.endpoint(&["bucket", bucket_segment(id)?]);
        let body = bucket_body(id, options);
        let resp = self.request(Method::PUT, url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Empty a bucket (remove all files).
    pub async fn empty_bucket(&self, id: &str) -> Result<(), StorageError> {
        let url = self.endpoint(&["bucket", bucket_segment(id)?, "empty"]);
        let resp = self
            .request(Method::POST, url)
            .json(&json!({}))
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    /// Delete a bucket. The bucket must be empty first.
    pub async fn delete_bucket(&self, id: &str) -> Result<(), StorageError> {
        let url = self.endpoint(&["bucket", bucket_segment(id)?]);
        let resp = self
            .request(Method::DELETE, url)
            .json(&json!({}))
            .send()
            .await?;
        self.handle_empty_response(resp).await
    }

    // ─── File API Factory ────────────────────────────────────────

    /// Create a file operations API scoped to a bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket')`. The bucket id is validated
    /// when a request is made.
    pub fn from(&self, bucket: &str) -> StorageBucketApi {
        StorageBucketApi::new(self.clone(), bucket.to_string())
    }

    // ─── Internal Helpers ────────────────────────────────────────

    /// Build `base_url/seg1/seg2/...`, percent-encoding each segment.
    ///
    /// Segments must already be validated: `PathSegmentsMut::push` silently
    /// drops `.` and `..`, and callers reject those up front so a request can
    /// never be redirected to a different endpoint.
    pub(crate) fn endpoint(&self, segments: &[&str]) -> Url {
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
        url
    }

    /// Start a request with the right `Authorization` header.
    pub(crate) fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        let token = self
            .auth_override
            .get()
            .or_else(|| self.session_token.as_ref().and_then(|t| t.get()));
        if let Some(token) = token {
            if let Ok(v) = bearer_header(&token) {
                req = req.header(AUTHORIZATION, v);
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(t) = self.timeout {
            req = req.timeout(t);
        }
        req
    }

    #[allow(dead_code)]
    pub(crate) fn api_key(&self) -> &str {
        &self.api_key
    }

    pub(crate) async fn handle_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, StorageError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        let body: T = resp.json().await?;
        Ok(body)
    }

    pub(crate) async fn handle_empty_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<(), StorageError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        Ok(())
    }

    pub(crate) async fn handle_bytes_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<Vec<u8>, StorageError> {
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(self.parse_error(status, resp).await);
        }
        read_body_limited(resp, self.max_download_bytes)
            .await
            .map_err(|e| match e {
                BodyReadError::Http(e) => StorageError::Http(e),
                BodyReadError::TooLarge { limit } => StorageError::ResponseTooLarge { limit },
            })
    }

    pub(crate) async fn parse_error(&self, status: u16, resp: reqwest::Response) -> StorageError {
        let body = read_error_body(resp).await;
        match serde_json::from_slice::<StorageApiErrorResponse>(&body) {
            Ok(err_resp) => StorageError::Api {
                status,
                message: err_resp.error_message(),
            },
            Err(_) => StorageError::Api {
                status,
                message: format!("HTTP {}", status),
            },
        }
    }
}

fn bucket_body(id: &str, options: BucketOptions) -> serde_json::Value {
    let mut body = json!({
        "id": id,
        "name": id,
    });
    if let Some(public) = options.public {
        body["public"] = json!(public);
    }
    if let Some(limit) = options.file_size_limit {
        body["file_size_limit"] = json!(limit);
    }
    if let Some(types) = options.allowed_mime_types {
        body["allowed_mime_types"] = json!(types);
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_ok() {
        let client = StorageClient::new("https://example.supabase.co", "test-key");
        assert!(client.is_ok());
    }

    #[test]
    fn client_base_url() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/storage/v1");
    }

    #[test]
    fn client_base_url_trailing_slash() {
        let client = StorageClient::new("https://example.supabase.co/", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/storage/v1");
    }

    #[test]
    fn url_building() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();

        let url = client.endpoint(&["bucket"]);
        assert_eq!(url.path(), "/storage/v1/bucket");
        assert!(url.query().is_none());

        let url = client.endpoint(&["bucket", "avatars"]);
        assert_eq!(url.path(), "/storage/v1/bucket/avatars");
    }

    #[test]
    fn url_building_encodes_segments() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client.endpoint(&["object", "b", "a b?x=1#y"]);
        assert_eq!(url.path(), "/storage/v1/object/b/a%20b%3Fx=1%23y");
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn public_url_construction() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("avatars");
        let url = api.get_public_url("folder/photo.png");
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/object/public/avatars/folder/photo.png"
        );
    }

    #[test]
    fn public_url_with_transform_all_options() {
        use crate::types::{TransformOptions, ResizeMode, ImageFormat};

        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("photos");
        let transform = TransformOptions::new()
            .width(200)
            .height(150)
            .resize(ResizeMode::Cover)
            .quality(80)
            .format(ImageFormat::Origin);
        let url = api.get_public_url_with_transform("photo.jpg", &transform);
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/render/image/public/photos/photo.jpg?width=200&height=150&resize=cover&quality=80&format=origin"
        );
    }

    #[test]
    fn public_url_with_transform_partial() {
        use crate::types::TransformOptions;

        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("photos");
        let transform = TransformOptions::new().width(300);
        let url = api.get_public_url_with_transform("img.png", &transform);
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/render/image/public/photos/img.png?width=300"
        );
    }

    #[test]
    fn public_url_with_empty_transform() {
        use crate::types::TransformOptions;

        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("photos");
        let transform = TransformOptions::default();
        let url = api.get_public_url_with_transform("img.png", &transform);
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/render/image/public/photos/img.png"
        );
    }

    // ─── Phase 10: Download URL Tests ────────────────────────

    #[test]
    fn public_url_with_download_filename() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("docs");
        let url = api.get_public_url_with_download("report.pdf", Some("my-report.pdf"));
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/object/public/docs/report.pdf?download=my-report.pdf"
        );
    }

    #[test]
    fn public_url_with_download_default() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("docs");
        let url = api.get_public_url_with_download("report.pdf", Some(""));
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/object/public/docs/report.pdf?download="
        );
    }

    #[test]
    fn public_url_with_download_none() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("docs");
        let url = api.get_public_url_with_download("report.pdf", None);
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/object/public/docs/report.pdf"
        );
    }

    // ─── Wiremock Tests ──────────────────────────────────────

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: create a StorageClient pointing at the given mock server.
    fn mock_client(server: &MockServer) -> StorageClient {
        StorageClient::new(&server.uri(), "test-anon-key").unwrap()
    }

    #[tokio::test]
    async fn wiremock_exists_returns_false_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/storage/v1/object/avatars/missing.png"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let api = client.from("avatars");
        let exists = api.exists("missing.png").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn wiremock_exists_returns_false_on_400() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/storage/v1/object/avatars/bad-path"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let api = client.from("avatars");
        let exists = api.exists("bad-path").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn wiremock_exists_returns_true_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/storage/v1/object/avatars/photo.png"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let api = client.from("avatars");
        let exists = api.exists("photo.png").await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn wiremock_exists_returns_error_on_500() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/storage/v1/object/avatars/error.png"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let api = client.from("avatars");
        let err = api.exists("error.png").await.unwrap_err();
        match err {
            StorageError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wiremock_list_buckets_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/bucket"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({"message": "Forbidden"})),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let err = client.list_buckets().await.unwrap_err();
        match err {
            StorageError::Api { status, message } => {
                assert_eq!(status, 403);
                assert_eq!(message, "Forbidden");
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wiremock_download_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/object/docs/secret.pdf"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"message": "Unauthorized"})),
            )
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let api = client.from("docs");
        let err = api.download("secret.pdf").await.unwrap_err();
        match err {
            StorageError::Api { status, message } => {
                assert_eq!(status, 401);
                assert_eq!(message, "Unauthorized");
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn wiremock_delete_bucket_error_non_json() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/storage/v1/bucket/locked"))
            .respond_with(ResponseTemplate::new(409).set_body_string("conflict"))
            .mount(&server)
            .await;

        let client = mock_client(&server);
        let err = client.delete_bucket("locked").await.unwrap_err();
        match err {
            StorageError::Api { status, message } => {
                assert_eq!(status, 409);
                // Falls back to "HTTP 409" when JSON parsing fails
                assert_eq!(message, "HTTP 409");
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }
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
    async fn regression_object_path_traversal_is_rejected() {
        let s = catch_all().await;
        let st = StorageClient::new(&s.uri(), "SERVICE_ROLE_KEY").unwrap();
        let err = st
            .from("avatars")
            .download("../../../../rest/v1/secrets?select=*")
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidPath(_)), "{:?}", err);
        for bad in ["a/../b", "./a", "a//b", "/a", ""] {
            let err = st.from("avatars").download(bad).await.unwrap_err();
            assert!(matches!(err, StorageError::InvalidPath(_)), "{bad}: {err:?}");
        }
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn regression_bucket_id_traversal_is_rejected() {
        let s = catch_all().await;
        let st = StorageClient::new(&s.uri(), "SERVICE_ROLE_KEY").unwrap();
        let err = st
            .delete_bucket("../../../rest/v1/profiles?id=not.is.null")
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidPath(_)), "{:?}", err);
        let err = st.from("..").download("x").await.unwrap_err();
        assert!(matches!(err, StorageError::InvalidPath(_)), "{:?}", err);
        let err = st.from("..").list(None, None).await.unwrap_err();
        assert!(matches!(err, StorageError::InvalidPath(_)), "{:?}", err);
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn regression_path_with_hash_space_and_percent_is_encoded() {
        let s = catch_all().await;
        let st = StorageClient::new(&s.uri(), "k").unwrap();
        let _ = st.from("b").download("dir/a b#c%2F.png").await;
        let reqs = s.received_requests().await.unwrap();
        let r = reqs.last().unwrap();
        assert_eq!(r.url.path(), "/storage/v1/object/b/dir/a%20b%23c%252F.png");
        assert!(r.url.query().is_none());
    }

    #[test]
    fn regression_public_urls_are_encoded() {
        let st = StorageClient::new("https://x.supabase.co", "k").unwrap();
        assert_eq!(
            st.from("b").get_public_url("a b?x=1#y"),
            "https://x.supabase.co/storage/v1/object/public/b/a%20b%3Fx=1%23y"
        );
        assert_eq!(
            st.from("b")
                .get_public_url_with_download("f.pdf", Some("x&token=evil")),
            "https://x.supabase.co/storage/v1/object/public/b/f.pdf?download=x%26token%3Devil"
        );
        // Dot segments can never climb out of the bucket prefix.
        assert_eq!(
            st.from("b").get_public_url("../../../auth/v1/x"),
            "https://x.supabase.co/storage/v1/object/public/b/auth/v1/x"
        );
    }

    #[test]
    fn regression_debug_does_not_leak_keys() {
        let st = StorageClient::new("https://x.supabase.co", "SECRET-SERVICE-KEY").unwrap();
        st.set_auth("USER-JWT-SECRET");
        let ds = format!("{:?} {:?}", st, st.from("b"));
        assert!(!ds.contains("SECRET-SERVICE-KEY"), "{}", ds);
        assert!(!ds.contains("USER-JWT-SECRET"), "{}", ds);
    }

    #[tokio::test]
    async fn regression_metadata_header_is_base64() {
        let s = catch_all().await;
        let st = StorageClient::new(&s.uri(), "k").unwrap();
        let _ = st
            .from("b")
            .upload(
                "f.txt",
                b"x".to_vec(),
                FileOptions::new().metadata(serde_json::json!({"k":"v"})),
            )
            .await;
        let reqs = s.received_requests().await.unwrap();
        let r = reqs.last().unwrap();
        // base64(`{"k":"v"}`)
        assert_eq!(
            r.headers.get("x-metadata").unwrap().to_str().unwrap(),
            "eyJrIjoidiJ9"
        );
    }

    #[tokio::test]
    async fn regression_upload_to_signed_url_encodes_token() {
        let s = catch_all().await;
        let st = StorageClient::new(&s.uri(), "k").unwrap();
        st.from("b")
            .upload_to_signed_url("t&upsert=true#x", "f.txt", b"x".to_vec(), None)
            .await
            .unwrap();
        let reqs = s.received_requests().await.unwrap();
        let r = reqs.last().unwrap();
        assert_eq!(r.url.path(), "/storage/v1/object/upload/sign/b/f.txt");
        let pairs: Vec<(String, String)> = r.url.query_pairs().into_owned().collect();
        assert_eq!(pairs, vec![("token".into(), "t&upsert=true#x".into())]);
    }

    #[tokio::test]
    async fn regression_signed_url_error_does_not_leak_token() {
        // Nothing listens on port 9 (discard) on localhost.
        let st = StorageClient::new("http://127.0.0.1:9", "k").unwrap();
        let err = st
            .from("b")
            .upload_to_signed_url("SIGNED-TOKEN", "f.txt", b"x".to_vec(), None)
            .await
            .unwrap_err();
        assert!(!err.to_string().contains("SIGNED-TOKEN"), "{}", err);
        assert!(!format!("{:?}", err).contains("SIGNED-TOKEN"), "{:?}", err);
    }

    #[tokio::test]
    async fn set_auth_overrides_bearer_and_keeps_apikey() {
        let s = catch_all().await;
        let st = StorageClient::new(&s.uri(), "anon-key").unwrap();
        let _ = st.list_buckets().await;
        st.set_auth("user-jwt");
        let _ = st.from("b").download("f").await;
        st.clear_auth();
        let _ = st.list_buckets().await;
        let reqs = s.received_requests().await.unwrap();
        let auth: Vec<&str> = reqs
            .iter()
            .map(|r| r.headers.get("authorization").unwrap().to_str().unwrap())
            .collect();
        assert_eq!(auth, vec!["Bearer anon-key", "Bearer user-jwt", "Bearer anon-key"]);
        for r in &reqs {
            assert_eq!(r.headers.get("apikey").unwrap(), "anon-key");
        }
    }

    #[tokio::test]
    async fn session_token_is_followed() {
        let s = catch_all().await;
        let slot = supabase_client_core::AccessToken::new();
        let st = StorageClient::new(&s.uri(), "anon-key")
            .unwrap()
            .with_session_token(slot.clone());
        slot.set("session-jwt");
        let _ = st.list_buckets().await;
        st.set_auth("explicit");
        let _ = st.list_buckets().await;
        let reqs = s.received_requests().await.unwrap();
        assert_eq!(reqs[0].headers.get("authorization").unwrap(), "Bearer session-jwt");
        assert_eq!(reqs[1].headers.get("authorization").unwrap(), "Bearer explicit");
    }

    #[tokio::test]
    async fn download_size_cap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/object/b/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 4096]))
            .mount(&server)
            .await;
        let st = StorageClient::new(&server.uri(), "k")
            .unwrap()
            .with_max_download_size(Some(1024));
        let err = st.from("b").download("big").await.unwrap_err();
        assert!(matches!(err, StorageError::ResponseTooLarge { limit: 1024 }), "{:?}", err);
        let st = st.with_max_download_size(Some(4096));
        assert_eq!(st.from("b").download("big").await.unwrap().len(), 4096);
    }

    #[tokio::test]
    async fn error_with_numeric_status_code_is_parsed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/bucket/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                serde_json::json!({"statusCode": 404, "error": "not_found", "message": "Bucket not found"}),
            ))
            .mount(&server)
            .await;
        let st = StorageClient::new(&server.uri(), "k").unwrap();
        match st.get_bucket("missing").await.unwrap_err() {
            StorageError::Api { status, message } => {
                assert_eq!(status, 404);
                assert_eq!(message, "Bucket not found");
            }
            other => panic!("{:?}", other),
        }
    }
}
