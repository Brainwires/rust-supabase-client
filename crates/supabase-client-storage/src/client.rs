use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde_json::json;
use url::Url;

use crate::bucket_api::StorageBucketApi;
use crate::error::{StorageApiErrorResponse, StorageError};
use crate::types::*;

/// HTTP client for Supabase Storage API.
///
/// Communicates with Storage REST endpoints at `/storage/v1/...`.
///
/// # Example
/// ```ignore
/// use supabase_client_storage::StorageClient;
///
/// let storage = StorageClient::new("https://your-project.supabase.co", "your-anon-key")?;
/// let buckets = storage.list_buckets().await?;
/// let file_api = storage.from("avatars");
/// ```
#[derive(Debug, Clone)]
pub struct StorageClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: String,
}

impl StorageClient {
    /// Create a new storage client.
    ///
    /// `supabase_url` is the project URL (e.g., `https://your-project.supabase.co`).
    /// `api_key` is the Supabase anon or service_role key.
    pub fn new(supabase_url: &str, api_key: &str) -> Result<Self, StorageError> {
        let base = supabase_url.trim_end_matches('/');
        let base_url = Url::parse(&format!("{}/storage/v1", base))?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            "apikey",
            HeaderValue::from_str(api_key)
                .map_err(|e| StorageError::InvalidConfig(format!("Invalid API key header: {}", e)))?,
        );
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))
                .map_err(|e| StorageError::InvalidConfig(format!("Invalid auth header: {}", e)))?,
        );
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .map_err(StorageError::Http)?;

        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
        })
    }

    /// Get the base URL for the storage API.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ─── Bucket Operations ───────────────────────────────────────

    /// List all buckets.
    pub async fn list_buckets(&self) -> Result<Vec<Bucket>, StorageError> {
        let url = self.url("/bucket");
        let resp = self.http.get(url).send().await?;
        self.handle_response(resp).await
    }

    /// Get a bucket by ID.
    pub async fn get_bucket(&self, id: &str) -> Result<Bucket, StorageError> {
        let url = self.url(&format!("/bucket/{}", id));
        let resp = self.http.get(url).send().await?;
        self.handle_response(resp).await
    }

    /// Create a new bucket.
    pub async fn create_bucket(
        &self,
        id: &str,
        options: BucketOptions,
    ) -> Result<CreateBucketResponse, StorageError> {
        let url = self.url("/bucket");
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

        let resp = self.http.post(url).json(&body).send().await?;
        self.handle_response(resp).await
    }

    /// Update a bucket.
    pub async fn update_bucket(
        &self,
        id: &str,
        options: BucketOptions,
    ) -> Result<(), StorageError> {
        let url = self.url(&format!("/bucket/{}", id));
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

        let resp = self.http.put(url).json(&body).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Empty a bucket (remove all files).
    pub async fn empty_bucket(&self, id: &str) -> Result<(), StorageError> {
        let url = self.url(&format!("/bucket/{}/empty", id));
        let resp = self.http.post(url).json(&json!({})).send().await?;
        self.handle_empty_response(resp).await
    }

    /// Delete a bucket. The bucket must be empty first.
    pub async fn delete_bucket(&self, id: &str) -> Result<(), StorageError> {
        let url = self.url(&format!("/bucket/{}", id));
        let resp = self.http.delete(url).json(&json!({})).send().await?;
        self.handle_empty_response(resp).await
    }

    // ─── File API Factory ────────────────────────────────────────

    /// Create a file operations API scoped to a bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket')`.
    pub fn from(&self, bucket: &str) -> StorageBucketApi {
        StorageBucketApi::new(self.clone(), bucket.to_string())
    }

    // ─── Internal Helpers ────────────────────────────────────────

    pub(crate) fn url(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        let current = url.path().to_string();
        if let Some(query_start) = path.find('?') {
            url.set_path(&format!("{}{}", current, &path[..query_start]));
            url.set_query(Some(&path[query_start + 1..]));
        } else {
            url.set_path(&format!("{}{}", current, path));
        }
        url
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
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
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    async fn parse_error(&self, status: u16, resp: reqwest::Response) -> StorageError {
        match resp.json::<StorageApiErrorResponse>().await {
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

        let url = client.url("/bucket");
        assert_eq!(url.path(), "/storage/v1/bucket");
        assert!(url.query().is_none());

        let url = client.url("/bucket/avatars");
        assert_eq!(url.path(), "/storage/v1/bucket/avatars");
    }

    #[test]
    fn url_building_with_query() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let url = client.url("/object/upload/sign/bucket/path?token=abc");
        assert_eq!(url.path(), "/storage/v1/object/upload/sign/bucket/path");
        assert_eq!(url.query(), Some("token=abc"));
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
}
