use std::fmt;

use base64::Engine;
use reqwest::header::HeaderValue;
use reqwest::Method;
use serde_json::json;
use url::Url;

use crate::client::StorageClient;
use crate::error::StorageError;
use crate::path::{bucket_segment, object_segments};
use crate::types::*;

/// File operations API scoped to a specific bucket.
///
/// Created via `StorageClient::from("bucket_name")`.
///
/// Object paths are split on `/` and each segment is percent-encoded, so
/// names may contain spaces, `?`, `#` or `%`. Paths with empty, `.` or `..`
/// segments are rejected with [`StorageError::InvalidPath`].
///
/// # Example
/// ```ignore
/// let file_api = storage.from("avatars");
/// file_api.upload("photo.png", data, FileOptions::new()).await?;
/// let bytes = file_api.download("photo.png").await?;
/// ```
#[derive(Clone)]
pub struct StorageBucketApi {
    client: StorageClient,
    bucket_id: String,
}

impl fmt::Debug for StorageBucketApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageBucketApi")
            .field("client", &self.client)
            .field("bucket_id", &self.bucket_id)
            .finish()
    }
}

impl StorageBucketApi {
    pub(crate) fn new(client: StorageClient, bucket_id: String) -> Self {
        Self { client, bucket_id }
    }

    /// URL for `<prefix...>/<bucket>/<path...>`, validating bucket and path.
    fn object_url(&self, prefix: &[&str], path: &str) -> Result<Url, StorageError> {
        let bucket = bucket_segment(&self.bucket_id)?;
        let mut segments: Vec<&str> = prefix.to_vec();
        segments.push(bucket);
        segments.extend(object_segments(path)?);
        Ok(self.client.endpoint(&segments))
    }

    /// URL for `<prefix...>/<bucket>`.
    fn bucket_url(&self, prefix: &[&str]) -> Result<Url, StorageError> {
        let bucket = bucket_segment(&self.bucket_id)?;
        let mut segments: Vec<&str> = prefix.to_vec();
        segments.push(bucket);
        Ok(self.client.endpoint(&segments))
    }

    /// Public-URL builder: like `object_url` but infallible. `.`/`..` and
    /// empty segments are dropped by `PathSegmentsMut::push`, so the result
    /// always stays under `<prefix>/<bucket>/`.
    fn public_url(&self, prefix: &[&str], path: &str) -> Url {
        let mut segments: Vec<&str> = prefix.to_vec();
        segments.push(&self.bucket_id);
        segments.extend(path.split('/').filter(|s| !s.is_empty()));
        self.client.endpoint(&segments)
    }

    fn apply_file_options(
        mut req: reqwest::RequestBuilder,
        opts: &FileOptions,
    ) -> Result<reqwest::RequestBuilder, StorageError> {
        if let Some(cache) = &opts.cache_control {
            req = req.header("cache-control", header_value(cache)?);
        }
        if let Some(upsert) = opts.upsert {
            req = req.header("x-upsert", if upsert { "true" } else { "false" });
        }
        if let Some(metadata) = &opts.metadata {
            req = req.header("x-metadata", encode_metadata(metadata)?);
        }
        Ok(req)
    }

    /// Upload a file to the bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket').upload(path, file, options)`.
    pub async fn upload(
        &self,
        path: &str,
        data: Vec<u8>,
        options: FileOptions,
    ) -> Result<UploadResponse, StorageError> {
        let url = self.object_url(&["object"], path)?;
        let content_type = options
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");

        let req = self
            .client
            .request(Method::POST, url)
            .header("content-type", header_value(content_type)?)
            .body(data);
        let req = Self::apply_file_options(req, &options)?;

        let resp = req.send().await?;
        self.client.handle_response(resp).await
    }

    /// Update (replace) a file in the bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket').update(path, file, options)`.
    pub async fn update(
        &self,
        path: &str,
        data: Vec<u8>,
        options: Option<FileOptions>,
    ) -> Result<UploadResponse, StorageError> {
        let url = self.object_url(&["object"], path)?;
        let opts = options.unwrap_or_default();
        let content_type = opts
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");

        let req = self
            .client
            .request(Method::PUT, url)
            .header("content-type", header_value(content_type)?)
            .body(data);
        let req = Self::apply_file_options(req, &opts)?;

        let resp = req.send().await?;
        self.client.handle_response(resp).await
    }

    /// Download a file from the bucket.
    ///
    /// Returns the raw file bytes. See
    /// [`StorageClient::with_max_download_size`] to bound the size.
    pub async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        let url = self.object_url(&["object"], path)?;
        let resp = self.client.request(Method::GET, url).send().await?;
        self.client.handle_bytes_response(resp).await
    }

    /// List files in the bucket.
    ///
    /// `path` is the folder prefix (e.g., `"folder"` or `None` for root).
    pub async fn list(
        &self,
        path: Option<&str>,
        options: Option<SearchOptions>,
    ) -> Result<Vec<FileObject>, StorageError> {
        let url = self.bucket_url(&["object", "list"])?;

        let mut body = json!({
            "prefix": path.unwrap_or(""),
        });

        if let Some(opts) = options {
            if let Some(limit) = opts.limit {
                body["limit"] = json!(limit);
            }
            if let Some(offset) = opts.offset {
                body["offset"] = json!(offset);
            }
            if let Some(sort_by) = opts.sort_by {
                body["sortBy"] = json!(sort_by);
            }
            if let Some(search) = opts.search {
                body["search"] = json!(search);
            }
        }

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        self.client.handle_response(resp).await
    }

    /// Move a file within the bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket').move(from, to)`.
    pub async fn move_file(&self, from: &str, to: &str) -> Result<(), StorageError> {
        let url = self.client.endpoint(&["object", "move"]);
        let body = json!({
            "bucketId": self.bucket_id,
            "sourceKey": from,
            "destinationKey": to,
        });

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        self.client.handle_empty_response(resp).await
    }

    /// Copy a file within the bucket.
    ///
    /// Returns the key of the new file.
    pub async fn copy(&self, from: &str, to: &str) -> Result<String, StorageError> {
        let url = self.client.endpoint(&["object", "copy"]);
        let body = json!({
            "bucketId": self.bucket_id,
            "sourceKey": from,
            "destinationKey": to,
        });

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        let result: serde_json::Value = self.client.handle_response(resp).await?;
        Ok(result
            .get("Key")
            .or_else(|| result.get("key"))
            .and_then(|v| v.as_str())
            .unwrap_or(to)
            .to_string())
    }

    /// Remove files from the bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket').remove([paths])`.
    pub async fn remove(&self, paths: Vec<&str>) -> Result<Vec<FileObject>, StorageError> {
        let url = self.bucket_url(&["object"])?;
        let body = json!({
            "prefixes": paths,
        });

        let resp = self
            .client
            .request(Method::DELETE, url)
            .json(&body)
            .send()
            .await?;
        self.client.handle_response(resp).await
    }

    /// Create a signed URL for time-limited access to a file.
    ///
    /// `expires_in` is the number of seconds until the URL expires.
    pub async fn create_signed_url(
        &self,
        path: &str,
        expires_in: u64,
    ) -> Result<SignedUrlResponse, StorageError> {
        let url = self.object_url(&["object", "sign"], path)?;
        let body = json!({ "expiresIn": expires_in });

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        let mut result: SignedUrlResponse = self.client.handle_response(resp).await?;
        result.signed_url = self.absolute(&result.signed_url);
        Ok(result)
    }

    /// Create signed URLs for multiple files.
    ///
    /// `expires_in` is the number of seconds until the URLs expire.
    pub async fn create_signed_urls(
        &self,
        paths: Vec<&str>,
        expires_in: u64,
    ) -> Result<Vec<SignedUrlBatchEntry>, StorageError> {
        let url = self.bucket_url(&["object", "sign"])?;
        let body = json!({
            "expiresIn": expires_in,
            "paths": paths,
        });

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        let mut results: Vec<SignedUrlBatchEntry> = self.client.handle_response(resp).await?;
        for entry in &mut results {
            if let Some(signed_url) = entry.signed_url.as_mut() {
                *signed_url = self.absolute(signed_url);
            }
        }
        Ok(results)
    }

    /// Prefix a server-relative signed URL with the storage base URL.
    fn absolute(&self, signed_url: &str) -> String {
        if signed_url.starts_with('/') {
            let base = self.client.base_url().as_str().trim_end_matches('/');
            format!("{}{}", base, signed_url)
        } else {
            signed_url.to_string()
        }
    }

    /// Get the public URL for a file (no HTTP call, just URL construction).
    ///
    /// Only works for files in public buckets. Each path segment is
    /// percent-encoded; empty, `.` and `..` segments are dropped.
    pub fn get_public_url(&self, path: &str) -> String {
        self.public_url(&["object", "public"], path).to_string()
    }

    /// Create a signed upload URL for delegated uploads.
    pub async fn create_signed_upload_url(
        &self,
        path: &str,
    ) -> Result<SignedUploadUrlResponse, StorageError> {
        let url = self.object_url(&["object", "upload", "sign"], path)?;
        let resp = self
            .client
            .request(Method::POST, url)
            .json(&json!({}))
            .send()
            .await?;
        self.client.handle_response(resp).await
    }

    /// Upload a file using a previously created signed upload URL.
    ///
    /// Transport errors are returned without the request URL, so the upload
    /// token does not end up in logs.
    pub async fn upload_to_signed_url(
        &self,
        token: &str,
        path: &str,
        data: Vec<u8>,
        options: Option<FileOptions>,
    ) -> Result<(), StorageError> {
        let mut url = self.object_url(&["object", "upload", "sign"], path)?;
        url.query_pairs_mut().append_pair("token", token);

        let opts = options.unwrap_or_default();
        let content_type = opts
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");

        let mut req = self
            .client
            .request(Method::PUT, url)
            .header("content-type", header_value(content_type)?)
            .body(data);

        if let Some(cache) = &opts.cache_control {
            req = req.header("cache-control", header_value(cache)?);
        }
        if let Some(upsert) = opts.upsert {
            req = req.header("x-upsert", if upsert { "true" } else { "false" });
        }

        let resp = req.send().await.map_err(|e| e.without_url())?;
        self.client.handle_empty_response(resp).await
    }

    /// Get file metadata.
    ///
    /// Mirrors `supabase.storage.from('bucket').info(path)`.
    pub async fn info(&self, path: &str) -> Result<FileInfo, StorageError> {
        let url = self.object_url(&["object", "info", "authenticated"], path)?;
        let resp = self.client.request(Method::GET, url).send().await?;
        self.client.handle_response(resp).await
    }

    /// Check if a file exists.
    ///
    /// Mirrors `supabase.storage.from('bucket').exists(path)`.
    /// Returns `true` if the file exists, `false` if it does not (404).
    pub async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        let url = self.object_url(&["object"], path)?;
        let resp = self.client.request(Method::HEAD, url).send().await?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(true)
        } else if status == 404 || status == 400 {
            Ok(false)
        } else {
            Err(StorageError::Api {
                status,
                message: format!("HTTP {}", status),
            })
        }
    }

    /// Download with server-side image transformation.
    ///
    /// Mirrors `supabase.storage.from('bucket').download(path, { transform })`.
    pub async fn download_with_transform(
        &self,
        path: &str,
        transform: &TransformOptions,
    ) -> Result<Vec<u8>, StorageError> {
        let mut url = self.object_url(&["render", "image", "authenticated"], path)?;
        set_transform_query(&mut url, transform);
        let resp = self.client.request(Method::GET, url).send().await?;
        self.client.handle_bytes_response(resp).await
    }

    /// Get public URL with image transformation (no HTTP call).
    ///
    /// Mirrors `supabase.storage.from('bucket').getPublicUrl(path, { transform })`.
    pub fn get_public_url_with_transform(&self, path: &str, transform: &TransformOptions) -> String {
        let mut url = self.public_url(&["render", "image", "public"], path);
        set_transform_query(&mut url, transform);
        url.to_string()
    }

    /// Create a signed URL with image transformation.
    ///
    /// Mirrors `supabase.storage.from('bucket').createSignedUrl(path, expiresIn, { transform })`.
    pub async fn create_signed_url_with_transform(
        &self,
        path: &str,
        expires_in: u64,
        transform: &TransformOptions,
    ) -> Result<SignedUrlResponse, StorageError> {
        let url = self.object_url(&["object", "sign"], path)?;
        let mut body = json!({ "expiresIn": expires_in });
        if !transform.is_empty() {
            body["transform"] = transform.to_json();
        }

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        let mut result: SignedUrlResponse = self.client.handle_response(resp).await?;
        result.signed_url = self.absolute(&result.signed_url);
        Ok(result)
    }

    /// Create batch signed URLs with image transformation.
    ///
    /// Mirrors `supabase.storage.from('bucket').createSignedUrls(paths, expiresIn, { transform })`.
    pub async fn create_signed_urls_with_transform(
        &self,
        paths: Vec<&str>,
        expires_in: u64,
        transform: &TransformOptions,
    ) -> Result<Vec<SignedUrlBatchEntry>, StorageError> {
        let url = self.bucket_url(&["object", "sign"])?;
        let mut body = json!({
            "expiresIn": expires_in,
            "paths": paths,
        });
        if !transform.is_empty() {
            body["transform"] = transform.to_json();
        }

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        let mut results: Vec<SignedUrlBatchEntry> = self.client.handle_response(resp).await?;
        for entry in &mut results {
            if let Some(signed_url) = entry.signed_url.as_mut() {
                *signed_url = self.absolute(signed_url);
            }
        }
        Ok(results)
    }

    /// Move a file to a different bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket').move(from, to, { destinationBucket })`.
    pub async fn move_to_bucket(
        &self,
        from: &str,
        to_bucket: &str,
        to_path: &str,
    ) -> Result<(), StorageError> {
        let url = self.client.endpoint(&["object", "move"]);
        let body = json!({
            "bucketId": self.bucket_id,
            "sourceKey": from,
            "destinationBucket": to_bucket,
            "destinationKey": to_path,
        });

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        self.client.handle_empty_response(resp).await
    }

    /// Copy a file to a different bucket.
    ///
    /// Returns the key of the new file.
    ///
    /// Mirrors `supabase.storage.from('bucket').copy(from, to, { destinationBucket })`.
    pub async fn copy_to_bucket(
        &self,
        from: &str,
        to_bucket: &str,
        to_path: &str,
    ) -> Result<String, StorageError> {
        let url = self.client.endpoint(&["object", "copy"]);
        let body = json!({
            "bucketId": self.bucket_id,
            "sourceKey": from,
            "destinationBucket": to_bucket,
            "destinationKey": to_path,
        });

        let resp = self
            .client
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await?;
        let result: serde_json::Value = self.client.handle_response(resp).await?;
        Ok(result
            .get("Key")
            .or_else(|| result.get("key"))
            .and_then(|v| v.as_str())
            .unwrap_or(to_path)
            .to_string())
    }

    /// Get a public URL with optional download disposition.
    ///
    /// When `filename` is `Some("file.txt")`, appends `?download=file.txt` to the URL.
    /// When `filename` is `Some("")`, appends `?download=` (uses original filename).
    /// The filename is form-encoded.
    ///
    /// Mirrors `supabase.storage.from('bucket').getPublicUrl(path, { download })`.
    pub fn get_public_url_with_download(&self, path: &str, filename: Option<&str>) -> String {
        let mut url = self.public_url(&["object", "public"], path);
        if let Some(name) = filename {
            url.query_pairs_mut().append_pair("download", name);
        }
        url.to_string()
    }

    /// Create a signed URL with optional download disposition.
    ///
    /// When `filename` is `Some("file.txt")`, appends `&download=file.txt` to the signed URL.
    /// When `filename` is `Some("")`, appends `&download=` (uses original filename).
    /// The filename is form-encoded.
    ///
    /// Mirrors `supabase.storage.from('bucket').createSignedUrl(path, expiresIn, { download })`.
    pub async fn create_signed_url_with_download(
        &self,
        path: &str,
        expires_in: u64,
        filename: Option<&str>,
    ) -> Result<SignedUrlResponse, StorageError> {
        let mut result = self.create_signed_url(path, expires_in).await?;
        if let Some(name) = filename {
            let separator = if result.signed_url.contains('?') {
                "&"
            } else {
                "?"
            };
            let encoded: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect();
            result.signed_url = format!("{}{}download={}", result.signed_url, separator, encoded);
        }
        Ok(result)
    }

    /// Get the bucket ID this API is scoped to.
    pub fn bucket_id(&self) -> &str {
        &self.bucket_id
    }
}

fn header_value(value: &str) -> Result<HeaderValue, StorageError> {
    HeaderValue::from_str(value)
        .map_err(|e| StorageError::InvalidConfig(format!("Invalid header value: {}", e)))
}

/// The storage server expects `x-metadata` to be base64 of the JSON text.
fn encode_metadata(metadata: &serde_json::Value) -> Result<HeaderValue, StorageError> {
    let json = serde_json::to_string(metadata)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(json);
    header_value(&encoded)
}

fn set_transform_query(url: &mut Url, transform: &TransformOptions) {
    let qs = transform.to_query_string();
    if !qs.is_empty() {
        url.set_query(Some(&qs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_base64_json() {
        let v = encode_metadata(&json!({"k": "v"})).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v.as_bytes())
            .unwrap();
        assert_eq!(decoded, br#"{"k":"v"}"#);
    }
}
