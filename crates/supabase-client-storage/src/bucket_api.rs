use reqwest::header::HeaderValue;
use serde_json::json;

use crate::client::StorageClient;
use crate::error::StorageError;
use crate::types::*;

/// File operations API scoped to a specific bucket.
///
/// Created via `StorageClient::from("bucket_name")`.
///
/// # Example
/// ```ignore
/// let file_api = storage.from("avatars");
/// file_api.upload("photo.png", data, FileOptions::new()).await?;
/// let bytes = file_api.download("photo.png").await?;
/// ```
#[derive(Debug, Clone)]
pub struct StorageBucketApi {
    client: StorageClient,
    bucket_id: String,
}

impl StorageBucketApi {
    pub(crate) fn new(client: StorageClient, bucket_id: String) -> Self {
        Self { client, bucket_id }
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
        let url = self
            .client
            .url(&format!("/object/{}/{}", self.bucket_id, path));

        let content_type = options
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");

        let mut req = self
            .client
            .http()
            .post(url)
            .header("content-type", content_type)
            .body(data);

        if let Some(cache) = &options.cache_control {
            req = req.header("cache-control", cache.as_str());
        }
        if let Some(upsert) = options.upsert {
            req = req.header("x-upsert", if upsert { "true" } else { "false" });
        }
        if let Some(metadata) = &options.metadata {
            let meta_str = serde_json::to_string(metadata)?;
            req = req.header("x-metadata", meta_str);
        }

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
        let url = self
            .client
            .url(&format!("/object/{}/{}", self.bucket_id, path));

        let opts = options.unwrap_or_default();
        let content_type = opts
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");

        let mut req = self
            .client
            .http()
            .put(url)
            .header("content-type", content_type)
            .body(data);

        if let Some(cache) = &opts.cache_control {
            req = req.header("cache-control", cache.as_str());
        }
        if let Some(upsert) = opts.upsert {
            req = req.header("x-upsert", if upsert { "true" } else { "false" });
        }
        if let Some(metadata) = &opts.metadata {
            let meta_str = serde_json::to_string(metadata)?;
            req = req.header("x-metadata", meta_str);
        }

        let resp = req.send().await?;
        self.client.handle_response(resp).await
    }

    /// Download a file from the bucket.
    ///
    /// Returns the raw file bytes.
    pub async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        let url = self
            .client
            .url(&format!("/object/{}/{}", self.bucket_id, path));
        let resp = self.client.http().get(url).send().await?;
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
        let url = self
            .client
            .url(&format!("/object/list/{}", self.bucket_id));

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

        let resp = self.client.http().post(url).json(&body).send().await?;
        self.client.handle_response(resp).await
    }

    /// Move a file within the bucket.
    ///
    /// Mirrors `supabase.storage.from('bucket').move(from, to)`.
    pub async fn move_file(&self, from: &str, to: &str) -> Result<(), StorageError> {
        let url = self.client.url("/object/move");
        let body = json!({
            "bucketId": self.bucket_id,
            "sourceKey": from,
            "destinationKey": to,
        });

        let resp = self.client.http().post(url).json(&body).send().await?;
        self.client.handle_empty_response(resp).await
    }

    /// Copy a file within the bucket.
    ///
    /// Returns the key of the new file.
    pub async fn copy(&self, from: &str, to: &str) -> Result<String, StorageError> {
        let url = self.client.url("/object/copy");
        let body = json!({
            "bucketId": self.bucket_id,
            "sourceKey": from,
            "destinationKey": to,
        });

        let resp = self.client.http().post(url).json(&body).send().await?;
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
        let url = self
            .client
            .url(&format!("/object/{}", self.bucket_id));
        let body = json!({
            "prefixes": paths,
        });

        let resp = self.client.http().delete(url).json(&body).send().await?;
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
        let url = self
            .client
            .url(&format!("/object/sign/{}/{}", self.bucket_id, path));
        let body = json!({ "expiresIn": expires_in });

        let resp = self.client.http().post(url).json(&body).send().await?;
        let mut result: SignedUrlResponse = self.client.handle_response(resp).await?;

        // Prepend base URL if the signed URL is relative
        if result.signed_url.starts_with('/') {
            let base = self.client.base_url().as_str().trim_end_matches('/');
            result.signed_url = format!("{}{}", base, result.signed_url);
        }

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
        let url = self
            .client
            .url(&format!("/object/sign/{}", self.bucket_id));
        let body = json!({
            "expiresIn": expires_in,
            "paths": paths,
        });

        let resp = self.client.http().post(url).json(&body).send().await?;
        let mut results: Vec<SignedUrlBatchEntry> = self.client.handle_response(resp).await?;

        // Prepend base URL to any relative signed URLs
        let base = self.client.base_url().as_str().trim_end_matches('/');
        for entry in &mut results {
            if let Some(ref mut signed_url) = entry.signed_url {
                if signed_url.starts_with('/') {
                    *signed_url = format!("{}{}", base, signed_url);
                }
            }
        }

        Ok(results)
    }

    /// Get the public URL for a file (no HTTP call, just URL construction).
    ///
    /// Only works for files in public buckets.
    pub fn get_public_url(&self, path: &str) -> String {
        let base = self.client.base_url().as_str().trim_end_matches('/');
        format!("{}/object/public/{}/{}", base, self.bucket_id, path)
    }

    /// Create a signed upload URL for delegated uploads.
    pub async fn create_signed_upload_url(
        &self,
        path: &str,
    ) -> Result<SignedUploadUrlResponse, StorageError> {
        let url = self.client.url(&format!(
            "/object/upload/sign/{}/{}",
            self.bucket_id, path
        ));

        let resp = self
            .client
            .http()
            .post(url)
            .json(&json!({}))
            .send()
            .await?;
        self.client.handle_response(resp).await
    }

    /// Upload a file using a previously created signed upload URL.
    pub async fn upload_to_signed_url(
        &self,
        token: &str,
        path: &str,
        data: Vec<u8>,
        options: Option<FileOptions>,
    ) -> Result<(), StorageError> {
        let url = self.client.url(&format!(
            "/object/upload/sign/{}/{}?token={}",
            self.bucket_id, path, token
        ));

        let opts = options.unwrap_or_default();
        let content_type = opts
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");

        let mut req = self
            .client
            .http()
            .put(url)
            .header("content-type", content_type)
            .body(data);

        if let Some(cache) = &opts.cache_control {
            req = req.header(
                "cache-control",
                HeaderValue::from_str(cache)
                    .map_err(|e| StorageError::InvalidConfig(format!("Invalid header: {}", e)))?,
            );
        }

        let resp = req.send().await?;
        self.client.handle_empty_response(resp).await
    }

    /// Get file metadata.
    ///
    /// Mirrors `supabase.storage.from('bucket').info(path)`.
    pub async fn info(&self, path: &str) -> Result<FileInfo, StorageError> {
        let url = self.client.url(&format!(
            "/object/info/authenticated/{}/{}",
            self.bucket_id, path
        ));
        let resp = self.client.http().get(url).send().await?;
        self.client.handle_response(resp).await
    }

    /// Check if a file exists.
    ///
    /// Mirrors `supabase.storage.from('bucket').exists(path)`.
    /// Returns `true` if the file exists, `false` if it does not (404).
    pub async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        let url = self
            .client
            .url(&format!("/object/{}/{}", self.bucket_id, path));
        let resp = self.client.http().head(url).send().await?;
        let status = resp.status().as_u16();
        if status >= 200 && status < 300 {
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
        let qs = transform.to_query_string();
        let url_path = if qs.is_empty() {
            format!(
                "/render/image/authenticated/{}/{}",
                self.bucket_id, path
            )
        } else {
            format!(
                "/render/image/authenticated/{}/{}?{}",
                self.bucket_id, path, qs
            )
        };
        let url = self.client.url(&url_path);
        let resp = self.client.http().get(url).send().await?;
        self.client.handle_bytes_response(resp).await
    }

    /// Get public URL with image transformation (no HTTP call).
    ///
    /// Mirrors `supabase.storage.from('bucket').getPublicUrl(path, { transform })`.
    pub fn get_public_url_with_transform(
        &self,
        path: &str,
        transform: &TransformOptions,
    ) -> String {
        let base = self.client.base_url().as_str().trim_end_matches('/');
        let qs = transform.to_query_string();
        if qs.is_empty() {
            format!(
                "{}/render/image/public/{}/{}",
                base, self.bucket_id, path
            )
        } else {
            format!(
                "{}/render/image/public/{}/{}?{}",
                base, self.bucket_id, path, qs
            )
        }
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
        let url = self
            .client
            .url(&format!("/object/sign/{}/{}", self.bucket_id, path));
        let mut body = json!({ "expiresIn": expires_in });
        if !transform.is_empty() {
            body["transform"] = transform.to_json();
        }

        let resp = self.client.http().post(url).json(&body).send().await?;
        let mut result: SignedUrlResponse = self.client.handle_response(resp).await?;

        if result.signed_url.starts_with('/') {
            let base = self.client.base_url().as_str().trim_end_matches('/');
            result.signed_url = format!("{}{}", base, result.signed_url);
        }

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
        let url = self
            .client
            .url(&format!("/object/sign/{}", self.bucket_id));
        let mut body = json!({
            "expiresIn": expires_in,
            "paths": paths,
        });
        if !transform.is_empty() {
            body["transform"] = transform.to_json();
        }

        let resp = self.client.http().post(url).json(&body).send().await?;
        let mut results: Vec<SignedUrlBatchEntry> = self.client.handle_response(resp).await?;

        let base = self.client.base_url().as_str().trim_end_matches('/');
        for entry in &mut results {
            if let Some(ref mut signed_url) = entry.signed_url {
                if signed_url.starts_with('/') {
                    *signed_url = format!("{}{}", base, signed_url);
                }
            }
        }

        Ok(results)
    }

    /// Get the bucket ID this API is scoped to.
    pub fn bucket_id(&self) -> &str {
        &self.bucket_id
    }
}
