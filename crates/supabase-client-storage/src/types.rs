use serde::{Deserialize, Serialize};

/// A storage bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub file_size_limit: Option<i64>,
    #[serde(default)]
    pub allowed_mime_types: Option<Vec<String>>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Options for creating or updating a bucket.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BucketOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size_limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_mime_types: Option<Vec<String>>,
}

impl BucketOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn public(mut self, public: bool) -> Self {
        self.public = Some(public);
        self
    }

    pub fn file_size_limit(mut self, limit: i64) -> Self {
        self.file_size_limit = Some(limit);
        self
    }

    pub fn allowed_mime_types(mut self, types: Vec<String>) -> Self {
        self.allowed_mime_types = Some(types);
        self
    }
}

/// A file object returned from list/remove operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileObject {
    pub name: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_accessed_at: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Options for file upload/update.
#[derive(Debug, Clone, Default)]
pub struct FileOptions {
    pub cache_control: Option<String>,
    pub content_type: Option<String>,
    pub upsert: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}

impl FileOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cache_control(mut self, value: &str) -> Self {
        self.cache_control = Some(value.to_string());
        self
    }

    pub fn content_type(mut self, value: &str) -> Self {
        self.content_type = Some(value.to_string());
        self
    }

    pub fn upsert(mut self, value: bool) -> Self {
        self.upsert = Some(value);
        self
    }

    pub fn metadata(mut self, value: serde_json::Value) -> Self {
        self.metadata = Some(value);
        self
    }
}

/// Options for listing files in a bucket.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SearchOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "sortBy")]
    pub sort_by: Option<SortBy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
}

impl SearchOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn sort_by(mut self, column: &str, order: SortOrder) -> Self {
        self.sort_by = Some(SortBy {
            column: column.to_string(),
            order: order.as_str().to_string(),
        });
        self
    }

    pub fn search(mut self, search: &str) -> Self {
        self.search = Some(search.to_string());
        self
    }
}

/// Sort configuration for file listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortBy {
    pub column: String,
    pub order: String,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

impl SortOrder {
    pub fn as_str(&self) -> &str {
        match self {
            SortOrder::Asc => "asc",
            SortOrder::Desc => "desc",
        }
    }
}

impl std::fmt::Display for SortOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Response from upload/update operations.
#[derive(Debug, Clone, Deserialize)]
pub struct UploadResponse {
    #[serde(default, rename = "Id")]
    pub id: Option<String>,
    #[serde(default, rename = "Key")]
    pub key: Option<String>,
}

/// Response from create_signed_url.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedUrlResponse {
    #[serde(rename = "signedURL")]
    pub signed_url: String,
}

/// Entry in a batch signed URL response.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedUrlBatchEntry {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, rename = "signedURL")]
    pub signed_url: Option<String>,
}

/// Response from create_signed_upload_url.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedUploadUrlResponse {
    #[serde(default)]
    pub url: Option<String>,
    pub token: String,
    #[serde(default)]
    pub path: Option<String>,
}

/// Response from bucket creation.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateBucketResponse {
    pub name: String,
}

/// Image resize mode for transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeMode {
    /// Crop to fit exact dimensions (default).
    Cover,
    /// Scale down to fit within dimensions, preserving aspect ratio.
    Contain,
    /// Stretch to fill exact dimensions.
    Fill,
}

impl ResizeMode {
    pub fn as_str(&self) -> &str {
        match self {
            ResizeMode::Cover => "cover",
            ResizeMode::Contain => "contain",
            ResizeMode::Fill => "fill",
        }
    }
}

impl std::fmt::Display for ResizeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Image output format for transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// Keep original format.
    Origin,
}

impl ImageFormat {
    pub fn as_str(&self) -> &str {
        match self {
            ImageFormat::Origin => "origin",
        }
    }
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options for server-side image transformation.
///
/// Matches the `transform` option in Supabase JS `download()`, `getPublicUrl()`,
/// `createSignedUrl()`, and `createSignedUrls()`.
#[derive(Debug, Clone, Default)]
pub struct TransformOptions {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub resize: Option<ResizeMode>,
    pub quality: Option<u8>,
    pub format: Option<ImageFormat>,
}

impl TransformOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn width(mut self, width: u32) -> Self {
        self.width = Some(width);
        self
    }

    pub fn height(mut self, height: u32) -> Self {
        self.height = Some(height);
        self
    }

    pub fn resize(mut self, resize: ResizeMode) -> Self {
        self.resize = Some(resize);
        self
    }

    pub fn quality(mut self, quality: u8) -> Self {
        self.quality = Some(quality);
        self
    }

    pub fn format(mut self, format: ImageFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Build a query string from the transform options.
    ///
    /// Returns an empty string if no options are set.
    pub fn to_query_string(&self) -> String {
        let mut params = Vec::new();
        if let Some(w) = self.width {
            params.push(format!("width={}", w));
        }
        if let Some(h) = self.height {
            params.push(format!("height={}", h));
        }
        if let Some(r) = &self.resize {
            params.push(format!("resize={}", r));
        }
        if let Some(q) = self.quality {
            params.push(format!("quality={}", q));
        }
        if let Some(f) = &self.format {
            params.push(format!("format={}", f));
        }
        params.join("&")
    }

    /// Convert to a JSON value for inclusion in signed URL request bodies.
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        if let Some(w) = self.width {
            map.insert("width".into(), serde_json::json!(w));
        }
        if let Some(h) = self.height {
            map.insert("height".into(), serde_json::json!(h));
        }
        if let Some(r) = &self.resize {
            map.insert("resize".into(), serde_json::json!(r.as_str()));
        }
        if let Some(q) = self.quality {
            map.insert("quality".into(), serde_json::json!(q));
        }
        if let Some(f) = &self.format {
            map.insert("format".into(), serde_json::json!(f.as_str()));
        }
        serde_json::Value::Object(map)
    }

    /// Returns true if no transform options are set.
    pub fn is_empty(&self) -> bool {
        self.width.is_none()
            && self.height.is_none()
            && self.resize.is_none()
            && self.quality.is_none()
            && self.format.is_none()
    }
}

/// File metadata returned by `info()`.
///
/// Matches the response from Supabase Storage `info` endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct FileInfo {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub size: Option<i64>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub cache_control: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub bucket_id: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_options_builder() {
        let opts = BucketOptions::new()
            .public(true)
            .file_size_limit(5_000_000)
            .allowed_mime_types(vec!["image/png".into(), "image/jpeg".into()]);

        assert_eq!(opts.public, Some(true));
        assert_eq!(opts.file_size_limit, Some(5_000_000));
        assert_eq!(
            opts.allowed_mime_types,
            Some(vec!["image/png".to_string(), "image/jpeg".to_string()])
        );
    }

    #[test]
    fn bucket_options_serialization() {
        let opts = BucketOptions::new().public(true);
        let json = serde_json::to_value(&opts).unwrap();
        assert_eq!(json["public"], true);
        // None fields should be skipped
        assert!(json.get("file_size_limit").is_none());
        assert!(json.get("allowed_mime_types").is_none());
    }

    #[test]
    fn file_options_builder() {
        let opts = FileOptions::new()
            .content_type("image/png")
            .cache_control("max-age=3600")
            .upsert(true);

        assert_eq!(opts.content_type.as_deref(), Some("image/png"));
        assert_eq!(opts.cache_control.as_deref(), Some("max-age=3600"));
        assert_eq!(opts.upsert, Some(true));
    }

    #[test]
    fn search_options_builder_and_serialization() {
        let opts = SearchOptions::new()
            .limit(100)
            .offset(10)
            .sort_by("name", SortOrder::Asc)
            .search("photo");

        let json = serde_json::to_value(&opts).unwrap();
        assert_eq!(json["limit"], 100);
        assert_eq!(json["offset"], 10);
        assert_eq!(json["sortBy"]["column"], "name");
        assert_eq!(json["sortBy"]["order"], "asc");
        assert_eq!(json["search"], "photo");
    }

    #[test]
    fn sort_order_display() {
        assert_eq!(SortOrder::Asc.to_string(), "asc");
        assert_eq!(SortOrder::Desc.to_string(), "desc");
    }

    #[test]
    fn bucket_deserialization() {
        let json = r#"{
            "id": "avatars",
            "name": "avatars",
            "owner": null,
            "public": true,
            "file_size_limit": 5000000,
            "allowed_mime_types": ["image/png"],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }"#;
        let bucket: Bucket = serde_json::from_str(json).unwrap();
        assert_eq!(bucket.id, "avatars");
        assert!(bucket.public);
        assert_eq!(bucket.file_size_limit, Some(5000000));
    }

    #[test]
    fn file_object_deserialization() {
        let json = r#"{
            "name": "photo.png",
            "id": "abc-123",
            "updated_at": "2024-01-01T00:00:00Z",
            "created_at": "2024-01-01T00:00:00Z",
            "last_accessed_at": "2024-01-01T00:00:00Z",
            "metadata": {"size": 1234}
        }"#;
        let file: FileObject = serde_json::from_str(json).unwrap();
        assert_eq!(file.name, "photo.png");
        assert_eq!(file.id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn upload_response_deserialization() {
        let json = r#"{"Id": "abc-123", "Key": "avatars/photo.png"}"#;
        let resp: UploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id.as_deref(), Some("abc-123"));
        assert_eq!(resp.key.as_deref(), Some("avatars/photo.png"));
    }

    #[test]
    fn signed_url_response_deserialization() {
        let json = r#"{"signedURL": "/object/sign/bucket/file?token=abc"}"#;
        let resp: SignedUrlResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.signed_url, "/object/sign/bucket/file?token=abc");
    }

    #[test]
    fn signed_upload_url_response_deserialization() {
        let json = r#"{"url": "https://example.com/upload", "token": "abc123", "path": "folder/file.png"}"#;
        let resp: SignedUploadUrlResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token, "abc123");
        assert_eq!(resp.path.as_deref(), Some("folder/file.png"));
    }

    // ─── TransformOptions Tests ─────────────────────────────

    #[test]
    fn transform_options_builder_all() {
        let opts = TransformOptions::new()
            .width(200)
            .height(150)
            .resize(ResizeMode::Cover)
            .quality(80)
            .format(ImageFormat::Origin);

        assert_eq!(opts.width, Some(200));
        assert_eq!(opts.height, Some(150));
        assert_eq!(opts.resize, Some(ResizeMode::Cover));
        assert_eq!(opts.quality, Some(80));
        assert_eq!(opts.format, Some(ImageFormat::Origin));
    }

    #[test]
    fn transform_options_default_is_empty() {
        let opts = TransformOptions::default();
        assert!(opts.is_empty());
        assert_eq!(opts.to_query_string(), "");
    }

    #[test]
    fn transform_options_to_query_string_all() {
        let qs = TransformOptions::new()
            .width(200)
            .height(150)
            .resize(ResizeMode::Cover)
            .quality(80)
            .format(ImageFormat::Origin)
            .to_query_string();
        assert_eq!(qs, "width=200&height=150&resize=cover&quality=80&format=origin");
    }

    #[test]
    fn transform_options_to_query_string_partial() {
        let qs = TransformOptions::new()
            .width(300)
            .quality(60)
            .to_query_string();
        assert_eq!(qs, "width=300&quality=60");
    }

    #[test]
    fn transform_options_to_json() {
        let json = TransformOptions::new()
            .width(200)
            .height(150)
            .resize(ResizeMode::Contain)
            .to_json();
        assert_eq!(json["width"], 200);
        assert_eq!(json["height"], 150);
        assert_eq!(json["resize"], "contain");
        assert!(json.get("quality").is_none());
        assert!(json.get("format").is_none());
    }

    #[test]
    fn resize_mode_display() {
        assert_eq!(ResizeMode::Cover.to_string(), "cover");
        assert_eq!(ResizeMode::Contain.to_string(), "contain");
        assert_eq!(ResizeMode::Fill.to_string(), "fill");
    }

    #[test]
    fn image_format_display() {
        assert_eq!(ImageFormat::Origin.to_string(), "origin");
    }

    #[test]
    fn file_info_deserialization() {
        let json = r#"{
            "id": "abc-123",
            "name": "photo.png",
            "version": "v1",
            "size": 12345,
            "content_type": "image/png",
            "cache_control": "max-age=3600",
            "etag": "\"abc\"",
            "last_modified": "2024-01-01T00:00:00Z",
            "created_at": "2024-01-01T00:00:00Z",
            "bucket_id": "photos",
            "metadata": {"custom": "value"}
        }"#;
        let info: FileInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.id.as_deref(), Some("abc-123"));
        assert_eq!(info.name.as_deref(), Some("photo.png"));
        assert_eq!(info.size, Some(12345));
        assert_eq!(info.content_type.as_deref(), Some("image/png"));
        assert_eq!(info.cache_control.as_deref(), Some("max-age=3600"));
        assert_eq!(info.etag.as_deref(), Some("\"abc\""));
        assert_eq!(info.created_at.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(info.bucket_id.as_deref(), Some("photos"));
    }

    #[test]
    fn file_info_deserialization_minimal() {
        let json = r#"{}"#;
        let info: FileInfo = serde_json::from_str(json).unwrap();
        assert!(info.id.is_none());
        assert!(info.name.is_none());
        assert!(info.size.is_none());
        assert!(info.content_type.is_none());
    }
}
