//! Integration tests for supabase-client-storage.
//!
//! These tests require a running local Supabase instance started via `supabase start`.
//! Configuration is read from environment variables or falls back to defaults matching
//! the local dev instance in this project's supabase/ directory.
//!
//! Run with: cargo test -p supabase-client-storage --test integration -- --test-threads=1

use supabase_client_storage::{
    BucketOptions, FileOptions, ImageFormat, ResizeMode, SearchOptions, SortOrder, StorageClient,
    StorageError, TransformOptions,
};

/// Default local Supabase URL (from `supabase start` output).
fn supabase_url() -> String {
    std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:64321".to_string())
}

/// Default local service_role key (needed for bucket management).
fn service_role_key() -> String {
    std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU".to_string()
    })
}

/// Default local anon key.
fn storage_client() -> StorageClient {
    StorageClient::new(&supabase_url(), &service_role_key())
        .expect("Failed to create StorageClient")
}

/// Generate a unique bucket name to avoid collisions.
fn test_bucket_name(suffix: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("test-{}-{}", suffix, ts)
}

/// Cleanup helper: empty and delete a bucket, ignoring errors.
async fn cleanup_bucket(storage: &StorageClient, bucket_id: &str) {
    let _ = storage.empty_bucket(bucket_id).await;
    let _ = storage.delete_bucket(bucket_id).await;
}

// ─── Unit Tests (no server needed) ────────────────────────────

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn storage_client_new_ok() {
        let client = StorageClient::new("https://example.supabase.co", "test-key");
        assert!(client.is_ok());
    }

    #[test]
    fn storage_client_base_url() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        assert_eq!(client.base_url().path(), "/storage/v1");
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
    fn public_url_nested_path() {
        let client = StorageClient::new("https://example.supabase.co", "test-key").unwrap();
        let api = client.from("docs");
        let url = api.get_public_url("a/b/c/file.pdf");
        assert_eq!(
            url,
            "https://example.supabase.co/storage/v1/object/public/docs/a/b/c/file.pdf"
        );
    }
}

// ─── Integration Tests (require local Supabase) ──────────────

#[cfg(test)]
mod integration_tests {
    use super::*;

    // ─── Bucket CRUD ─────────────────────────────────────────

    #[tokio::test]
    async fn create_and_get_bucket() {
        let storage = storage_client();
        let name = test_bucket_name("create");

        let result = storage
            .create_bucket(&name, BucketOptions::new().public(true))
            .await;
        assert!(result.is_ok(), "create_bucket failed: {:?}", result.err());
        assert_eq!(result.unwrap().name, name);

        let bucket = storage.get_bucket(&name).await;
        assert!(bucket.is_ok(), "get_bucket failed: {:?}", bucket.err());
        let bucket = bucket.unwrap();
        assert_eq!(bucket.id, name);
        assert!(bucket.public);

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn list_buckets() {
        let storage = storage_client();
        let name = test_bucket_name("list");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let buckets = storage.list_buckets().await;
        assert!(buckets.is_ok(), "list_buckets failed: {:?}", buckets.err());
        let buckets = buckets.unwrap();
        assert!(
            buckets.iter().any(|b| b.id == name),
            "Created bucket not found in list"
        );

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn update_bucket() {
        let storage = storage_client();
        let name = test_bucket_name("update");

        storage
            .create_bucket(&name, BucketOptions::new().public(false))
            .await
            .expect("create_bucket failed");

        let result = storage
            .update_bucket(
                &name,
                BucketOptions::new()
                    .public(true)
                    .file_size_limit(10_000_000),
            )
            .await;
        assert!(result.is_ok(), "update_bucket failed: {:?}", result.err());

        let bucket = storage.get_bucket(&name).await.expect("get_bucket failed");
        assert!(bucket.public);

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn empty_and_delete_bucket() {
        let storage = storage_client();
        let name = test_bucket_name("empty-del");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        // Upload a file so bucket isn't empty
        let file_api = storage.from(&name);
        file_api
            .upload(
                "test.txt",
                b"hello".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        // Empty it
        let result = storage.empty_bucket(&name).await;
        assert!(result.is_ok(), "empty_bucket failed: {:?}", result.err());

        // Now delete
        let result = storage.delete_bucket(&name).await;
        assert!(result.is_ok(), "delete_bucket failed: {:?}", result.err());

        // Verify it's gone
        let get_result = storage.get_bucket(&name).await;
        assert!(get_result.is_err());
    }

    // ─── File Operations ─────────────────────────────────────

    #[tokio::test]
    async fn upload_and_download() {
        let storage = storage_client();
        let name = test_bucket_name("updown");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        let content = b"Hello, Supabase Storage!".to_vec();

        let upload = file_api
            .upload(
                "test-file.txt",
                content.clone(),
                FileOptions::new()
                    .content_type("text/plain")
                    .cache_control("max-age=3600"),
            )
            .await;
        assert!(upload.is_ok(), "upload failed: {:?}", upload.err());

        let downloaded = file_api.download("test-file.txt").await;
        assert!(downloaded.is_ok(), "download failed: {:?}", downloaded.err());
        assert_eq!(downloaded.unwrap(), content);

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn upload_with_upsert() {
        let storage = storage_client();
        let name = test_bucket_name("upsert");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);

        // First upload
        file_api
            .upload(
                "file.txt",
                b"version 1".to_vec(),
                FileOptions::new()
                    .content_type("text/plain")
                    .upsert(true),
            )
            .await
            .expect("first upload failed");

        // Upsert (replace)
        file_api
            .upload(
                "file.txt",
                b"version 2".to_vec(),
                FileOptions::new()
                    .content_type("text/plain")
                    .upsert(true),
            )
            .await
            .expect("upsert failed");

        let data = file_api.download("file.txt").await.expect("download failed");
        assert_eq!(data, b"version 2");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn update_file() {
        let storage = storage_client();
        let name = test_bucket_name("update-file");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);

        file_api
            .upload(
                "doc.txt",
                b"original".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        file_api
            .update(
                "doc.txt",
                b"updated".to_vec(),
                Some(FileOptions::new().content_type("text/plain")),
            )
            .await
            .expect("update failed");

        let data = file_api.download("doc.txt").await.expect("download failed");
        assert_eq!(data, b"updated");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn list_files() {
        let storage = storage_client();
        let name = test_bucket_name("list-files");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);

        // Upload some files
        for fname in &["a.txt", "b.txt", "c.txt"] {
            file_api
                .upload(
                    fname,
                    format!("content of {}", fname).into_bytes(),
                    FileOptions::new().content_type("text/plain"),
                )
                .await
                .expect("upload failed");
        }

        // List all
        let files = file_api.list(None, None).await;
        assert!(files.is_ok(), "list failed: {:?}", files.err());
        let files = files.unwrap();
        assert!(files.len() >= 3);

        // List with limit
        let files = file_api
            .list(
                None,
                Some(SearchOptions::new().limit(2).sort_by("name", SortOrder::Asc)),
            )
            .await
            .expect("list with options failed");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "a.txt");

        // List with search
        let files = file_api
            .list(None, Some(SearchOptions::new().search("b")))
            .await
            .expect("list with search failed");
        assert!(files.iter().any(|f| f.name == "b.txt"));

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn list_files_in_folder() {
        let storage = storage_client();
        let name = test_bucket_name("list-folder");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);

        file_api
            .upload(
                "docs/readme.txt",
                b"readme".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");
        file_api
            .upload(
                "docs/guide.txt",
                b"guide".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");
        file_api
            .upload(
                "images/photo.png",
                b"png-data".to_vec(),
                FileOptions::new().content_type("image/png"),
            )
            .await
            .expect("upload failed");

        let docs = file_api.list(Some("docs"), None).await.expect("list docs failed");
        assert_eq!(docs.len(), 2);

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn move_file() {
        let storage = storage_client();
        let name = test_bucket_name("move");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "old.txt",
                b"data".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let result = file_api.move_file("old.txt", "new.txt").await;
        assert!(result.is_ok(), "move failed: {:?}", result.err());

        // Old path should fail
        let old = file_api.download("old.txt").await;
        assert!(old.is_err());

        // New path should work
        let new = file_api.download("new.txt").await;
        assert!(new.is_ok());
        assert_eq!(new.unwrap(), b"data");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn copy_file() {
        let storage = storage_client();
        let name = test_bucket_name("copy");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "original.txt",
                b"original data".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let result = file_api.copy("original.txt", "copy.txt").await;
        assert!(result.is_ok(), "copy failed: {:?}", result.err());

        // Both should be accessible
        let orig = file_api.download("original.txt").await.expect("download original failed");
        let copied = file_api.download("copy.txt").await.expect("download copy failed");
        assert_eq!(orig, b"original data");
        assert_eq!(copied, b"original data");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn remove_files() {
        let storage = storage_client();
        let name = test_bucket_name("remove");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "a.txt",
                b"a".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload a failed");
        file_api
            .upload(
                "b.txt",
                b"b".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload b failed");

        let result = file_api.remove(vec!["a.txt", "b.txt"]).await;
        assert!(result.is_ok(), "remove failed: {:?}", result.err());

        // Both should be gone
        assert!(file_api.download("a.txt").await.is_err());
        assert!(file_api.download("b.txt").await.is_err());

        cleanup_bucket(&storage, &name).await;
    }

    // ─── Signed URLs ─────────────────────────────────────────

    #[tokio::test]
    async fn create_signed_url() {
        let storage = storage_client();
        let name = test_bucket_name("signed");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "secret.txt",
                b"secret data".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let signed = file_api.create_signed_url("secret.txt", 3600).await;
        assert!(signed.is_ok(), "create_signed_url failed: {:?}", signed.err());
        let signed = signed.unwrap();
        assert!(!signed.signed_url.is_empty());
        assert!(signed.signed_url.contains("token="));

        // Download via the signed URL
        let resp = reqwest::get(&signed.signed_url).await.expect("GET signed URL failed");
        assert!(resp.status().is_success());
        let body = resp.bytes().await.expect("read body failed");
        assert_eq!(body.as_ref(), b"secret data");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn create_signed_urls_batch() {
        let storage = storage_client();
        let name = test_bucket_name("signed-batch");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "file1.txt",
                b"one".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload 1 failed");
        file_api
            .upload(
                "file2.txt",
                b"two".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload 2 failed");

        let result = file_api
            .create_signed_urls(vec!["file1.txt", "file2.txt"], 3600)
            .await;
        assert!(result.is_ok(), "create_signed_urls failed: {:?}", result.err());
        let entries = result.unwrap();
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            assert!(
                entry.signed_url.is_some(),
                "Missing signed URL for {:?}",
                entry.path
            );
            assert!(entry.error.is_none());
        }

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn public_url_for_public_bucket() {
        let storage = storage_client();
        let name = test_bucket_name("public-url");

        storage
            .create_bucket(&name, BucketOptions::new().public(true))
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "hello.txt",
                b"hello world".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let public_url = file_api.get_public_url("hello.txt");
        assert!(public_url.contains(&name));
        assert!(public_url.contains("hello.txt"));
        assert!(public_url.contains("/object/public/"));

        // Download via public URL
        let resp = reqwest::get(&public_url).await.expect("GET public URL failed");
        assert!(
            resp.status().is_success(),
            "Public URL download failed: {}",
            resp.status()
        );
        let body = resp.bytes().await.expect("read body failed");
        assert_eq!(body.as_ref(), b"hello world");

        cleanup_bucket(&storage, &name).await;
    }

    // ─── Signed Upload URLs ──────────────────────────────────

    #[tokio::test]
    async fn signed_upload_url_flow() {
        let storage = storage_client();
        let name = test_bucket_name("signed-upload");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);

        let signed = file_api.create_signed_upload_url("delegated.txt").await;
        assert!(
            signed.is_ok(),
            "create_signed_upload_url failed: {:?}",
            signed.err()
        );
        let signed = signed.unwrap();
        assert!(!signed.token.is_empty());

        let result = file_api
            .upload_to_signed_url(
                &signed.token,
                "delegated.txt",
                b"delegated upload data".to_vec(),
                Some(FileOptions::new().content_type("text/plain")),
            )
            .await;
        assert!(
            result.is_ok(),
            "upload_to_signed_url failed: {:?}",
            result.err()
        );

        let data = file_api
            .download("delegated.txt")
            .await
            .expect("download failed");
        assert_eq!(data, b"delegated upload data");

        cleanup_bucket(&storage, &name).await;
    }

    // ─── Error Cases ─────────────────────────────────────────

    #[tokio::test]
    async fn error_download_nonexistent() {
        let storage = storage_client();
        let name = test_bucket_name("err-download");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        let result = file_api.download("nonexistent.txt").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            StorageError::Api { status, .. } => {
                assert!(status == 400 || status == 404, "Expected 400 or 404, got {}", status);
            }
            other => panic!("Expected Api error, got: {:?}", other),
        }

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn error_get_nonexistent_bucket() {
        let storage = storage_client();
        let result = storage.get_bucket("definitely-does-not-exist-12345").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn error_upload_to_nonexistent_bucket() {
        let storage = storage_client();
        let file_api = storage.from("definitely-does-not-exist-12345");
        let result = file_api
            .upload(
                "file.txt",
                b"data".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await;
        assert!(result.is_err());
    }

    // ─── File Info & Exists ─────────────────────────────────

    #[tokio::test]
    async fn info_existing_file() {
        let storage = storage_client();
        let name = test_bucket_name("info");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        let content = b"hello info test".to_vec();
        file_api
            .upload(
                "info-test.txt",
                content.clone(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let info = file_api.info("info-test.txt").await;
        assert!(info.is_ok(), "info failed: {:?}", info.err());
        let info = info.unwrap();
        // Size should match uploaded content
        assert_eq!(info.size, Some(content.len() as i64));
        // Content type should be set
        assert!(
            info.content_type.is_some(),
            "Expected content_type to be populated"
        );

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn info_nonexistent_file() {
        let storage = storage_client();
        let name = test_bucket_name("info-miss");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        let result = file_api.info("does-not-exist.txt").await;
        assert!(result.is_err(), "Expected error for nonexistent file info");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn exists_true() {
        let storage = storage_client();
        let name = test_bucket_name("exists-t");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "existing.txt",
                b"data".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let found = file_api.exists("existing.txt").await;
        assert!(found.is_ok(), "exists failed: {:?}", found.err());
        assert!(found.unwrap(), "Expected file to exist");

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn exists_false() {
        let storage = storage_client();
        let name = test_bucket_name("exists-f");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        let found = file_api.exists("no-such-file.txt").await;
        assert!(found.is_ok(), "exists failed: {:?}", found.err());
        assert!(!found.unwrap(), "Expected file to NOT exist");

        cleanup_bucket(&storage, &name).await;
    }

    // ─── Transform URLs ─────────────────────────────────────

    #[tokio::test]
    async fn public_url_with_transform() {
        let storage = storage_client();
        let api = storage.from("photos");
        let transform = TransformOptions::new()
            .width(200)
            .height(200)
            .resize(ResizeMode::Cover)
            .quality(80)
            .format(ImageFormat::Origin);

        let url = api.get_public_url_with_transform("photo.jpg", &transform);
        assert!(
            url.contains("/render/image/public/"),
            "URL should use render path: {}",
            url
        );
        assert!(url.contains("width=200"), "URL missing width: {}", url);
        assert!(url.contains("height=200"), "URL missing height: {}", url);
        assert!(url.contains("resize=cover"), "URL missing resize: {}", url);
        assert!(url.contains("quality=80"), "URL missing quality: {}", url);
        assert!(url.contains("format=origin"), "URL missing format: {}", url);
    }

    #[tokio::test]
    async fn create_signed_url_with_transform() {
        let storage = storage_client();
        let name = test_bucket_name("sig-tfm");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        file_api
            .upload(
                "image.txt",
                b"fake image data".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        let transform = TransformOptions::new().width(100).height(100);

        let signed = file_api
            .create_signed_url_with_transform("image.txt", 3600, &transform)
            .await;
        assert!(
            signed.is_ok(),
            "create_signed_url_with_transform failed: {:?}",
            signed.err()
        );
        let signed = signed.unwrap();
        assert!(!signed.signed_url.is_empty());
        assert!(signed.signed_url.contains("token="));

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn create_signed_urls_with_transform_batch() {
        let storage = storage_client();
        let name = test_bucket_name("sig-tfm-batch");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        for fname in &["a.txt", "b.txt"] {
            file_api
                .upload(
                    fname,
                    format!("content of {}", fname).into_bytes(),
                    FileOptions::new().content_type("text/plain"),
                )
                .await
                .expect("upload failed");
        }

        let transform = TransformOptions::new().width(50);

        let result = file_api
            .create_signed_urls_with_transform(vec!["a.txt", "b.txt"], 3600, &transform)
            .await;
        assert!(
            result.is_ok(),
            "create_signed_urls_with_transform failed: {:?}",
            result.err()
        );
        let entries = result.unwrap();
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            assert!(
                entry.signed_url.is_some(),
                "Missing signed URL for {:?}",
                entry.path
            );
            assert!(entry.error.is_none());
        }

        cleanup_bucket(&storage, &name).await;
    }

    #[tokio::test]
    async fn download_with_transform() {
        let storage = storage_client();
        let name = test_bucket_name("dl-tfm");

        storage
            .create_bucket(&name, BucketOptions::new())
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);
        // Upload a minimal 1x1 red PNG (67 bytes)
        let png_data: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // RGB, no interlace
            0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
            0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, // compressed data
            0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC, 0x33, // CRC
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
            0xAE, 0x42, 0x60, 0x82,
        ];

        file_api
            .upload(
                "tiny.png",
                png_data,
                FileOptions::new().content_type("image/png"),
            )
            .await
            .expect("upload failed");

        let transform = TransformOptions::new().width(1).height(1);

        // Note: Local Supabase may not have image transformation service (Pro feature).
        // We test that the request is made correctly; it may return an error from the
        // server if the transform service is not available.
        let result = file_api
            .download_with_transform("tiny.png", &transform)
            .await;

        // Accept either success (transform service available) or specific error
        // (transform service not available). The request should not crash.
        match &result {
            Ok(bytes) => {
                assert!(!bytes.is_empty(), "Expected non-empty response");
            }
            Err(StorageError::Api { status, .. }) => {
                // 400, 404, or 422 are acceptable if transform service isn't available
                assert!(
                    *status == 400 || *status == 404 || *status == 422,
                    "Unexpected error status: {}",
                    status
                );
            }
            Err(e) => panic!("Unexpected error type: {:?}", e),
        }

        cleanup_bucket(&storage, &name).await;
    }

    // ─── Full Lifecycle ──────────────────────────────────────

    #[tokio::test]
    async fn full_lifecycle() {
        let storage = storage_client();
        let name = test_bucket_name("lifecycle");

        // 1. Create bucket
        storage
            .create_bucket(&name, BucketOptions::new().public(true))
            .await
            .expect("create_bucket failed");

        let file_api = storage.from(&name);

        // 2. Upload
        file_api
            .upload(
                "doc.txt",
                b"hello world".to_vec(),
                FileOptions::new().content_type("text/plain"),
            )
            .await
            .expect("upload failed");

        // 3. Download
        let data = file_api.download("doc.txt").await.expect("download failed");
        assert_eq!(data, b"hello world");

        // 4. List
        let files = file_api.list(None, None).await.expect("list failed");
        assert!(files.iter().any(|f| f.name == "doc.txt"));

        // 5. Move
        file_api
            .move_file("doc.txt", "renamed.txt")
            .await
            .expect("move failed");

        // 6. Copy
        file_api
            .copy("renamed.txt", "copy.txt")
            .await
            .expect("copy failed");

        // 7. Verify both exist
        let data1 = file_api.download("renamed.txt").await.expect("download renamed failed");
        let data2 = file_api.download("copy.txt").await.expect("download copy failed");
        assert_eq!(data1, data2);

        // 8. Remove
        file_api
            .remove(vec!["renamed.txt", "copy.txt"])
            .await
            .expect("remove failed");

        // 9. Verify removed
        assert!(file_api.download("renamed.txt").await.is_err());
        assert!(file_api.download("copy.txt").await.is_err());

        // 10. Delete bucket
        storage.empty_bucket(&name).await.expect("empty failed");
        storage.delete_bucket(&name).await.expect("delete failed");

        // 11. Verify gone
        assert!(storage.get_bucket(&name).await.is_err());
    }
}
