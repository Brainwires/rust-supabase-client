//! Storage example: bucket management, file upload/download, signed URLs.
//!
//! Run with: cargo run --example storage -p supabase-client-sdk --features storage
//!
//! Requires: `supabase start` in the project root.

use supabase_client_sdk::prelude::*;

const DEFAULT_URL: &str = "http://127.0.0.1:64321";
const DEFAULT_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("SUPABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let key = std::env::var("SUPABASE_SERVICE_ROLE_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string());
    let config = SupabaseConfig::new(&url, &key);
    let client = SupabaseClient::new(config)?;
    let storage = client.storage()?;

    let bucket_name = "example-bucket";

    // ── Clean up from previous runs ──
    let _ = storage.empty_bucket(bucket_name).await;
    let _ = storage.delete_bucket(bucket_name).await;

    // ── Create a bucket ──
    println!("=== Create bucket ===");
    storage
        .create_bucket(bucket_name, BucketOptions::new().public(true))
        .await?;
    println!("  Created bucket: {}", bucket_name);

    // ── List buckets ──
    println!("\n=== List buckets ===");
    let buckets = storage.list_buckets().await?;
    for b in &buckets {
        println!("  {} (public: {})", b.name, b.public);
    }

    // ── Upload a file ──
    println!("\n=== Upload file ===");
    let file_api = storage.from(bucket_name);
    let content = b"Hello from supabase-client Rust SDK!";
    file_api
        .upload(
            "hello.txt",
            content.to_vec(),
            FileOptions::new().content_type("text/plain"),
        )
        .await?;
    println!("  Uploaded hello.txt ({} bytes)", content.len());

    // ── Download the file ──
    println!("\n=== Download file ===");
    let data = file_api.download("hello.txt").await?;
    println!("  Downloaded: {}", String::from_utf8_lossy(&data));

    // ── List files ──
    println!("\n=== List files ===");
    let files = file_api.list(None, None).await?;
    for f in &files {
        println!("  {} (size: {:?})", f.name, f.metadata.as_ref().and_then(|m| m.get("size")));
    }

    // ── File info ──
    println!("\n=== File info ===");
    let info = file_api.info("hello.txt").await?;
    println!("  Name: {:?}", info.name);
    println!("  Size: {:?} bytes", info.size);
    println!("  Content-Type: {:?}", info.content_type);

    // ── File exists check ──
    println!("\n=== File exists ===");
    let exists = file_api.exists("hello.txt").await?;
    println!("  hello.txt exists: {}", exists);
    let not_exists = file_api.exists("nope.txt").await?;
    println!("  nope.txt exists: {}", not_exists);

    // ── Public URL (no HTTP call) ──
    println!("\n=== Public URL ===");
    let public_url = file_api.get_public_url("hello.txt");
    println!("  {}", public_url);

    // ── Signed URL ──
    println!("\n=== Signed URL (60s expiry) ===");
    let signed = file_api.create_signed_url("hello.txt", 60).await?;
    println!("  {}", signed.signed_url);

    // ── Copy file ──
    println!("\n=== Copy file ===");
    let copy_key = file_api.copy("hello.txt", "hello-copy.txt").await?;
    println!("  Copied to: {}", copy_key);

    // ── Move file ──
    println!("\n=== Move file ===");
    file_api.move_file("hello-copy.txt", "hello-moved.txt").await?;
    println!("  Moved hello-copy.txt -> hello-moved.txt");

    // ── Remove files ──
    println!("\n=== Remove files ===");
    let removed = file_api.remove(vec!["hello.txt", "hello-moved.txt"]).await?;
    println!("  Removed {} files", removed.len());

    // ── Cleanup: delete bucket ──
    println!("\n=== Cleanup ===");
    storage.empty_bucket(bucket_name).await?;
    storage.delete_bucket(bucket_name).await?;
    println!("  Deleted bucket: {}", bucket_name);

    println!("\nDone!");
    Ok(())
}
