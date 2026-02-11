//! Supabase Storage HTTP client.
//!
//! This crate provides an HTTP client for the Supabase Storage API.
//! It communicates with Storage REST endpoints at `/storage/v1/...`.
//!
//! # Usage
//!
//! ```ignore
//! use supabase_client::prelude::*;
//!
//! let client = SupabaseClient::new(config).await?;
//! let storage = client.storage()?;
//!
//! // Bucket operations
//! let buckets = storage.list_buckets().await?;
//! storage.create_bucket("photos", BucketOptions::new().public(true)).await?;
//!
//! // File operations
//! let file_api = storage.from("photos");
//! file_api.upload("photo.png", data, FileOptions::new().content_type("image/png")).await?;
//! let bytes = file_api.download("photo.png").await?;
//! ```

pub mod bucket_api;
pub mod client;
pub mod error;
pub mod types;

// Re-exports for convenient access
pub use bucket_api::StorageBucketApi;
pub use client::StorageClient;
pub use error::{StorageApiErrorResponse, StorageError};
pub use types::*;

use supabase_client_core::SupabaseClient;

/// Extension trait to create a [`StorageClient`] from a [`SupabaseClient`].
///
/// # Example
/// ```ignore
/// use supabase_client::prelude::*;
/// use supabase_client_storage::SupabaseClientStorageExt;
///
/// let client = SupabaseClient::new(config).await?;
/// let storage = client.storage()?;
/// let buckets = storage.list_buckets().await?;
/// ```
pub trait SupabaseClientStorageExt {
    /// Create a [`StorageClient`] from the client's configuration.
    ///
    /// Requires `supabase_url` and `supabase_key` to be set in the config.
    fn storage(&self) -> Result<StorageClient, StorageError>;
}

impl SupabaseClientStorageExt for SupabaseClient {
    fn storage(&self) -> Result<StorageClient, StorageError> {
        StorageClient::new(self.supabase_url(), self.api_key())
    }
}
