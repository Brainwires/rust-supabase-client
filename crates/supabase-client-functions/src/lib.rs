//! Supabase Edge Functions HTTP client.
//!
//! This crate provides an HTTP client for invoking Supabase Edge Functions
//! deployed at `/functions/v1/{function_name}`.
//!
//! # Usage
//!
//! ```ignore
//! use supabase_client::prelude::*;
//! use serde_json::json;
//!
//! let client = SupabaseClient::new(config).await?;
//! let functions = client.functions()?;
//!
//! let response = functions.invoke("hello", InvokeOptions::new()
//!     .body(json!({"name": "World"}))
//! ).await?;
//! let data: serde_json::Value = response.json()?;
//! ```

pub mod client;
pub mod error;
pub mod types;

// Re-exports for convenient access
pub use client::FunctionsClient;
pub use error::{FunctionsApiErrorResponse, FunctionsError};
pub use types::*;

use supabase_client_core::SupabaseClient;

/// Extension trait to create a [`FunctionsClient`] from a [`SupabaseClient`].
///
/// # Example
/// ```ignore
/// use supabase_client::prelude::*;
/// use supabase_client_functions::SupabaseClientFunctionsExt;
///
/// let client = SupabaseClient::new(config).await?;
/// let functions = client.functions()?;
/// let response = functions.invoke("hello", InvokeOptions::new()).await?;
/// ```
pub trait SupabaseClientFunctionsExt {
    /// Create a [`FunctionsClient`] from the client's configuration.
    ///
    /// Requires `supabase_url` and `supabase_key` to be set in the config.
    fn functions(&self) -> Result<FunctionsClient, FunctionsError>;
}

impl SupabaseClientFunctionsExt for SupabaseClient {
    fn functions(&self) -> Result<FunctionsClient, FunctionsError> {
        let config = self.config();
        let url = config
            .supabase_url
            .as_ref()
            .ok_or_else(|| {
                FunctionsError::InvalidConfig("supabase_url is required for functions".into())
            })?;
        let key = config
            .supabase_key
            .as_ref()
            .ok_or_else(|| {
                FunctionsError::InvalidConfig("supabase_key is required for functions".into())
            })?;
        FunctionsClient::new(url, key)
    }
}
