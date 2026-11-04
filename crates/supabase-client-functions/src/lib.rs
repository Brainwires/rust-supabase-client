//! Supabase Edge Functions HTTP client.
//!
//! This crate provides an HTTP client for invoking Supabase Edge Functions
//! deployed at `/functions/v1/{function_name}`.
//!
//! # Usage
//!
//! ```ignore
//! use supabase_client_sdk::prelude::*;
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

#![cfg_attr(docsrs, feature(doc_cfg))]

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
/// use supabase_client_sdk::prelude::*;
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
    /// The returned client follows the `SupabaseClient`'s access token, so
    /// once the auth client from `client.auth()` has a session, invocations
    /// carry the user's JWT.
    fn functions(&self) -> Result<FunctionsClient, FunctionsError> {
        Ok(FunctionsClient::new(self.supabase_url(), self.api_key())?
            .with_session_token(self.access_token_handle()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supabase_client_core::config::SupabaseConfig;

    #[test]
    fn test_functions_extension_trait() {
        let config = SupabaseConfig::new("http://localhost:54321", "test-key");
        let client = SupabaseClient::new(config).unwrap();
        let functions = client.functions();
        assert!(functions.is_ok());
        let functions = functions.unwrap();
        assert_eq!(functions.base_url().path(), "/functions/v1");
        assert_eq!(functions.api_key(), "test-key");
    }
}
