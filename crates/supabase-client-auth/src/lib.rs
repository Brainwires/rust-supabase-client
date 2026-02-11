//! Supabase Auth (GoTrue) HTTP client.
//!
//! This crate provides an HTTP client for the Supabase GoTrue auth API.
//! It communicates with GoTrue REST endpoints at `/auth/v1/...`.
//!
//! # Usage
//!
//! ```ignore
//! use supabase_client_sdk::prelude::*;
//!
//! let client = SupabaseClient::new(config).await?;
//! let auth = client.auth()?;
//!
//! // Sign up
//! let response = auth.sign_up_with_email("user@example.com", "password123").await?;
//!
//! // Sign in
//! let session = auth.sign_in_with_password_email("user@example.com", "pass").await?;
//!
//! // Get current user
//! let user = auth.get_user(&session.access_token).await?;
//!
//! // Admin operations (requires service_role key)
//! let admin = auth.admin();
//! let users = admin.list_users(None, None).await?;
//! ```

pub mod admin;
pub mod client;
pub mod error;
pub mod params;
pub mod types;

// Re-exports for convenient access
pub use admin::AdminClient;
pub use client::AuthClient;
pub use error::{AuthError, AuthErrorCode, GoTrueErrorResponse};
pub use params::*;
pub use types::*;

use supabase_client_core::SupabaseClient;

/// Extension trait to create an [`AuthClient`] from a [`SupabaseClient`].
///
/// # Example
/// ```ignore
/// use supabase_client_sdk::prelude::*;
/// use supabase_client_auth::SupabaseClientAuthExt;
///
/// let client = SupabaseClient::new(config).await?;
/// let auth = client.auth()?;
/// let session = auth.sign_in_with_password_email("user@example.com", "pass").await?;
/// ```
pub trait SupabaseClientAuthExt {
    /// Create an [`AuthClient`] from the client's configuration.
    ///
    /// Requires `supabase_url` and `supabase_key` to be set in the config.
    fn auth(&self) -> Result<AuthClient, AuthError>;
}

impl SupabaseClientAuthExt for SupabaseClient {
    fn auth(&self) -> Result<AuthClient, AuthError> {
        AuthClient::new(self.supabase_url(), self.api_key())
    }
}
