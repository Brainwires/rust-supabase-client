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
    /// The auth client writes its session's access token into the
    /// `SupabaseClient`'s shared token slot on sign-in and refresh, and clears
    /// it on sign-out. The query builder and the storage, functions, GraphQL
    /// and realtime clients created from the same `SupabaseClient` read that
    /// slot, so their requests run as the signed-in user.
    ///
    /// Each call returns an independent auth client with its own session
    /// state; create it once and keep it.
    ///
    /// Requires `supabase_url` and `supabase_key` to be set in the config.
    fn auth(&self) -> Result<AuthClient, AuthError>;
}

impl SupabaseClientAuthExt for SupabaseClient {
    fn auth(&self) -> Result<AuthClient, AuthError> {
        AuthClient::with_token_sink(
            self.supabase_url(),
            self.api_key(),
            self.access_token_handle(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supabase_client_core::config::SupabaseConfig;

    #[test]
    fn test_auth_extension_trait() {
        let config = SupabaseConfig::new("http://localhost:54321", "test-key");
        let client = SupabaseClient::new(config).unwrap();
        let auth = client.auth();
        assert!(auth.is_ok());
        let auth = auth.unwrap();
        assert_eq!(auth.base_url().path(), "/auth/v1");
    }

    #[tokio::test]
    async fn test_auth_session_is_shared_with_supabase_client() {
        let config = SupabaseConfig::new("http://localhost:54321", "anon-key");
        let client = SupabaseClient::new(config).unwrap();
        let auth = client.auth().unwrap();
        let session: Session = serde_json::from_value(serde_json::json!({
            "access_token": "user-jwt", "refresh_token": "rt", "expires_in": 3600,
            "token_type": "bearer", "user": {"id": "u1"}
        }))
        .unwrap();
        auth.set_session(session).await;
        assert_eq!(client.bearer_token(), "user-jwt");
        auth.clear_session().await;
        assert_eq!(client.bearer_token(), "anon-key");
    }
}
