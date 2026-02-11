//! # supabase-client
//!
//! A Rust client for [Supabase](https://supabase.com/) with a fluent, Supabase JS-like API.
//! Uses the **PostgREST REST API by default** — no database connection needed. Opt into
//! direct PostgreSQL access via [sqlx](https://github.com/launchbadge/sqlx) with the
//! `direct-sql` feature flag.
//!
//! This is the main facade crate that re-exports all sub-crates behind feature flags.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use supabase_client::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SupabaseConfig::new("https://your-project.supabase.co", "your-anon-key");
//!     let client = SupabaseClient::new(config)?;
//!
//!     let response = client.from("cities").select("*").execute().await;
//!     for row in response.into_result()? {
//!         println!("{}", row.get_as::<String>("name").unwrap());
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `query` | Yes | Query builder (select, insert, update, delete, upsert, rpc) |
//! | `derive` | Yes | `#[derive(Table)]` proc macro |
//! | `auth` | No | GoTrue authentication client |
//! | `realtime` | No | WebSocket realtime subscriptions |
//! | `storage` | No | Object storage client |
//! | `functions` | No | Edge Functions client |
//! | `direct-sql` | No | Direct PostgreSQL via sqlx (bypasses PostgREST) |
//! | `full` | No | All features enabled |

// Re-export core (always available)
pub use supabase_client_core::*;

// Re-export query builder (feature-gated)
#[cfg(feature = "query")]
pub use supabase_client_query::*;

// Re-export derive macros (feature-gated)
#[cfg(feature = "derive")]
pub use supabase_client_derive::*;

// Re-export auth crate
#[cfg(feature = "auth")]
pub use supabase_client_auth;

#[cfg(feature = "realtime")]
pub use supabase_client_realtime;

#[cfg(feature = "storage")]
pub use supabase_client_storage;

#[cfg(feature = "functions")]
pub use supabase_client_functions;

/// Prelude module for convenient imports.
///
/// ```ignore
/// use supabase_client::prelude::*;
/// ```
pub mod prelude {
    pub use supabase_client_core::{
        Row, SupabaseClient, SupabaseConfig, SupabaseError, SupabaseResponse, SupabaseResult,
    };
    #[cfg(feature = "direct-sql")]
    pub use supabase_client_core::PoolConfig;
    pub use supabase_client_core::row;

    #[cfg(feature = "query")]
    pub use supabase_client_query::{
        Filterable, Modifiable, OrderDirection, IsValue, TextSearchType,
        SupabaseClientQueryExt, Table,
        ExplainOptions, ExplainFormat, CountOption,
        CsvSelectBuilder, GeoJsonSelectBuilder,
    };

    #[cfg(feature = "derive")]
    pub use supabase_client_derive::Table;

    #[cfg(feature = "auth")]
    pub use supabase_client_auth::{
        AuthClient, AuthError, AuthResponse, Session, User,
        SupabaseClientAuthExt,
        // Session state management
        AuthChangeEvent, AuthStateChange, AuthSubscription, AutoRefreshConfig,
        // MFA types
        MfaEnrollParams, MfaVerifyParams, MfaChallengeParams,
        MfaEnrollResponse, MfaTotpInfo, MfaChallengeResponse, MfaUnenrollResponse,
        MfaListFactorsResponse, AuthenticatorAssuranceLevelInfo,
        AuthenticatorAssuranceLevel, AmrEntry, FactorType, FactorStatus,
        // SSO
        SsoSignInParams, SsoSignInResponse,
        // ID Token
        SignInWithIdTokenParams,
        // Identity linking
        LinkIdentityResponse,
        // Resend
        ResendParams, ResendType,
        // OAuth Server types
        OAuthClient, OAuthClientType, OAuthClientGrantType, OAuthClientResponseType,
        OAuthClientRegistrationType, OAuthClientListResponse,
        OAuthAuthorizationClient, OAuthAuthorizationUser, OAuthAuthorizationDetails,
        OAuthAuthorizationDetailsResponse, OAuthRedirect, OAuthGrant,
        CreateOAuthClientParams, UpdateOAuthClientParams,
        // OAuth Client-Side Flow types
        PkceCodeVerifier, PkceCodeChallenge, PkcePair,
        OAuthTokenResponse, OpenIdConfiguration, JwksResponse, Jwk,
        OAuthAuthorizeUrlParams, OAuthTokenExchangeParams,
        // Web3 auth
        Web3Chain, Web3SignInParams,
    };

    #[cfg(feature = "realtime")]
    pub use supabase_client_realtime::{
        RealtimeClient, RealtimeChannel, RealtimeConfig, RealtimeError,
        ChannelBuilder, SupabaseClientRealtimeExt,
        PostgresChangesEvent, PostgresChangesFilter, PostgresChangePayload,
        SubscriptionStatus, ChannelState, PresenceState, PresenceMeta,
    };

    #[cfg(feature = "storage")]
    pub use supabase_client_storage::{
        StorageClient, StorageBucketApi, StorageError,
        Bucket, BucketOptions, FileObject, FileOptions,
        SearchOptions, SortOrder, SignedUrlResponse,
        SupabaseClientStorageExt,
        // Phase 7: Storage enhancements
        TransformOptions, ResizeMode, ImageFormat, FileInfo,
    };

    #[cfg(feature = "functions")]
    pub use supabase_client_functions::{
        FunctionsClient, FunctionsError, FunctionResponse,
        InvokeOptions, InvokeBody, HttpMethod, FunctionRegion,
        SupabaseClientFunctionsExt,
    };
}
