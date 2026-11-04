//! # supabase-client-core
//!
//! Core types and client for the `supabase-client` crate family.
//!
//! This crate provides [`SupabaseClient`], [`SupabaseConfig`], error types, and the
//! [`SupabaseResponse`] abstraction used by all other `supabase-client-*` crates.
//!
//! **Most users should depend on [`supabase-client-sdk`](https://crates.io/crates/supabase-client-sdk)
//! instead**, which re-exports this crate and adds query building, auth, realtime,
//! storage, and edge functions behind feature flags.
//!
//! ## Features
//!
//! - `rustls` (default) — TLS via rustls with the OS certificate store.
//! - `native-tls` — TLS via the platform library (OpenSSL, SChannel, Secure Transport).
//! - `direct-sql` — Enables a direct PostgreSQL connection pool via sqlx,
//!   bypassing PostgREST for queries.

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "direct-sql", target_arch = "wasm32"))]
compile_error!(
    "the `direct-sql` feature is not supported on wasm32: it opens PostgreSQL \
     connections with sqlx, which needs a native TCP stack. Disable `direct-sql` \
     for wasm32 builds and use the REST query builder."
);

pub mod auth_token;
pub mod client;
pub mod config;
pub mod error;
pub mod http;
pub mod keys;
pub mod platform;
pub mod response;
pub mod value;

pub use auth_token::AccessToken;
pub use client::SupabaseClient;
pub use config::SupabaseConfig;
#[cfg(feature = "direct-sql")]
pub use config::PoolConfig;
pub use error::{StatusCode, SupabaseError, SupabaseResult};
pub use response::SupabaseResponse;
pub use value::Row;
