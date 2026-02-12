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
//! - `direct-sql` — Enables a direct PostgreSQL connection pool via sqlx,
//!   bypassing PostgREST for queries.

pub mod client;
pub mod config;
pub mod error;
pub mod platform;
pub mod response;
pub mod value;

pub use client::SupabaseClient;
pub use config::SupabaseConfig;
#[cfg(feature = "direct-sql")]
pub use config::PoolConfig;
pub use error::{StatusCode, SupabaseError, SupabaseResult};
pub use response::SupabaseResponse;
pub use value::Row;
