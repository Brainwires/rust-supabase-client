//! Supabase Realtime WebSocket client.
//!
//! This crate implements the Phoenix Channels v1.0.0 protocol to provide
//! real-time subscriptions for Postgres changes, broadcast messages, and
//! presence tracking.
//!
//! # Usage
//!
//! ```ignore
//! use supabase_client::prelude::*;
//!
//! let realtime = client.realtime()?;
//! realtime.connect().await?;
//!
//! let channel = realtime.channel("db-changes")
//!     .on_postgres_changes(
//!         PostgresChangesEvent::Insert,
//!         PostgresChangesFilter::new("public", "messages"),
//!         |payload| println!("New row: {:?}", payload.record),
//!     )
//!     .subscribe(|status, _err| println!("Status: {}", status))
//!     .await?;
//! ```

pub mod callback;
pub mod channel;
pub mod client;
pub mod error;
pub(crate) mod presence;
pub(crate) mod protocol;
pub mod types;

// Re-exports for convenient access
pub use channel::{ChannelBuilder, RealtimeChannel};
pub use client::RealtimeClient;
pub use error::RealtimeError;
pub use types::{
    BroadcastConfig, ChannelState, ColumnInfo, JoinConfig, JoinPayload,
    PostgresChangePayload, PostgresChangesEvent, PostgresChangesFilter, PresenceConfig,
    PresenceDiff, PresenceEntry, PresenceMeta, PresenceState, RealtimeConfig,
    ReconnectConfig, SubscriptionStatus,
};

use supabase_client_core::SupabaseClient;

/// Extension trait to create a [`RealtimeClient`] from a [`SupabaseClient`].
pub trait SupabaseClientRealtimeExt {
    /// Create a [`RealtimeClient`] from the client's configuration.
    ///
    /// Requires `supabase_url` and `supabase_key` to be set in the config.
    fn realtime(&self) -> Result<RealtimeClient, RealtimeError>;
}

impl SupabaseClientRealtimeExt for SupabaseClient {
    fn realtime(&self) -> Result<RealtimeClient, RealtimeError> {
        RealtimeClient::new(self.supabase_url(), self.api_key())
    }
}
