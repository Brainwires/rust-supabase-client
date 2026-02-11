use std::sync::Arc;

use serde_json::Value;
use tokio::sync::RwLock;

use crate::error::RealtimeError;
use crate::types::{
    PostgresChangePayload, PostgresChangesEvent, PresenceMeta, PresenceState,
    SubscriptionStatus,
};

// ── Callback type aliases ─────────────────────────────────────────────────────

pub type PostgresChangesCallback =
    Arc<dyn Fn(PostgresChangePayload) + Send + Sync + 'static>;

pub type BroadcastCallback = Arc<dyn Fn(Value) + Send + Sync + 'static>;

pub type PresenceSyncCallback =
    Arc<dyn Fn(&PresenceState) + Send + Sync + 'static>;

pub type PresenceJoinCallback =
    Arc<dyn Fn(String, Vec<PresenceMeta>) + Send + Sync + 'static>;

pub type PresenceLeaveCallback =
    Arc<dyn Fn(String, Vec<PresenceMeta>) + Send + Sync + 'static>;

pub type StatusCallback =
    Arc<dyn Fn(SubscriptionStatus, Option<RealtimeError>) + Send + Sync + 'static>;

// ── Binding ───────────────────────────────────────────────────────────────────

/// A registered event binding for a channel.
pub(crate) enum Binding {
    PostgresChanges {
        /// Index into the join payload's postgres_changes array.
        filter_index: usize,
        /// Which event type this binding listens for.
        event: PostgresChangesEvent,
        callback: PostgresChangesCallback,
    },
    Broadcast {
        event: String,
        callback: BroadcastCallback,
    },
    PresenceSync(PresenceSyncCallback),
    PresenceJoin(PresenceJoinCallback),
    PresenceLeave(PresenceLeaveCallback),
}

// ── Callback Registry ─────────────────────────────────────────────────────────

/// Manages all event bindings for a channel.
pub(crate) struct CallbackRegistry {
    pub bindings: Arc<RwLock<Vec<Binding>>>,
    pub status_callback: Arc<RwLock<Option<StatusCallback>>>,
}

impl CallbackRegistry {
    pub fn new() -> Self {
        Self {
            bindings: Arc::new(RwLock::new(Vec::new())),
            status_callback: Arc::new(RwLock::new(None)),
        }
    }
}
