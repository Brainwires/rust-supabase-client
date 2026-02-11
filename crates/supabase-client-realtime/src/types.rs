use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Phoenix Protocol ──────────────────────────────────────────────────────────

/// A Phoenix Channels protocol message (v1.0.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoenixMessage {
    pub event: String,
    pub topic: String,
    pub payload: Value,
    #[serde(rename = "ref")]
    pub msg_ref: Option<String>,
    pub join_ref: Option<String>,
}

// ── Channel State ─────────────────────────────────────────────────────────────

/// The lifecycle state of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    Closed,
    Joining,
    Joined,
    Leaving,
    Errored,
}

impl fmt::Display for ChannelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Joining => write!(f, "joining"),
            Self::Joined => write!(f, "joined"),
            Self::Leaving => write!(f, "leaving"),
            Self::Errored => write!(f, "errored"),
        }
    }
}

// ── Subscription Status ───────────────────────────────────────────────────────

/// Status reported to the user's subscribe callback.
/// Matches JS: SUBSCRIBED, TIMED_OUT, CLOSED, CHANNEL_ERROR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionStatus {
    Subscribed,
    TimedOut,
    Closed,
    ChannelError,
}

impl fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subscribed => write!(f, "SUBSCRIBED"),
            Self::TimedOut => write!(f, "TIMED_OUT"),
            Self::Closed => write!(f, "CLOSED"),
            Self::ChannelError => write!(f, "CHANNEL_ERROR"),
        }
    }
}

// ── Postgres Changes ──────────────────────────────────────────────────────────

/// Which Postgres change events to listen for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostgresChangesEvent {
    #[serde(rename = "*")]
    All,
    #[serde(rename = "INSERT")]
    Insert,
    #[serde(rename = "UPDATE")]
    Update,
    #[serde(rename = "DELETE")]
    Delete,
}

impl fmt::Display for PostgresChangesEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "*"),
            Self::Insert => write!(f, "INSERT"),
            Self::Update => write!(f, "UPDATE"),
            Self::Delete => write!(f, "DELETE"),
        }
    }
}

/// Filter for postgres_changes subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresChangesFilter {
    pub event: String,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

impl PostgresChangesFilter {
    /// Create a new filter for the given schema and table.
    pub fn new(schema: impl Into<String>, table: impl Into<String>) -> Self {
        Self {
            event: "*".to_string(),
            schema: schema.into(),
            table: Some(table.into()),
            filter: None,
        }
    }

    /// Create a schema-level filter (no specific table).
    pub fn schema_only(schema: impl Into<String>) -> Self {
        Self {
            event: "*".to_string(),
            schema: schema.into(),
            table: None,
            filter: None,
        }
    }

    /// Set the event type for this filter.
    pub fn event(mut self, event: PostgresChangesEvent) -> Self {
        self.event = event.to_string();
        self
    }

    /// Add a row-level filter (e.g., "id=eq.1").
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }
}

/// Payload delivered for a postgres_changes event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresChangePayload {
    pub schema: String,
    pub table: String,
    #[serde(rename = "type")]
    pub change_type: String,
    #[serde(default)]
    pub commit_timestamp: Option<String>,
    #[serde(default)]
    pub columns: Vec<ColumnInfo>,
    #[serde(default)]
    pub record: Option<Value>,
    #[serde(default)]
    pub old_record: Option<Value>,
    #[serde(default)]
    pub errors: Option<Value>,
}

/// Column metadata from a postgres_changes payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

// ── Presence ──────────────────────────────────────────────────────────────────

/// Full presence state: key → list of presence metas.
pub type PresenceState = HashMap<String, Vec<PresenceMeta>>;

/// Metadata associated with a single presence entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceMeta {
    #[serde(default)]
    pub phx_ref: Option<String>,
    #[serde(default)]
    pub phx_ref_prev: Option<String>,
    #[serde(flatten)]
    pub data: Value,
}

/// A presence diff message from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceDiff {
    pub joins: HashMap<String, PresenceEntry>,
    pub leaves: HashMap<String, PresenceEntry>,
}

/// A single presence entry containing its metas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceEntry {
    pub metas: Vec<PresenceMeta>,
}

// ── Join Payload ──────────────────────────────────────────────────────────────

/// The payload sent with `phx_join` to configure channel features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinPayload {
    pub config: JoinConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

/// Channel configuration sent during join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinConfig {
    pub broadcast: BroadcastConfig,
    pub presence: PresenceConfig,
    pub postgres_changes: Vec<PostgresChangesFilter>,
}

/// Broadcast feature configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastConfig {
    pub ack: bool,
    #[serde(rename = "self")]
    pub self_send: bool,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            ack: false,
            self_send: false,
        }
    }
}

/// Presence feature configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceConfig {
    pub key: String,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
        }
    }
}

// ── Realtime Client Config ────────────────────────────────────────────────────

/// Configuration for the RealtimeClient.
#[derive(Debug, Clone)]
pub struct RealtimeConfig {
    /// The Supabase project URL (http/https).
    pub url: String,
    /// The Supabase API key.
    pub api_key: String,
    /// Heartbeat interval (default: 25s).
    pub heartbeat_interval: Duration,
    /// Timeout for subscribe operations (default: 10s).
    pub subscribe_timeout: Duration,
    /// Reconnection backoff intervals.
    pub reconnect: ReconnectConfig,
}

impl RealtimeConfig {
    pub fn new(url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            api_key: api_key.into(),
            heartbeat_interval: Duration::from_secs(25),
            subscribe_timeout: Duration::from_secs(10),
            reconnect: ReconnectConfig::default(),
        }
    }
}

/// Reconnection backoff configuration.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Backoff intervals to try in order.
    pub intervals: Vec<Duration>,
    /// Fallback interval once all intervals are exhausted.
    pub fallback: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            intervals: vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(10),
            ],
            fallback: Duration::from_secs(10),
        }
    }
}
