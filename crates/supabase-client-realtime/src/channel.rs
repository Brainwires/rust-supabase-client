use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::RwLock;

use crate::callback::{Binding, CallbackRegistry};
use crate::error::RealtimeError;
use crate::types::{
    BroadcastConfig, ChannelState, JoinConfig, JoinPayload, PostgresChangesEvent,
    PostgresChangesFilter, PresenceConfig, PresenceState, SubscriptionStatus,
};

// ── ChannelBuilder ────────────────────────────────────────────────────────────

/// Builder for configuring and subscribing to a realtime channel.
///
/// Created via `RealtimeClient::channel("name")`. Consumed by `subscribe()`.
pub struct ChannelBuilder {
    pub(crate) name: String,
    pub(crate) topic: String,
    pub(crate) broadcast_config: BroadcastConfig,
    pub(crate) presence_key: String,
    pub(crate) presence_enabled: bool,
    pub(crate) postgres_changes: Vec<PostgresChangesFilter>,
    pub(crate) bindings: Vec<Binding>,
    pub(crate) is_private: bool,
    pub(crate) subscribe_timeout: Duration,
    pub(crate) access_token: Option<String>,
    /// Back-reference to the client for sending messages.
    pub(crate) client_sender: crate::client::ClientSender,
}

impl ChannelBuilder {
    /// Listen for postgres database changes.
    pub fn on_postgres_changes<F>(
        mut self,
        event: PostgresChangesEvent,
        filter: PostgresChangesFilter,
        callback: F,
    ) -> Self
    where
        F: Fn(crate::types::PostgresChangePayload) + Send + Sync + 'static,
    {
        let filter_index = self.postgres_changes.len();
        // Store the filter with the correct event type
        let filter = filter.event(event);
        self.postgres_changes.push(filter);
        self.bindings.push(Binding::PostgresChanges {
            filter_index,
            event,
            callback: Arc::new(callback),
        });
        self
    }

    /// Listen for broadcast messages with the given event name.
    pub fn on_broadcast<F>(mut self, event: &str, callback: F) -> Self
    where
        F: Fn(Value) + Send + Sync + 'static,
    {
        self.bindings.push(Binding::Broadcast {
            event: event.to_string(),
            callback: Arc::new(callback),
        });
        self
    }

    /// Listen for presence sync events (full state).
    pub fn on_presence_sync<F>(mut self, callback: F) -> Self
    where
        F: Fn(&PresenceState) + Send + Sync + 'static,
    {
        self.presence_enabled = true;
        self.bindings.push(Binding::PresenceSync(Arc::new(callback)));
        self
    }

    /// Listen for presence join events.
    pub fn on_presence_join<F>(mut self, callback: F) -> Self
    where
        F: Fn(String, Vec<crate::types::PresenceMeta>) + Send + Sync + 'static,
    {
        self.presence_enabled = true;
        self.bindings
            .push(Binding::PresenceJoin(Arc::new(callback)));
        self
    }

    /// Listen for presence leave events.
    pub fn on_presence_leave<F>(mut self, callback: F) -> Self
    where
        F: Fn(String, Vec<crate::types::PresenceMeta>) + Send + Sync + 'static,
    {
        self.presence_enabled = true;
        self.bindings
            .push(Binding::PresenceLeave(Arc::new(callback)));
        self
    }

    /// Enable broadcast acknowledgement from the server.
    pub fn broadcast_ack(mut self, ack: bool) -> Self {
        self.broadcast_config.ack = ack;
        self
    }

    /// Enable receiving your own broadcast messages.
    pub fn broadcast_self(mut self, self_send: bool) -> Self {
        self.broadcast_config.self_send = self_send;
        self
    }

    /// Set the presence key for this channel.
    pub fn presence_key(mut self, key: &str) -> Self {
        self.presence_enabled = true;
        self.presence_key = key.to_string();
        self
    }

    /// Mark this channel as private (requires RLS).
    pub fn private(mut self) -> Self {
        self.is_private = true;
        self
    }

    /// Set the subscribe timeout for this channel.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.subscribe_timeout = timeout;
        self
    }

    /// Subscribe to the channel. Sends `phx_join` and waits for acknowledgement.
    ///
    /// The `status_callback` is called when subscription status changes.
    pub async fn subscribe<F>(
        self,
        status_callback: F,
    ) -> Result<RealtimeChannel, RealtimeError>
    where
        F: Fn(SubscriptionStatus, Option<RealtimeError>) + Send + Sync + 'static,
    {
        let join_payload = JoinPayload {
            config: JoinConfig {
                broadcast: self.broadcast_config.clone(),
                presence: PresenceConfig {
                    key: self.presence_key.clone(),
                },
                postgres_changes: self.postgres_changes.clone(),
            },
            access_token: self.access_token.clone(),
        };

        let registry = CallbackRegistry::new();
        {
            let mut bindings = registry.bindings.write().await;
            for binding in self.bindings {
                bindings.push(binding);
            }
        }
        {
            let mut status_cb = registry.status_callback.write().await;
            *status_cb = Some(Arc::new(status_callback));
        }

        let inner = Arc::new(ChannelInner {
            name: self.name.clone(),
            topic: self.topic.clone(),
            state: RwLock::new(ChannelState::Joining),
            join_ref: RwLock::new(None),
            join_payload: RwLock::new(join_payload.clone()),
            registry,
            presence_state: RwLock::new(PresenceState::new()),
            pg_change_id_map: RwLock::new(HashMap::new()),
            client_sender: self.client_sender.clone(),
        });

        let channel = RealtimeChannel {
            inner: inner.clone(),
        };

        // Register channel with the client and send phx_join
        self.client_sender
            .subscribe_channel(channel.clone(), join_payload, self.subscribe_timeout)
            .await?;

        Ok(channel)
    }
}

// ── RealtimeChannel ───────────────────────────────────────────────────────────

/// A handle to a subscribed realtime channel.
///
/// This is cheaply cloneable and `Send + Sync`.
#[derive(Clone)]
pub struct RealtimeChannel {
    pub(crate) inner: Arc<ChannelInner>,
}

pub(crate) struct ChannelInner {
    pub(crate) name: String,
    pub(crate) topic: String,
    pub(crate) state: RwLock<ChannelState>,
    pub(crate) join_ref: RwLock<Option<String>>,
    pub(crate) join_payload: RwLock<JoinPayload>,
    pub(crate) registry: CallbackRegistry,
    pub(crate) presence_state: RwLock<PresenceState>,
    /// Maps server-assigned postgres_changes subscription IDs → filter_index
    pub(crate) pg_change_id_map: RwLock<HashMap<u64, usize>>,
    pub(crate) client_sender: crate::client::ClientSender,
}

impl RealtimeChannel {
    /// Get the channel topic (e.g., "realtime:db-changes").
    pub fn topic(&self) -> &str {
        &self.inner.topic
    }

    /// Get the channel name (user-provided name without prefix).
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Get the current channel state.
    pub async fn state(&self) -> ChannelState {
        *self.inner.state.read().await
    }

    /// Send a broadcast message on this channel.
    pub async fn send_broadcast(
        &self,
        event: &str,
        payload: Value,
    ) -> Result<(), RealtimeError> {
        let state = *self.inner.state.read().await;
        if state != ChannelState::Joined {
            return Err(RealtimeError::InvalidChannelState {
                expected: ChannelState::Joined,
                actual: state,
            });
        }
        let join_ref = self.inner.join_ref.read().await;
        let join_ref = join_ref
            .as_deref()
            .ok_or_else(|| RealtimeError::Internal("No join_ref".to_string()))?;
        self.inner
            .client_sender
            .send_broadcast(&self.inner.topic, event, payload, join_ref)
            .await
    }

    /// Track presence state on this channel.
    pub async fn track(&self, payload: Value) -> Result<(), RealtimeError> {
        let state = *self.inner.state.read().await;
        if state != ChannelState::Joined {
            return Err(RealtimeError::InvalidChannelState {
                expected: ChannelState::Joined,
                actual: state,
            });
        }
        let join_ref = self.inner.join_ref.read().await;
        let join_ref = join_ref
            .as_deref()
            .ok_or_else(|| RealtimeError::Internal("No join_ref".to_string()))?;
        self.inner
            .client_sender
            .send_presence_track(&self.inner.topic, payload, join_ref)
            .await
    }

    /// Stop tracking presence on this channel.
    pub async fn untrack(&self) -> Result<(), RealtimeError> {
        let state = *self.inner.state.read().await;
        if state != ChannelState::Joined {
            return Err(RealtimeError::InvalidChannelState {
                expected: ChannelState::Joined,
                actual: state,
            });
        }
        let join_ref = self.inner.join_ref.read().await;
        let join_ref = join_ref
            .as_deref()
            .ok_or_else(|| RealtimeError::Internal("No join_ref".to_string()))?;
        self.inner
            .client_sender
            .send_presence_untrack(&self.inner.topic, join_ref)
            .await
    }

    /// Get the current presence state for this channel.
    pub async fn presence_state(&self) -> PresenceState {
        self.inner.presence_state.read().await.clone()
    }

    /// Unsubscribe from this channel. Sends `phx_leave`.
    pub async fn unsubscribe(&self) -> Result<(), RealtimeError> {
        let state = *self.inner.state.read().await;
        if state == ChannelState::Closed || state == ChannelState::Leaving {
            return Ok(());
        }
        let join_ref = self.inner.join_ref.read().await;
        let join_ref = join_ref
            .as_deref()
            .ok_or_else(|| RealtimeError::Internal("No join_ref for leave".to_string()))?;
        self.inner
            .client_sender
            .send_leave(&self.inner.topic, join_ref)
            .await?;
        *self.inner.state.write().await = ChannelState::Leaving;
        Ok(())
    }

    /// Update the access token for this channel (e.g., after token refresh).
    pub async fn update_access_token(&self, token: &str) -> Result<(), RealtimeError> {
        let state = *self.inner.state.read().await;
        if state != ChannelState::Joined {
            return Err(RealtimeError::InvalidChannelState {
                expected: ChannelState::Joined,
                actual: state,
            });
        }
        // Update stored join payload
        {
            let mut jp = self.inner.join_payload.write().await;
            jp.access_token = Some(token.to_string());
        }
        let join_ref = self.inner.join_ref.read().await;
        let join_ref = join_ref
            .as_deref()
            .ok_or_else(|| RealtimeError::Internal("No join_ref".to_string()))?;
        self.inner
            .client_sender
            .send_access_token(&self.inner.topic, token, join_ref)
            .await
    }
}
