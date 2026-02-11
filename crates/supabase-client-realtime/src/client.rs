use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, oneshot, Mutex, RwLock};
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, trace, warn};

use crate::callback::Binding;
use crate::channel::{ChannelBuilder, RealtimeChannel};
use crate::error::RealtimeError;
use crate::presence;
use crate::protocol::{self, RefCounter};
use crate::types::{
    BroadcastConfig, ChannelState, JoinPayload, PhoenixMessage, PostgresChangePayload,
    PostgresChangesEvent, PresenceDiff, RealtimeConfig, SubscriptionStatus,
};

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    Message,
>;

// ── ClientSender ──────────────────────────────────────────────────────────────

/// Handle passed to channels for sending messages through the client's WebSocket.
#[derive(Clone)]
pub struct ClientSender {
    inner: Arc<RealtimeClientInner>,
}

impl ClientSender {
    /// Register a channel and send phx_join, waiting for acknowledgement.
    pub(crate) async fn subscribe_channel(
        &self,
        channel: RealtimeChannel,
        join_payload: JoinPayload,
        timeout: Duration,
    ) -> Result<(), RealtimeError> {
        let topic = channel.topic().to_string();

        // Check if channel already exists
        {
            let channels = self.inner.channels.read().await;
            if channels.contains_key(&topic) {
                return Err(RealtimeError::ChannelAlreadyExists(topic));
            }
        }

        // Build join message
        let join_msg = protocol::build_join(&topic, &join_payload, &self.inner.ref_counter);
        let join_ref = join_msg.join_ref.clone().unwrap();

        // Set join_ref on the channel
        {
            let mut ch_join_ref = channel.inner.join_ref.write().await;
            *ch_join_ref = Some(join_ref.clone());
        }

        // Register pending reply
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending_replies.lock().await;
            pending.insert(join_ref.clone(), reply_tx);
        }

        // Register channel
        {
            let mut channels = self.inner.channels.write().await;
            channels.insert(topic.clone(), channel.clone());
        }

        // Send join message
        self.send_message(join_msg).await?;

        // Wait for reply with timeout
        let result = tokio::time::timeout(timeout, reply_rx).await;

        match result {
            Ok(Ok(reply)) => {
                let status = reply
                    .payload
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                if status == "ok" {
                    // Extract server-assigned postgres_changes IDs
                    if let Some(pg_changes) = reply
                        .payload
                        .get("response")
                        .and_then(|r| r.get("postgres_changes"))
                        .and_then(|pc| pc.as_array())
                    {
                        let mut id_map = channel.inner.pg_change_id_map.write().await;
                        for (index, entry) in pg_changes.iter().enumerate() {
                            if let Some(server_id) = entry.get("id").and_then(|id| id.as_u64()) {
                                id_map.insert(server_id, index);
                            }
                        }
                    }

                    *channel.inner.state.write().await = ChannelState::Joined;
                    // Notify status callback
                    let status_cb = channel.inner.registry.status_callback.read().await;
                    if let Some(cb) = status_cb.as_ref() {
                        cb(SubscriptionStatus::Subscribed, None);
                    }
                    Ok(())
                } else {
                    *channel.inner.state.write().await = ChannelState::Errored;
                    let reason = reply
                        .payload
                        .get("response")
                        .and_then(|r| r.get("reason"))
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    // Remove channel on failure
                    self.inner.channels.write().await.remove(&topic);
                    // Notify status callback
                    let status_cb = channel.inner.registry.status_callback.read().await;
                    if let Some(cb) = status_cb.as_ref() {
                        cb(
                            SubscriptionStatus::ChannelError,
                            Some(RealtimeError::ServerError(reason.clone())),
                        );
                    }
                    Err(RealtimeError::ServerError(reason))
                }
            }
            Ok(Err(_)) => {
                *channel.inner.state.write().await = ChannelState::Errored;
                self.inner.channels.write().await.remove(&topic);
                Err(RealtimeError::ConnectionClosed)
            }
            Err(_) => {
                *channel.inner.state.write().await = ChannelState::Errored;
                self.inner.channels.write().await.remove(&topic);
                // Clean up pending reply
                self.inner.pending_replies.lock().await.remove(&join_ref);
                let status_cb = channel.inner.registry.status_callback.read().await;
                if let Some(cb) = status_cb.as_ref() {
                    cb(SubscriptionStatus::TimedOut, None);
                }
                Err(RealtimeError::SubscribeTimeout(timeout))
            }
        }
    }

    pub(crate) async fn send_broadcast(
        &self,
        topic: &str,
        event: &str,
        payload: Value,
        join_ref: &str,
    ) -> Result<(), RealtimeError> {
        let msg =
            protocol::build_broadcast(topic, event, payload, join_ref, &self.inner.ref_counter);
        self.send_message(msg).await
    }

    pub(crate) async fn send_presence_track(
        &self,
        topic: &str,
        payload: Value,
        join_ref: &str,
    ) -> Result<(), RealtimeError> {
        let msg =
            protocol::build_presence_track(topic, payload, join_ref, &self.inner.ref_counter);
        self.send_message(msg).await
    }

    pub(crate) async fn send_presence_untrack(
        &self,
        topic: &str,
        join_ref: &str,
    ) -> Result<(), RealtimeError> {
        let msg = protocol::build_presence_untrack(topic, join_ref, &self.inner.ref_counter);
        self.send_message(msg).await
    }

    pub(crate) async fn send_leave(
        &self,
        topic: &str,
        join_ref: &str,
    ) -> Result<(), RealtimeError> {
        let msg = protocol::build_leave(topic, join_ref, &self.inner.ref_counter);
        self.send_message(msg).await
    }

    pub(crate) async fn send_access_token(
        &self,
        topic: &str,
        token: &str,
        join_ref: &str,
    ) -> Result<(), RealtimeError> {
        let msg =
            protocol::build_access_token(topic, token, join_ref, &self.inner.ref_counter);
        self.send_message(msg).await
    }

    async fn send_message(&self, msg: PhoenixMessage) -> Result<(), RealtimeError> {
        let text = serde_json::to_string(&msg)?;
        let mut ws = self.inner.ws_write.lock().await;
        let sink = ws
            .as_mut()
            .ok_or(RealtimeError::ConnectionClosed)?;
        trace!(topic = %msg.topic, event = %msg.event, "Sending WS message");
        sink.send(Message::Text(text.into())).await?;
        Ok(())
    }
}

// ── RealtimeClient ────────────────────────────────────────────────────────────

struct RealtimeClientInner {
    config: RealtimeConfig,
    ws_write: Mutex<Option<WsSink>>,
    channels: RwLock<HashMap<String, RealtimeChannel>>,
    ref_counter: RefCounter,
    pending_replies: Mutex<HashMap<String, oneshot::Sender<PhoenixMessage>>>,
    connected: AtomicBool,
    intentional_disconnect: AtomicBool,
    shutdown_tx: broadcast::Sender<()>,
}

/// Client for Supabase Realtime WebSocket connections.
///
/// Wraps `Arc<Inner>` — cheaply cloneable, `Send + Sync`.
#[derive(Clone)]
pub struct RealtimeClient {
    inner: Arc<RealtimeClientInner>,
}

impl RealtimeClient {
    /// Create a new RealtimeClient from a Supabase URL and API key.
    pub fn new(
        url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, RealtimeError> {
        let config = RealtimeConfig::new(url, api_key);
        Self::with_config(config)
    }

    /// Create a new RealtimeClient with full configuration.
    pub fn with_config(config: RealtimeConfig) -> Result<Self, RealtimeError> {
        if config.url.is_empty() {
            return Err(RealtimeError::InvalidConfig(
                "URL must not be empty".to_string(),
            ));
        }
        if config.api_key.is_empty() {
            return Err(RealtimeError::InvalidConfig(
                "API key must not be empty".to_string(),
            ));
        }

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            inner: Arc::new(RealtimeClientInner {
                config,
                ws_write: Mutex::new(None),
                channels: RwLock::new(HashMap::new()),
                ref_counter: RefCounter::new(),
                pending_replies: Mutex::new(HashMap::new()),
                connected: AtomicBool::new(false),
                intentional_disconnect: AtomicBool::new(false),
                shutdown_tx,
            }),
        })
    }

    /// Connect to the Supabase Realtime server via WebSocket.
    ///
    /// Establishes the WebSocket connection and starts background reader,
    /// heartbeat, and auto-reconnect tasks.
    pub async fn connect(&self) -> Result<(), RealtimeError> {
        self.inner.intentional_disconnect.store(false, Ordering::SeqCst);

        let ws_url = build_ws_url(&self.inner.config.url, &self.inner.config.api_key)?;
        debug!(url = %ws_url, "Connecting to Supabase Realtime");

        let read = connect_ws(&self.inner, &ws_url).await?;

        // Spawn the reconnection-aware reader loop
        let inner = Arc::clone(&self.inner);
        let ws_url_owned = ws_url;
        tokio::spawn(async move {
            run_reader_loop(inner, read, ws_url_owned).await;
        });

        // Start heartbeat task
        spawn_heartbeat(Arc::clone(&self.inner));

        debug!("Connected to Supabase Realtime");
        Ok(())
    }

    /// Disconnect from the Realtime server.
    pub async fn disconnect(&self) -> Result<(), RealtimeError> {
        debug!("Disconnecting from Supabase Realtime");
        self.inner.intentional_disconnect.store(true, Ordering::SeqCst);
        // Signal background tasks to stop
        let _ = self.inner.shutdown_tx.send(());
        self.inner.connected.store(false, Ordering::SeqCst);

        // Close WebSocket
        {
            let mut ws = self.inner.ws_write.lock().await;
            if let Some(mut sink) = ws.take() {
                let _ = sink.send(Message::Close(None)).await;
            }
        }

        // Clear pending replies
        {
            let mut pending = self.inner.pending_replies.lock().await;
            pending.clear();
        }

        Ok(())
    }

    /// Create a ChannelBuilder for the given name.
    ///
    /// The topic will be `"realtime:<name>"`.
    pub fn channel(&self, name: &str) -> ChannelBuilder {
        let topic = format!("realtime:{}", name);
        ChannelBuilder {
            name: name.to_string(),
            topic,
            broadcast_config: BroadcastConfig::default(),
            presence_key: String::new(),
            presence_enabled: false,
            postgres_changes: Vec::new(),
            bindings: Vec::new(),
            is_private: false,
            subscribe_timeout: self.inner.config.subscribe_timeout,
            access_token: Some(self.inner.config.api_key.clone()),
            client_sender: ClientSender {
                inner: Arc::clone(&self.inner),
            },
        }
    }

    /// Remove a channel (unsubscribe and forget).
    pub async fn remove_channel(
        &self,
        channel: &RealtimeChannel,
    ) -> Result<(), RealtimeError> {
        let topic = channel.topic().to_string();
        // Send leave if joined
        let state = *channel.inner.state.read().await;
        if state == ChannelState::Joined || state == ChannelState::Joining {
            let _ = channel.unsubscribe().await;
        }
        *channel.inner.state.write().await = ChannelState::Closed;
        self.inner.channels.write().await.remove(&topic);
        Ok(())
    }

    /// Remove all channels.
    pub async fn remove_all_channels(&self) -> Result<(), RealtimeError> {
        let channels: Vec<RealtimeChannel> = {
            self.inner.channels.read().await.values().cloned().collect()
        };
        for ch in channels {
            self.remove_channel(&ch).await?;
        }
        Ok(())
    }

    /// Get a list of all active channels.
    pub fn channels(&self) -> Vec<RealtimeChannel> {
        // Use try_read to avoid blocking; if locked, return empty
        match self.inner.channels.try_read() {
            Ok(channels) => channels.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Update the auth token for the realtime connection.
    ///
    /// If connected, pushes the new access token to the server for each subscribed channel.
    ///
    /// Mirrors `supabase.realtime.setAuth(token)`.
    pub async fn set_auth(&self, token: &str) -> Result<(), RealtimeError> {
        if !self.is_connected() {
            return Err(RealtimeError::ConnectionClosed);
        }

        let channels: Vec<RealtimeChannel> = {
            self.inner.channels.read().await.values().cloned().collect()
        };

        let sender = ClientSender {
            inner: Arc::clone(&self.inner),
        };

        for channel in &channels {
            let state = *channel.inner.state.read().await;
            if state == ChannelState::Joined {
                let join_ref = channel.inner.join_ref.read().await;
                if let Some(ref jr) = *join_ref {
                    sender
                        .send_access_token(channel.topic(), token, jr)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Check if the client is currently connected.
    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }
}

// ── WebSocket URL Construction ────────────────────────────────────────────────

/// Convert a Supabase HTTP URL to a WebSocket URL for the Realtime endpoint.
pub(crate) fn build_ws_url(base_url: &str, api_key: &str) -> Result<String, RealtimeError> {
    let mut parsed = url::Url::parse(base_url)?;

    // Convert scheme: http→ws, https→wss
    let ws_scheme = match parsed.scheme() {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        other => {
            return Err(RealtimeError::InvalidConfig(format!(
                "Unsupported URL scheme: {}",
                other
            )));
        }
    };
    parsed
        .set_scheme(ws_scheme)
        .map_err(|_| RealtimeError::InvalidConfig("Failed to set WS scheme".to_string()))?;

    // Append realtime path
    {
        let mut path = parsed.path().to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str("realtime/v1/websocket");
        parsed.set_path(&path);
    }

    // Add query params
    parsed
        .query_pairs_mut()
        .append_pair("apikey", api_key)
        .append_pair("vsn", "1.0.0");

    Ok(parsed.to_string())
}

// ── Connection Helpers ────────────────────────────────────────────────────────

type WsRead = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
>;

/// Establish a WebSocket connection and store the write half. Returns the read half.
async fn connect_ws(
    inner: &RealtimeClientInner,
    ws_url: &str,
) -> Result<WsRead, RealtimeError> {
    // Build HTTP request with custom headers
    let mut request = Request::builder().uri(ws_url);
    for (key, value) in &inner.config.headers {
        request = request.header(key.as_str(), value.as_str());
    }
    let request = request
        .body(())
        .map_err(|e| RealtimeError::InvalidConfig(format!("Failed to build WS request: {}", e)))?;

    let (ws_stream, _) = tokio_tungstenite::connect_async(request).await?;
    let (write, read) = ws_stream.split();

    *inner.ws_write.lock().await = Some(write);
    inner.connected.store(true, Ordering::SeqCst);

    Ok(read)
}

/// Run the reader loop with auto-reconnect support.
///
/// Reads from the WebSocket, handling messages. On disconnect (if not intentional),
/// attempts reconnection with backoff and rejoins channels on success.
async fn run_reader_loop(
    inner: Arc<RealtimeClientInner>,
    initial_read: WsRead,
    ws_url: String,
) {
    let mut read = initial_read;
    let mut shutdown_rx = inner.shutdown_tx.subscribe();

    loop {
        // Read messages until disconnect
        let disconnected_by_shutdown = read_until_disconnect(&inner, &mut read, &mut shutdown_rx).await;

        if disconnected_by_shutdown || inner.intentional_disconnect.load(Ordering::SeqCst) {
            break;
        }

        // Attempt auto-reconnect with backoff
        match attempt_reconnect(&inner, &ws_url).await {
            Some(new_read) => {
                read = new_read;
                // Spawn a new heartbeat for the new connection
                spawn_heartbeat(Arc::clone(&inner));
                // Rejoin channels
                if let Err(e) = rejoin_channels(&inner).await {
                    warn!(error = %e, "Failed to rejoin channels after reconnect");
                }
            }
            None => {
                // All reconnect attempts failed
                notify_all_channels_closed(&inner).await;
                break;
            }
        }
    }
}

/// Read messages from the WebSocket until it disconnects or shutdown is signaled.
/// Returns `true` if shutdown was requested, `false` if the connection was lost.
async fn read_until_disconnect(
    inner: &RealtimeClientInner,
    read: &mut WsRead,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> bool {
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_message(inner, &text).await;
                    }
                    Some(Ok(Message::Close(_))) => {
                        debug!("WebSocket closed by server");
                        inner.connected.store(false, Ordering::SeqCst);
                        return false;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let mut ws = inner.ws_write.lock().await;
                        if let Some(sink) = ws.as_mut() {
                            let _ = sink.send(Message::Pong(data)).await;
                        }
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "WebSocket read error");
                        inner.connected.store(false, Ordering::SeqCst);
                        return false;
                    }
                    None => {
                        debug!("WebSocket stream ended");
                        inner.connected.store(false, Ordering::SeqCst);
                        return false;
                    }
                    _ => {} // Binary, Pong, Frame — ignore
                }
            }
            _ = shutdown_rx.recv() => {
                debug!("Reader task shutting down");
                return true;
            }
        }
    }
}

/// Spawn a heartbeat task that sends periodic heartbeats over the WebSocket.
fn spawn_heartbeat(inner: Arc<RealtimeClientInner>) {
    let mut shutdown_rx = inner.shutdown_tx.subscribe();
    let heartbeat_interval = inner.config.heartbeat_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        interval.tick().await; // Skip the first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if !inner.connected.load(Ordering::SeqCst) {
                        break;
                    }
                    let heartbeat = protocol::build_heartbeat(&inner.ref_counter);
                    let text = match serde_json::to_string(&heartbeat) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let mut ws = inner.ws_write.lock().await;
                    if let Some(sink) = ws.as_mut() {
                        if let Err(e) = sink.send(Message::Text(text.into())).await {
                            warn!(error = %e, "Heartbeat send failed");
                            inner.connected.store(false, Ordering::SeqCst);
                            break;
                        }
                        trace!("Heartbeat sent");
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("Heartbeat task shutting down");
                    break;
                }
            }
        }
    });
}

/// Attempt to reconnect with backoff intervals from config.
/// Returns the new read half on success, or None if all attempts failed.
async fn attempt_reconnect(
    inner: &Arc<RealtimeClientInner>,
    ws_url: &str,
) -> Option<WsRead> {
    let config = &inner.config;

    // Build iterator: configured intervals, then repeat fallback
    let intervals = config.reconnect.intervals.iter().copied()
        .chain(std::iter::repeat(config.reconnect.fallback));

    let max_attempts = config.reconnect.intervals.len() + 3;

    for (attempt, delay) in intervals.enumerate().take(max_attempts) {
        if inner.intentional_disconnect.load(Ordering::SeqCst) {
            return None;
        }

        info!(attempt = attempt + 1, delay_ms = delay.as_millis(), "Attempting reconnect");
        tokio::time::sleep(delay).await;

        if inner.intentional_disconnect.load(Ordering::SeqCst) {
            return None;
        }

        match connect_ws(inner, ws_url).await {
            Ok(read) => {
                info!("Reconnected successfully");
                return Some(read);
            }
            Err(e) => {
                warn!(error = %e, attempt = attempt + 1, "Reconnect attempt failed");
            }
        }
    }

    warn!("All reconnect attempts exhausted");
    None
}

/// Rejoin all active channels after a successful reconnect.
async fn rejoin_channels(inner: &RealtimeClientInner) -> Result<(), RealtimeError> {
    let channels = inner.channels.read().await;
    for (topic, channel) in channels.iter() {
        let state = *channel.inner.state.read().await;
        if state == ChannelState::Joined || state == ChannelState::Joining {
            debug!(topic = %topic, "Rejoining channel after reconnect");
            let join_ref = inner.ref_counter.next();
            let msg_ref = inner.ref_counter.next();
            // Use the stored join payload from the original subscribe
            let join_payload = channel.inner.join_payload.read().await.clone();
            let phoenix_msg = PhoenixMessage {
                event: "phx_join".to_string(),
                topic: topic.clone(),
                payload: serde_json::to_value(&join_payload).unwrap_or(json!({})),
                msg_ref: Some(msg_ref),
                join_ref: Some(join_ref),
            };
            let text = serde_json::to_string(&phoenix_msg)
                .map_err(|e| RealtimeError::ServerError(format!("JSON error: {}", e)))?;
            let mut ws = inner.ws_write.lock().await;
            if let Some(sink) = ws.as_mut() {
                sink.send(Message::Text(text.into())).await?;
            }
            *channel.inner.state.write().await = ChannelState::Joining;
        }
    }
    Ok(())
}

// ── Message Routing ───────────────────────────────────────────────────────────

async fn handle_message(inner: &RealtimeClientInner, text: &str) {
    let msg: PhoenixMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "Failed to parse Phoenix message");
            return;
        }
    };

    trace!(
        topic = %msg.topic,
        event = %msg.event,
        "Received WS message"
    );

    match msg.event.as_str() {
        "phx_reply" => handle_phx_reply(inner, msg).await,
        "postgres_changes" => handle_postgres_changes(inner, msg).await,
        "broadcast" => handle_broadcast(inner, msg).await,
        "presence_state" => handle_presence_state(inner, msg).await,
        "presence_diff" => handle_presence_diff(inner, msg).await,
        "phx_close" => handle_phx_close(inner, msg).await,
        "phx_error" => handle_phx_error(inner, msg).await,
        "system" => handle_system(inner, msg).await,
        _ => {
            trace!(event = %msg.event, "Unhandled event type");
        }
    }
}

async fn handle_phx_reply(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    // Check if this is a reply to a join (ref matches join_ref)
    if let Some(ref ref_id) = msg.msg_ref {
        let mut pending = inner.pending_replies.lock().await;
        if let Some(tx) = pending.remove(ref_id) {
            let _ = tx.send(msg);
            return;
        }
    }
    // Check if it's a reply by join_ref
    if let Some(ref join_ref) = msg.join_ref {
        let mut pending = inner.pending_replies.lock().await;
        if let Some(tx) = pending.remove(join_ref) {
            let _ = tx.send(msg);
            return;
        }
    }
}

async fn handle_postgres_changes(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    let channels = inner.channels.read().await;
    let channel = match channels.get(&msg.topic) {
        Some(ch) => ch,
        None => return,
    };

    // Parse the payload — the actual data is nested under the message
    let data = &msg.payload;

    // Extract ids from the payload to match with filter_index
    let ids_val = data.get("ids").and_then(|v| v.as_array());

    // Parse the postgres change payload from the "data" field
    let change_data = match data.get("data") {
        Some(d) => d,
        None => {
            // Sometimes the payload IS the data directly
            data
        }
    };

    let payload: PostgresChangePayload = match serde_json::from_value(change_data.clone()) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse postgres change payload");
            return;
        }
    };

    // Resolve server IDs to filter indices
    let id_map = channel.inner.pg_change_id_map.read().await;
    let matched_indices: Vec<usize> = match ids_val {
        Some(ids) => ids
            .iter()
            .filter_map(|id| id.as_u64())
            .filter_map(|server_id| id_map.get(&server_id).copied())
            .collect(),
        None => Vec::new(),
    };
    drop(id_map);

    // Dispatch to matching bindings
    let bindings = channel.inner.registry.bindings.read().await;
    for binding in bindings.iter() {
        if let Binding::PostgresChanges {
            filter_index,
            event,
            callback,
        } = binding
        {
            // Check if this binding's filter_index matches
            let matches_id = matched_indices.is_empty() || matched_indices.contains(filter_index);

            // Check event type matches
            let event_matches = match event {
                PostgresChangesEvent::All => true,
                PostgresChangesEvent::Insert => payload.change_type == "INSERT",
                PostgresChangesEvent::Update => payload.change_type == "UPDATE",
                PostgresChangesEvent::Delete => payload.change_type == "DELETE",
            };

            if matches_id && event_matches {
                callback(payload.clone());
            }
        }
    }
}

async fn handle_broadcast(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    let channels = inner.channels.read().await;
    let channel = match channels.get(&msg.topic) {
        Some(ch) => ch,
        None => return,
    };

    let event = msg
        .payload
        .get("event")
        .and_then(|e| e.as_str())
        .unwrap_or("");
    let payload = msg
        .payload
        .get("payload")
        .cloned()
        .unwrap_or(json!({}));

    let bindings = channel.inner.registry.bindings.read().await;
    for binding in bindings.iter() {
        if let Binding::Broadcast {
            event: bind_event,
            callback,
        } = binding
        {
            if bind_event == event {
                callback(payload.clone());
            }
        }
    }
}

async fn handle_presence_state(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    let channels = inner.channels.read().await;
    let channel = match channels.get(&msg.topic) {
        Some(ch) => ch,
        None => return,
    };

    let new_state = presence::apply_state(msg.payload);
    *channel.inner.presence_state.write().await = new_state.clone();

    // Dispatch sync callbacks
    let bindings = channel.inner.registry.bindings.read().await;
    for binding in bindings.iter() {
        if let Binding::PresenceSync(callback) = binding {
            callback(&new_state);
        }
    }
}

async fn handle_presence_diff(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    let channels = inner.channels.read().await;
    let channel = match channels.get(&msg.topic) {
        Some(ch) => ch,
        None => return,
    };

    let diff: PresenceDiff = match serde_json::from_value(msg.payload) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Failed to parse presence diff");
            return;
        }
    };

    let (joins, leaves) = {
        let mut state = channel.inner.presence_state.write().await;
        presence::apply_diff(&mut state, diff)
    };

    let state = channel.inner.presence_state.read().await;

    // Dispatch callbacks
    let bindings = channel.inner.registry.bindings.read().await;
    for binding in bindings.iter() {
        match binding {
            Binding::PresenceJoin(callback) => {
                for (key, metas) in &joins {
                    callback(key.clone(), metas.clone());
                }
            }
            Binding::PresenceLeave(callback) => {
                for (key, metas) in &leaves {
                    callback(key.clone(), metas.clone());
                }
            }
            Binding::PresenceSync(callback) => {
                callback(&state);
            }
            _ => {}
        }
    }
}

async fn handle_phx_close(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    let channels = inner.channels.read().await;
    if let Some(channel) = channels.get(&msg.topic) {
        *channel.inner.state.write().await = ChannelState::Closed;
        let status_cb = channel.inner.registry.status_callback.read().await;
        if let Some(cb) = status_cb.as_ref() {
            cb(SubscriptionStatus::Closed, None);
        }
    }
}

async fn handle_phx_error(inner: &RealtimeClientInner, msg: PhoenixMessage) {
    let channels = inner.channels.read().await;
    if let Some(channel) = channels.get(&msg.topic) {
        *channel.inner.state.write().await = ChannelState::Errored;
        let reason = msg
            .payload
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("unknown")
            .to_string();
        let status_cb = channel.inner.registry.status_callback.read().await;
        if let Some(cb) = status_cb.as_ref() {
            cb(
                SubscriptionStatus::ChannelError,
                Some(RealtimeError::ServerError(reason)),
            );
        }
    }
}

async fn handle_system(_inner: &RealtimeClientInner, msg: PhoenixMessage) {
    // System messages can include subscription confirmations, extensions info, etc.
    debug!(
        topic = %msg.topic,
        payload = %msg.payload,
        "System message received"
    );
}

async fn notify_all_channels_closed(inner: &RealtimeClientInner) {
    let channels = inner.channels.read().await;
    for channel in channels.values() {
        let current = *channel.inner.state.read().await;
        if current == ChannelState::Joined || current == ChannelState::Joining {
            *channel.inner.state.write().await = ChannelState::Closed;
            let status_cb = channel.inner.registry.status_callback.read().await;
            if let Some(cb) = status_cb.as_ref() {
                cb(SubscriptionStatus::Closed, None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ReconnectConfig;

    #[test]
    fn test_build_ws_url_http() {
        let url = build_ws_url("http://localhost:54321", "test-key").unwrap();
        assert_eq!(
            url,
            "ws://localhost:54321/realtime/v1/websocket?apikey=test-key&vsn=1.0.0"
        );
    }

    #[test]
    fn test_build_ws_url_https() {
        let url = build_ws_url("https://example.supabase.co", "anon-key").unwrap();
        assert_eq!(
            url,
            "wss://example.supabase.co/realtime/v1/websocket?apikey=anon-key&vsn=1.0.0"
        );
    }

    #[test]
    fn test_build_ws_url_with_path() {
        let url = build_ws_url("http://localhost:54321/", "key").unwrap();
        assert!(url.starts_with("ws://localhost:54321/realtime/v1/websocket"));
    }

    #[test]
    fn test_build_ws_url_invalid_scheme() {
        let result = build_ws_url("ftp://localhost", "key");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_auth_requires_connection() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = RealtimeClient::new("http://localhost:54321", "test-key").unwrap();
        // Not connected → should error
        let result = rt.block_on(client.set_auth("new-token"));
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_headers_stored() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom-Header".to_string(), "custom-value".to_string());
        let config = RealtimeConfig::new("http://localhost:54321", "test-key")
            .with_headers(headers);
        assert_eq!(config.headers.len(), 1);
        assert_eq!(config.headers.get("X-Custom-Header").unwrap(), "custom-value");
    }

    #[test]
    fn test_custom_headers_default_empty() {
        let config = RealtimeConfig::new("http://localhost:54321", "test-key");
        assert!(config.headers.is_empty());
    }

    #[test]
    fn test_intentional_disconnect_flag() {
        let client = RealtimeClient::new("http://localhost:54321", "test-key").unwrap();
        assert!(!client.inner.intentional_disconnect.load(Ordering::SeqCst));
    }

    #[test]
    fn test_reconnect_config_intervals() {
        let config = ReconnectConfig::default();
        assert_eq!(config.intervals.len(), 4);
        assert_eq!(config.intervals[0], Duration::from_secs(1));
        assert_eq!(config.intervals[3], Duration::from_secs(10));
        assert_eq!(config.fallback, Duration::from_secs(10));
    }
}
