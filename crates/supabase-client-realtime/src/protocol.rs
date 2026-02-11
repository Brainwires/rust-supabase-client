use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use crate::types::{JoinPayload, PhoenixMessage};

/// Atomic counter for generating unique message reference IDs.
pub(crate) struct RefCounter {
    counter: AtomicU64,
}

impl RefCounter {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }

    pub fn next(&self) -> String {
        self.counter.fetch_add(1, Ordering::Relaxed).to_string()
    }
}

/// Build a heartbeat message (sent to topic "phoenix").
pub(crate) fn build_heartbeat(ref_counter: &RefCounter) -> PhoenixMessage {
    PhoenixMessage {
        event: "heartbeat".to_string(),
        topic: "phoenix".to_string(),
        payload: json!({}),
        msg_ref: Some(ref_counter.next()),
        join_ref: None,
    }
}

/// Build a phx_join message for a channel.
pub(crate) fn build_join(
    topic: &str,
    join_payload: &JoinPayload,
    ref_counter: &RefCounter,
) -> PhoenixMessage {
    let ref_id = ref_counter.next();
    PhoenixMessage {
        event: "phx_join".to_string(),
        topic: topic.to_string(),
        payload: serde_json::to_value(join_payload).unwrap_or(json!({})),
        msg_ref: Some(ref_id.clone()),
        join_ref: Some(ref_id),
    }
}

/// Build a phx_leave message for a channel.
pub(crate) fn build_leave(
    topic: &str,
    join_ref: &str,
    ref_counter: &RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        event: "phx_leave".to_string(),
        topic: topic.to_string(),
        payload: json!({}),
        msg_ref: Some(ref_counter.next()),
        join_ref: Some(join_ref.to_string()),
    }
}

/// Build a broadcast message.
pub(crate) fn build_broadcast(
    topic: &str,
    event: &str,
    payload: Value,
    join_ref: &str,
    ref_counter: &RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        event: "broadcast".to_string(),
        topic: topic.to_string(),
        payload: json!({
            "event": event,
            "payload": payload,
            "type": "broadcast",
        }),
        msg_ref: Some(ref_counter.next()),
        join_ref: Some(join_ref.to_string()),
    }
}

/// Build a presence track message.
pub(crate) fn build_presence_track(
    topic: &str,
    payload: Value,
    join_ref: &str,
    ref_counter: &RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        event: "presence".to_string(),
        topic: topic.to_string(),
        payload: json!({
            "type": "presence",
            "event": "track",
            "payload": payload,
        }),
        msg_ref: Some(ref_counter.next()),
        join_ref: Some(join_ref.to_string()),
    }
}

/// Build a presence untrack message.
pub(crate) fn build_presence_untrack(
    topic: &str,
    join_ref: &str,
    ref_counter: &RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        event: "presence".to_string(),
        topic: topic.to_string(),
        payload: json!({
            "type": "presence",
            "event": "untrack",
        }),
        msg_ref: Some(ref_counter.next()),
        join_ref: Some(join_ref.to_string()),
    }
}

/// Build an access_token refresh message.
pub(crate) fn build_access_token(
    topic: &str,
    token: &str,
    join_ref: &str,
    ref_counter: &RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        event: "access_token".to_string(),
        topic: topic.to_string(),
        payload: json!({ "access_token": token }),
        msg_ref: Some(ref_counter.next()),
        join_ref: Some(join_ref.to_string()),
    }
}
