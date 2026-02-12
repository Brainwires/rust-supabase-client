use std::time::Duration;

use crate::types::ChannelState;
use supabase_client_core::SupabaseError;

#[derive(Debug, thiserror::Error)]
pub enum RealtimeError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[cfg(target_arch = "wasm32")]
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Channel not found: {0}")]
    ChannelNotFound(String),

    #[error("Channel already exists: {0}")]
    ChannelAlreadyExists(String),

    #[error("Invalid channel state: expected {expected:?}, actual {actual:?}")]
    InvalidChannelState {
        expected: ChannelState,
        actual: ChannelState,
    },

    #[error("Subscribe timed out after {0:?}")]
    SubscribeTimeout(Duration),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<RealtimeError> for SupabaseError {
    fn from(e: RealtimeError) -> Self {
        SupabaseError::Realtime(e.to_string())
    }
}
