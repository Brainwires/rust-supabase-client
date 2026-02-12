//! Native WebSocket transport using tokio-tungstenite.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::Message;

use crate::error::RealtimeError;
use crate::types::RealtimeConfig;

pub(crate) type WsSink = SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    Message,
>;

pub(crate) type WsRead = SplitStream<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
>;

/// Connect to a WebSocket URL and return split (sink, stream).
pub(crate) async fn connect_ws(
    config: &RealtimeConfig,
    ws_url: &str,
) -> Result<(WsSink, WsRead), RealtimeError> {
    let uri: http::Uri = ws_url
        .parse()
        .map_err(|e| RealtimeError::InvalidConfig(format!("Invalid WS URL: {}", e)))?;

    let mut request = uri
        .into_client_request()
        .map_err(|e| RealtimeError::InvalidConfig(format!("Failed to build WS request: {}", e)))?;

    for (key, value) in &config.headers {
        request.headers_mut().insert(
            http::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| RealtimeError::InvalidConfig(format!("Invalid header name: {}", e)))?,
            http::header::HeaderValue::from_str(value.as_str())
                .map_err(|e| RealtimeError::InvalidConfig(format!("Invalid header value: {}", e)))?,
        );
    }

    let (ws_stream, _) = tokio_tungstenite::connect_async(request).await?;
    let (write, read) = ws_stream.split();
    Ok((write, read))
}

/// Send a text message over the WebSocket sink.
pub(crate) async fn send_text(sink: &mut WsSink, text: String) -> Result<(), RealtimeError> {
    sink.send(Message::Text(text.into())).await?;
    Ok(())
}

/// Send a close frame over the WebSocket sink.
pub(crate) async fn send_close(sink: &mut WsSink) -> Result<(), RealtimeError> {
    let _ = sink.send(Message::Close(None)).await;
    Ok(())
}

/// Receive the next message from the WebSocket stream.
///
/// Returns `None` when the stream ends.
pub(crate) async fn recv_message(read: &mut WsRead) -> Option<Result<WsMessage, RealtimeError>> {
    match read.next().await {
        Some(Ok(Message::Text(text))) => Some(Ok(WsMessage::Text(text.to_string()))),
        Some(Ok(Message::Close(_))) => Some(Ok(WsMessage::Close)),
        Some(Ok(Message::Ping(data))) => Some(Ok(WsMessage::Ping(data.to_vec()))),
        Some(Ok(Message::Pong(_))) => None, // Ignore pong
        Some(Err(e)) => Some(Err(RealtimeError::WebSocket(e))),
        None => None,
        _ => None, // Binary, Frame — ignore
    }
}

/// Send a pong response.
pub(crate) async fn send_pong(sink: &mut WsSink, data: Vec<u8>) -> Result<(), RealtimeError> {
    sink.send(Message::Pong(data.into())).await?;
    Ok(())
}

/// Platform-neutral WebSocket message type.
pub(crate) enum WsMessage {
    Text(String),
    Close,
    Ping(Vec<u8>),
}
