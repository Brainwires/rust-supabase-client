//! Native WebSocket transport using tokio-tungstenite.

use std::sync::Arc;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::Message;

use crate::error::RealtimeError;
use crate::types::RealtimeConfig;

pub(crate) type WsSink = SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;

pub(crate) type WsRead = SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
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
            http::header::HeaderValue::from_str(value.as_str()).map_err(|e| {
                RealtimeError::InvalidConfig(format!("Invalid header value: {}", e))
            })?,
        );
    }

    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(rustls_client_config()?));
    let connect =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector));
    let (ws_stream, _) = tokio::time::timeout(config.connect_timeout, connect)
        .await
        .map_err(|_| {
            RealtimeError::WebSocket(tokio_tungstenite::tungstenite::Error::Io(
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "WebSocket connection timed out after {:?}",
                        config.connect_timeout
                    ),
                ),
            ))
        })??;
    let (write, read) = ws_stream.split();
    Ok((write, read))
}

/// Build the rustls client config for `wss://` connections with an explicit
/// crypto provider.
///
/// `ClientConfig::builder()` (what tokio-tungstenite uses by default) panics
/// with "Could not automatically determine the process-level CryptoProvider"
/// when more than one rustls backend is compiled in, e.g. reqwest 0.13
/// (aws-lc-rs) next to sqlx (ring). Use the process default provider when
/// the application installed one, otherwise ring.
fn rustls_client_config() -> Result<rustls::ClientConfig, RealtimeError> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| RealtimeError::InvalidConfig(format!("TLS configuration error: {}", e)))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
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
/// Pong, binary and raw frames are skipped: they are not end of stream.
pub(crate) async fn recv_message(read: &mut WsRead) -> Option<Result<WsMessage, RealtimeError>> {
    loop {
        return match read.next().await? {
            Ok(Message::Text(text)) => Some(Ok(WsMessage::Text(text.to_string()))),
            Ok(Message::Close(_)) => Some(Ok(WsMessage::Close)),
            Ok(Message::Ping(data)) => Some(Ok(WsMessage::Ping(data.to_vec()))),
            Ok(Message::Pong(_)) | Ok(Message::Binary(_)) | Ok(Message::Frame(_)) => continue,
            Err(e) => Some(Err(RealtimeError::WebSocket(e))),
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_builds_with_several_crypto_providers_compiled_in() {
        // Tests compile rustls with both ring and aws-lc-rs and install no
        // process default, the setup in which `ClientConfig::builder()`
        // panics.
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        rustls_client_config().unwrap();
    }

    #[test]
    #[should_panic(expected = "CryptoProvider")]
    fn default_builder_panics_in_the_same_setup() {
        // Documents the failure mode the explicit provider avoids.
        let _ = rustls::ClientConfig::builder();
    }
}
