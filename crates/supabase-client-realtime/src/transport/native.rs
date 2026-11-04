//! Native WebSocket transport using tokio-tungstenite.

#[cfg(feature = "rustls")]
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

    let connect =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, tls_connector()?);
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

/// TLS connector for `wss://` URLs.
///
/// With the `rustls` feature, an explicit rustls config (see
/// [`rustls_client_config`]); it takes precedence when both TLS features are
/// enabled. With only `native-tls`, `None` lets tokio-tungstenite use
/// native-tls. With neither, `wss://` URLs fail with a "TLS support not
/// compiled in" error.
#[cfg(feature = "rustls")]
fn tls_connector() -> Result<Option<tokio_tungstenite::Connector>, RealtimeError> {
    Ok(Some(tokio_tungstenite::Connector::Rustls(Arc::new(
        rustls_client_config()?,
    ))))
}

#[cfg(not(feature = "rustls"))]
fn tls_connector() -> Result<Option<tokio_tungstenite::Connector>, RealtimeError> {
    Ok(None)
}

/// Build the rustls client config for `wss://` connections with an explicit
/// crypto provider.
///
/// `ClientConfig::builder()` (what tokio-tungstenite uses by default) panics
/// with "Could not automatically determine the process-level CryptoProvider"
/// when the application links more than one rustls backend (e.g. another
/// dependency enables rustls' `ring` feature next to our aws-lc-rs). Use the
/// process default provider when the application installed one, otherwise
/// aws-lc-rs, the provider reqwest's `rustls` feature uses.
///
/// Certificates are checked by the OS verifier (rustls-platform-verifier),
/// the same one reqwest uses, so HTTP and WebSocket connections trust the
/// same certificate store.
#[cfg(feature = "rustls")]
fn rustls_client_config() -> Result<rustls::ClientConfig, RealtimeError> {
    use rustls_platform_verifier::BuilderVerifierExt;

    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let tls_err =
        |e: rustls::Error| RealtimeError::InvalidConfig(format!("TLS configuration error: {}", e));
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(tls_err)?
        .with_platform_verifier()
        .map_err(tls_err)?
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

#[cfg(all(test, feature = "rustls"))]
mod tests {
    use super::*;

    #[test]
    fn tls_config_builds_with_several_crypto_providers_compiled_in() {
        // Tests compile rustls with both ring and aws-lc-rs (see the
        // dev-dependencies) and install no process default, the setup in
        // which `ClientConfig::builder()` panics.
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let config = rustls_client_config().unwrap();
        // Falls back to aws-lc-rs, not ring (their key-exchange groups
        // differ: aws-lc-rs offers the post-quantum X25519MLKEM768 hybrid).
        let kx_names = |p: &rustls::crypto::CryptoProvider| -> Vec<_> {
            p.kx_groups.iter().map(|g| g.name()).collect()
        };
        let aws_lc = rustls::crypto::aws_lc_rs::default_provider();
        let ring = rustls::crypto::ring::default_provider();
        assert_ne!(kx_names(&aws_lc), kx_names(&ring));
        assert_eq!(kx_names(config.crypto_provider()), kx_names(&aws_lc));
    }

    #[test]
    #[should_panic(expected = "CryptoProvider")]
    fn default_builder_panics_in_the_same_setup() {
        // Documents the failure mode the explicit provider avoids.
        let _ = rustls::ClientConfig::builder();
    }
}
