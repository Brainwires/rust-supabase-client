//! WASM WebSocket transport using web_sys::WebSocket.
//!
//! Bridges web_sys callback-based WebSocket API into async channels
//! compatible with the client's message loop.

use std::sync::Arc;

use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::error::RealtimeError;
use crate::types::RealtimeConfig;

/// Write half: holds the web_sys::WebSocket for sending.
pub(crate) struct WsSink {
    ws: web_sys::WebSocket,
}

/// Read half: receives messages via an mpsc channel fed by JS callbacks.
pub(crate) struct WsRead {
    rx: mpsc::UnboundedReceiver<Result<WsMessage, RealtimeError>>,
    /// Must be kept alive to prevent closures from being dropped.
    _closures: Arc<WsClosures>,
}

/// Prevents JS closures from being garbage collected.
struct WsClosures {
    _on_message: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _on_error: Closure<dyn FnMut(web_sys::ErrorEvent)>,
    _on_close: Closure<dyn FnMut(web_sys::CloseEvent)>,
}

/// Platform-neutral WebSocket message type.
pub(crate) enum WsMessage {
    Text(String),
    Close,
    #[allow(dead_code)]
    Ping(Vec<u8>),
}

/// Connect to a WebSocket URL and return split (sink, read).
pub(crate) async fn connect_ws(
    _config: &RealtimeConfig,
    ws_url: &str,
) -> Result<(WsSink, WsRead), RealtimeError> {
    let ws = web_sys::WebSocket::new(ws_url)
        .map_err(|e| RealtimeError::WebSocket(format!("Failed to create WebSocket: {:?}", e)))?;

    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    let (tx, rx) = mpsc::unbounded_channel();

    // onmessage callback
    let tx_msg = tx.clone();
    let on_message = Closure::<dyn FnMut(_)>::new(move |event: web_sys::MessageEvent| {
        if let Ok(text) = event.data().dyn_into::<js_sys::JsString>() {
            let _ = tx_msg.send(Ok(WsMessage::Text(String::from(text))));
        }
    });
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    // onerror callback
    let tx_err = tx.clone();
    let on_error = Closure::<dyn FnMut(_)>::new(move |_event: web_sys::ErrorEvent| {
        let _ = tx_err.send(Err(RealtimeError::WebSocket("WebSocket error".to_string())));
    });
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    // onclose callback
    let tx_close = tx;
    let on_close = Closure::<dyn FnMut(_)>::new(move |_event: web_sys::CloseEvent| {
        let _ = tx_close.send(Ok(WsMessage::Close));
    });
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    // Wait for connection to open
    let (open_tx, open_rx) = tokio::sync::oneshot::channel::<Result<(), RealtimeError>>();
    let on_open = Closure::once(move || {
        let _ = open_tx.send(Ok(()));
    });
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

    // Await open with timeout
    let open_result = supabase_client_core::platform::timeout(
        std::time::Duration::from_secs(10),
        async {
            open_rx.await.unwrap_or(Err(RealtimeError::ConnectionClosed))
        },
    ).await;

    match open_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(RealtimeError::WebSocket("WebSocket connection timed out".to_string())),
    }

    // Keep closures alive
    let closures = Arc::new(WsClosures {
        _on_message: on_message,
        _on_error: on_error,
        _on_close: on_close,
    });

    Ok((
        WsSink { ws },
        WsRead { rx, _closures: closures },
    ))
}

/// Send a text message over the WebSocket.
pub(crate) async fn send_text(sink: &mut WsSink, text: String) -> Result<(), RealtimeError> {
    sink.ws
        .send_with_str(&text)
        .map_err(|e| RealtimeError::WebSocket(format!("Send failed: {:?}", e)))?;
    Ok(())
}

/// Send a close frame over the WebSocket.
pub(crate) async fn send_close(sink: &mut WsSink) -> Result<(), RealtimeError> {
    let _ = sink.ws.close();
    Ok(())
}

/// Receive the next message from the WebSocket.
pub(crate) async fn recv_message(read: &mut WsRead) -> Option<Result<WsMessage, RealtimeError>> {
    read.rx.recv().await
}

/// Send a pong response (no-op on WASM — browser handles ping/pong).
pub(crate) async fn send_pong(_sink: &mut WsSink, _data: Vec<u8>) -> Result<(), RealtimeError> {
    Ok(())
}
