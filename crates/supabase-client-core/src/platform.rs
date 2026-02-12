//! Platform abstractions for cross-platform async operations.
//!
//! Provides unified APIs for spawning tasks, sleeping, and timeouts
//! that work on both native (tokio) and WASM (wasm-bindgen-futures + gloo) targets.

use std::future::Future;
use std::time::Duration;

// ── Spawn ────────────────────────────────────────────────────────────────────

/// Spawn a future as a background task.
///
/// - **Native:** Uses `tokio::spawn` (requires `Send + 'static`).
/// - **WASM:** Uses `wasm_bindgen_futures::spawn_local` (no `Send` required).
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F>(future: F) -> SpawnHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    SpawnHandle {
        handle: tokio::spawn(future),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F>(future: F) -> SpawnHandle
where
    F: Future<Output = ()> + 'static,
{
    let (abort_tx, abort_rx) = tokio::sync::oneshot::channel::<()>();
    wasm_bindgen_futures::spawn_local(async move {
        futures_util::pin_mut!(future);
        futures_util::future::select(future, abort_rx).await;
    });
    SpawnHandle { abort_tx: Some(abort_tx) }
}

// ── SpawnHandle ──────────────────────────────────────────────────────────────

/// Handle to a spawned background task, allowing cancellation.
#[cfg(not(target_arch = "wasm32"))]
pub struct SpawnHandle {
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(not(target_arch = "wasm32"))]
impl SpawnHandle {
    /// Abort the spawned task.
    pub fn abort(&self) {
        self.handle.abort();
    }
}

#[cfg(target_arch = "wasm32")]
pub struct SpawnHandle {
    abort_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(target_arch = "wasm32")]
impl SpawnHandle {
    /// Abort the spawned task.
    pub fn abort(&mut self) {
        if let Some(tx) = self.abort_tx.take() {
            let _ = tx.send(());
        }
    }
}

// ── Sleep ────────────────────────────────────────────────────────────────────

/// Sleep for the given duration.
///
/// - **Native:** Uses `tokio::time::sleep`.
/// - **WASM:** Uses `gloo_timers::future::sleep`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await;
}

// ── Timeout ──────────────────────────────────────────────────────────────────

/// Error returned when a timeout expires.
#[derive(Debug, Clone)]
pub struct TimeoutError;

impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "operation timed out")
    }
}

impl std::error::Error for TimeoutError {}

/// Run a future with a timeout.
///
/// - **Native:** Uses `tokio::time::timeout`.
/// - **WASM:** Races the future against `gloo_timers::future::sleep`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn timeout<F, T>(duration: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| TimeoutError)
}

#[cfg(target_arch = "wasm32")]
pub async fn timeout<F, T>(duration: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    use futures_util::future::{select, Either};

    futures_util::pin_mut!(future);
    let sleep = gloo_timers::future::sleep(duration);
    futures_util::pin_mut!(sleep);

    match select(future, sleep).await {
        Either::Left((output, _)) => Ok(output),
        Either::Right((_, _)) => Err(TimeoutError),
    }
}
