//! Platform-specific WebSocket transport.
//!
//! Provides a unified interface for connecting, sending, and receiving
//! WebSocket messages on both native and WASM targets.

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::*;

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::*;
