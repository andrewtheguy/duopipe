//! Iroh-based networking components.
//!
//! This module provides:
//! - `endpoint`: Iroh endpoint creation and connection helpers
//! - `peer`: Symmetric peer mode — one connection, many tunnels in both directions
//! - `helpers`: Shared stream and connection helpers (internal)

pub mod endpoint;
mod helpers;
mod peer;

// Re-export public API
pub use peer::{run_peer, PeerConfig};
