//! The resolved, role-dependent peer parameters.
//!
//! Both the interactive in-TUI setup and the env-var (test) path produce a
//! [`ResolvedPeer`]; it is the only role-dependent input to building the runtime
//! [`crate::iroh_mode::PeerConfig`].

use iroh::EndpointId;

use crate::app_state::Role;
use crate::config::AllowedSources;

/// Role + target + credential, fully validated.
///
/// Invariants (enforced where constructed):
/// - `Dial` ⇒ `auth_token` passed `validate_token`. `peer_node_id` is `Some` when
///   entered/supplied directly, or `None` when it will be discovered via nostr at
///   runtime (keyed off `auth_token`).
/// - `Listen` ⇒ `peer_node_id.is_none()`; `auth_token` is a valid supplied token
///   or a freshly generated one.
#[derive(Clone)]
pub struct ResolvedPeer {
    pub role: Role,
    /// Target node id, or `None` for a dialer that discovers it via nostr.
    pub peer_node_id: Option<EndpointId>,
    pub auth_token: String,
    /// `true` when `auth_token` was freshly generated (no token in config/env), so
    /// the TUI must surface it for the user to copy. `false` when supplied.
    pub token_generated: bool,
    /// CIDR allowlist gating which of our sources the peer may request. Supplied by
    /// config, or entered interactively in setup when config provides none.
    pub allowed_sources: AllowedSources,
}
