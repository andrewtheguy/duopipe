//! The resolved, role-dependent peer parameters.
//!
//! Both the interactive in-TUI setup and the env-var (test) path produce a
//! [`ResolvedPeer`]; it is the only role-dependent input to building the runtime
//! [`crate::iroh_mode::PeerConfig`].

use iroh::EndpointId;

use crate::app_state::Role;

/// Role + target + credential, fully validated.
///
/// Invariants (enforced where constructed):
/// - `Dial` ⇒ `peer_node_id.is_some()` and `auth_token` passed `validate_token`.
/// - `Listen` ⇒ `peer_node_id.is_none()`; `auth_token` is a valid supplied token
///   or a freshly generated one.
#[derive(Clone)]
pub struct ResolvedPeer {
    pub role: Role,
    pub peer_node_id: Option<EndpointId>,
    pub auth_token: String,
    /// `true` when `auth_token` was freshly generated (no token in config/env), so
    /// the TUI must surface it for the user to copy. `false` when supplied.
    pub token_generated: bool,
}
