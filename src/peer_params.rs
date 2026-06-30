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
/// - `Dial` ⇒ `auth_token` passed `validate_token`, and exactly one target is set:
///   `peer_node_id` (quick mode, entered directly) or `peer_identifier` (connect mode,
///   the target peer's name, resolved to a node id at runtime via `auth_token`).
/// - `Listen` ⇒ `peer_node_id` and `peer_identifier` are `None`; `auth_token` is a
///   valid supplied token or a freshly generated one.
/// - `Both` ⇒ the interactive mode: always serving with an on-demand dial session. No
///   target is set here (`peer_node_id`/`peer_identifier` are `None`) — the user
///   supplies the dial target at runtime via the connect prompt. `auth_token` is valid
///   (supplied or generated).
#[derive(Clone)]
pub struct ResolvedPeer {
    pub role: Role,
    /// Target node id (quick-mode dial), or `None` in connect mode where the target is
    /// named by `peer_identifier`.
    pub peer_node_id: Option<EndpointId>,
    /// Target peer's nostr identifier (nostr-mode dial), looked up at runtime. `None`
    /// for quick mode and for listeners.
    pub peer_identifier: Option<String>,
    pub auth_token: String,
    /// `true` when `auth_token` was freshly generated (no token in config/env), so
    /// the TUI must surface it for the user to copy. `false` when supplied.
    pub token_generated: bool,
}
