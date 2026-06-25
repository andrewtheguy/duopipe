//! Shared runtime state surfaced by the TUI.
//!
//! The peer runtime writes status transitions here; the TUI polls
//! [`AppState::snapshot`] on a tick and renders from the owned snapshot. All
//! writers are synchronous and never hold a lock across `.await`, so the
//! `parking_lot` locks are safe inside async tasks. The session gauge reads the
//! live [`Semaphore`] so it can never drift from the real limiter.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use iroh::EndpointId;
use parking_lot::RwLock;
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use crate::config::TunnelEntry;
use crate::logging::LogBuffer;

/// Capacity of the tunnel-command broadcast channel (commands are tiny; this
/// only bounds how far a lagging connection supervisor may fall behind).
const TUNNEL_COMMAND_CAPACITY: usize = 64;
const DIAL_COMMAND_CAPACITY: usize = 16;
const NAME_COMMAND_CAPACITY: usize = 8;

/// Stable identity for a tunnel, allocated once when the tunnel is added
/// (config-seeded or runtime) and unchanged for the life of the session, including
/// across reconnect reseeds. Identity is decoupled from the vec position so tunnels
/// can be removed without disturbing the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelId(u64);

impl std::fmt::Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A request to start or stop a configured tunnel, addressed by its stable
/// [`TunnelId`]. Sent by the TUI, consumed by the connection supervisor.
#[derive(Debug, Clone, Copy)]
pub enum TunnelCommand {
    Start(TunnelId),
    Stop(TunnelId),
}

/// A runtime request to the dial manager to (re)point or tear down the single
/// outbound dial session. Sent by the TUI, consumed by `run_dial_manager`.
#[derive(Debug, Clone)]
pub enum DialCommand {
    /// Start a dial session to this target, replacing any current one.
    Connect(DialTarget),
    /// Tear down the current dial session and return to idle.
    Disconnect,
}

/// A user decision on a nostr name conflict, sent by the TUI's conflict prompt to the
/// node-id publisher. All unit variants — "rename" carries no new name: it appends a
/// nudge comment to the config and then behaves like decline (the running name is never
/// changed live).
#[derive(Debug, Clone, Copy)]
pub enum NameCommand {
    /// Claim/reclaim the name: clear the flag and (re)publish, gaining precedence.
    TakeOver,
    /// Append a rename nudge to the config, then decline.
    Rename,
    /// Stop competing for the name (quit at startup / degraded serve-only mid-session).
    Decline,
}

/// Surfaced state of the nostr name-conflict flow, polled by the TUI each tick. The
/// publisher sets it; the TUI renders a modal (`Prompt`) or a persistent warning
/// (`Degraded`) from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NameConflict {
    /// No conflict: publishing normally (or nostr discovery is off).
    #[default]
    Inactive,
    /// A conflict needs a user decision; `message` is the full prompt body (the
    /// publisher bakes in the situation and the per-key consequences).
    Prompt { message: String },
    /// The user declined or renamed mid-session: serving continues but the name is no
    /// longer published. `message` is a persistent warning.
    Degraded { message: String },
}

/// What to dial, as typed at runtime: a full node id (quick mode) or a peer name
/// looked up via nostr (nostr mode).
#[derive(Debug, Clone)]
pub enum DialTarget {
    NodeId(EndpointId),
    Name(String),
}

impl DialTarget {
    /// Short human-readable form for the TUI (`dial → …`).
    pub fn describe(&self) -> String {
        match self {
            DialTarget::NodeId(id) => {
                let s = id.to_string();
                // Mirror the peer-list short id (first 12 chars).
                s.chars().take(12).collect::<String>() + "…"
            }
            DialTarget::Name(name) => name.clone(),
        }
    }
}

/// Internal role of this peer. Every interactive run is `Both` (the single combined
/// mode); the single-direction `Dial`/`Listen` variants exist only for the headless
/// test path. This is not a startup choice the user makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Dial,
    Listen,
    /// The combined mode used by every interactive run: a serve half that handles
    /// inbound peers *and* a dial session that maintains one outbound connection
    /// requesting tunnels. Each underlying connection still has exactly one requester
    /// and one server — the two halves run side by side over separate endpoints and
    /// never interact at the connection layer.
    Both,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Dial => "Dial",
            Role::Listen => "Listen",
            Role::Both => "Serve + Dial",
        }
    }
}

/// High-level connection status (primarily meaningful for the dial session, which
/// has a single outbound connection at a time).
#[derive(Clone, PartialEq)]
pub enum ConnStatus {
    /// No dial session: serving only, waiting for the user to dial a peer.
    Idle,
    Connecting,
    Authenticating,
    Connected,
    Closed,
    Reconnecting { backoff_secs: u64 },
}

impl ConnStatus {
    pub fn label(&self) -> String {
        match self {
            ConnStatus::Idle => "Idle".to_string(),
            ConnStatus::Connecting => "Connecting".to_string(),
            ConnStatus::Authenticating => "Authenticating".to_string(),
            ConnStatus::Connected => "Connected".to_string(),
            ConnStatus::Closed => "Closed".to_string(),
            ConnStatus::Reconnecting { backoff_secs } => {
                format!("Reconnecting ({backoff_secs}s)")
            }
        }
    }
}

/// The kind of network path a connection is using.
#[derive(Clone)]
pub enum PathKind {
    Establishing,
    Direct(String),
    Relay(String),
}

/// Selected path plus its measured round-trip time.
#[derive(Clone)]
pub struct PathInfo {
    pub kind: PathKind,
    pub rtt_ms: Option<f64>,
}

impl PathInfo {
    pub fn establishing() -> Self {
        Self {
            kind: PathKind::Establishing,
            rtt_ms: None,
        }
    }

    /// One-line description, e.g. "Direct 1.2.3.4:5 (12ms)".
    pub fn describe(&self) -> String {
        let base = match &self.kind {
            PathKind::Establishing => "establishing…".to_string(),
            PathKind::Direct(addr) => format!("Direct {addr}"),
            PathKind::Relay(url) => format!("Relay {url}"),
        };
        match self.rtt_ms {
            Some(rtt) => format!("{base} ({rtt:.0}ms)"),
            None => base,
        }
    }
}

/// Lifecycle status of a configured tunnel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TunnelStatus {
    /// Configured but not started (or stopped).
    Idle,
    /// Local listener is bound and the tunnel is active.
    Listening,
    /// The tunnel failed (bind error, peer rejection, etc.).
    Error,
}

impl TunnelStatus {
    pub fn label(self) -> &'static str {
        match self {
            TunnelStatus::Idle => "Idle",
            TunnelStatus::Listening => "Listening",
            TunnelStatus::Error => "Error",
        }
    }

    /// Whether the tunnel is currently running (toggling it should stop it).
    pub fn is_running(self) -> bool {
        matches!(self, TunnelStatus::Listening)
    }
}

/// A configured tunnel and its current status. Carries the tunnel's stable
/// [`TunnelId`]; rows are kept in display order, but the id (not the position) is the
/// identity used to start/stop/delete it.
#[derive(Clone)]
pub struct TunnelRow {
    /// Stable identity of the underlying tunnel.
    pub id: TunnelId,
    /// Display label from the tunnel's `name`.
    pub name: String,
    /// Human-readable "LISTEN <- SOURCE" description.
    pub spec: String,
    pub status: TunnelStatus,
    /// Bound address or rejection/error reason.
    pub detail: String,
}

/// A configured tunnel paired with its stable id. The authoritative spec
/// list (`AppState::specs`) is seeded from config and appended to at runtime.
struct TunnelSpec {
    id: TunnelId,
    entry: TunnelEntry,
}

/// Build the `Idle` tunnel row for a tunnel (centralizes the spec format used by
/// both seeding and runtime additions).
fn tunnel_row_for(id: TunnelId, entry: &TunnelEntry) -> TunnelRow {
    TunnelRow {
        id,
        name: entry.name.clone(),
        spec: format!("{} <- {}", entry.local_listen, entry.remote_source),
        status: TunnelStatus::Idle,
        detail: String::new(),
    }
}

/// A currently-connected, authenticated inbound peer. The serve half handles
/// many of these at once — one row per live inbound connection.
#[derive(Clone)]
pub struct PeerRow {
    pub remote_id: String,
    pub connected_since: Instant,
    pub path: PathInfo,
}

/// Shared application state. Construct via [`AppState::new`], wrap in `Arc`.
pub struct AppState {
    pub role: Role,
    /// This machine's hostname, shown in the dashboard title.
    pub hostname: String,
    /// `true` when the auth token was freshly generated (not supplied by
    /// config/env), so the dashboard flags it for the user to copy.
    pub token_generated: bool,
    /// The shared auth token, shown in the dashboard so a peer can copy it (it may be
    /// freshly generated each run).
    auth_token: RwLock<Option<String>>,
    endpoint_id: RwLock<Option<String>>,
    conn_status: RwLock<ConnStatus>,
    path: RwLock<PathInfo>,
    /// Currently-connected inbound peers (the serve half handles many at once; the
    /// dial session tracks its own outbound path separately via `path`).
    peers: RwLock<Vec<PeerRow>>,
    /// Monotonic allocator for [`TunnelId`]s. Never reused within a session.
    next_id: AtomicU64,
    /// Authoritative tunnel list: seeded from config and appended to at runtime via
    /// [`AppState::add_tunnel`]. `tunnels` is kept 1:1 with this (same order), but
    /// identity is the [`TunnelId`], not the vec position.
    specs: RwLock<Vec<TunnelSpec>>,
    tunnels: RwLock<Vec<TunnelRow>>,
    /// Live stream limiter; `used = max - available_permits()`. One global cap on
    /// concurrent forwarded streams across all tunnels and all connected peers.
    semaphore: RwLock<Option<Arc<Semaphore>>>,
    streams_max: RwLock<usize>,
    /// Broadcast channel for tunnel start/stop commands (TUI -> connection supervisor).
    tunnel_tx: broadcast::Sender<TunnelCommand>,
    /// Broadcast channel for dial connect/disconnect commands (TUI -> dial manager).
    dial_tx: broadcast::Sender<DialCommand>,
    /// Broadcast channel for name-conflict decisions (TUI -> node-id publisher).
    name_tx: broadcast::Sender<NameCommand>,
    /// Current nostr name-conflict state, surfaced to the TUI.
    name_conflict: RwLock<NameConflict>,
    /// Display string for the current dial target (`Some` while a session is up or
    /// being established), shown in the header. `None` when idle (serving only).
    dial_target: RwLock<Option<String>>,
    /// Whether nostr discovery is active (nostr mode). Read by the connect prompt to
    /// decide whether the user types a peer name (true) or a node id (false).
    pub nostr_discovery: bool,
    /// This machine's own nostr name (config `name`), used by the connect prompt to
    /// reject dialing ourselves. `None` in quick mode.
    pub own_name: Option<String>,
    pub shutdown: CancellationToken,
    pub logs: Arc<LogBuffer>,
}

impl AppState {
    pub fn new(
        role: Role,
        token_generated: bool,
        logs: Arc<LogBuffer>,
        tunnels: Vec<TunnelEntry>,
        nostr_discovery: bool,
        own_name: Option<String>,
    ) -> Arc<Self> {
        let (tunnel_tx, _) = broadcast::channel(TUNNEL_COMMAND_CAPACITY);
        let (dial_tx, _) = broadcast::channel(DIAL_COMMAND_CAPACITY);
        let (name_tx, _) = broadcast::channel(NAME_COMMAND_CAPACITY);
        // Assign a stable id to each config-seeded tunnel; runtime adds continue
        // from the same counter via `alloc_id`.
        let specs: Vec<TunnelSpec> = tunnels
            .into_iter()
            .enumerate()
            .map(|(i, entry)| TunnelSpec {
                id: TunnelId(i as u64),
                entry,
            })
            .collect();
        let next_id = AtomicU64::new(specs.len() as u64);
        Arc::new(Self {
            role,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            token_generated,
            auth_token: RwLock::new(None),
            endpoint_id: RwLock::new(None),
            conn_status: RwLock::new(ConnStatus::Connecting),
            path: RwLock::new(PathInfo::establishing()),
            peers: RwLock::new(Vec::new()),
            next_id,
            specs: RwLock::new(specs),
            tunnels: RwLock::new(Vec::new()),
            semaphore: RwLock::new(None),
            streams_max: RwLock::new(0),
            tunnel_tx,
            dial_tx,
            name_tx,
            name_conflict: RwLock::new(NameConflict::Inactive),
            dial_target: RwLock::new(None),
            nostr_discovery,
            own_name,
            shutdown: CancellationToken::new(),
            logs,
        })
    }

    /// Subscribe to tunnel commands. Each connection supervisor subscribes once;
    /// only commands sent after subscribing are delivered (so reconnects start clean).
    pub fn subscribe_commands(&self) -> broadcast::Receiver<TunnelCommand> {
        self.tunnel_tx.subscribe()
    }

    /// Send a tunnel command to any active connection supervisor(s).
    pub fn send_command(&self, cmd: TunnelCommand) {
        let _ = self.tunnel_tx.send(cmd);
    }

    /// Subscribe to dial commands. The dial manager subscribes once at startup.
    pub fn subscribe_dial(&self) -> broadcast::Receiver<DialCommand> {
        self.dial_tx.subscribe()
    }

    /// Send a dial command to the dial manager (TUI connect/disconnect). Returns
    /// `true` if it was delivered to a live manager; `false` if there is no subscriber
    /// (the manager hasn't started yet or has exited), so the caller can surface it.
    pub fn send_dial(&self, cmd: DialCommand) -> bool {
        self.dial_tx.send(cmd).is_ok()
    }

    /// Subscribe to name-conflict decisions. The node-id publisher subscribes once.
    pub fn subscribe_name(&self) -> broadcast::Receiver<NameCommand> {
        self.name_tx.subscribe()
    }

    /// Send a name-conflict decision to the publisher (TUI take over/rename/decline).
    /// Returns `true` if delivered to a live subscriber.
    pub fn send_name(&self, cmd: NameCommand) -> bool {
        self.name_tx.send(cmd).is_ok()
    }

    /// Set the current name-conflict state (publisher -> TUI).
    pub fn set_name_conflict(&self, conflict: NameConflict) {
        *self.name_conflict.write() = conflict;
    }

    /// Clear the name-conflict state back to `Inactive`.
    pub fn clear_name_conflict(&self) {
        *self.name_conflict.write() = NameConflict::Inactive;
    }

    /// Current name-conflict state, cloned (read by the TUI key handler).
    pub fn name_conflict(&self) -> NameConflict {
        self.name_conflict.read().clone()
    }

    /// Set (or clear) the current dial target's display string.
    pub fn set_dial_target(&self, target: Option<String>) {
        *self.dial_target.write() = target;
    }

    /// Allocate a fresh, never-reused tunnel id.
    fn alloc_id(&self) -> TunnelId {
        TunnelId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Toggle the tunnel `id`: stop it if running, otherwise (re)start it.
    pub fn toggle_tunnel(&self, id: TunnelId) {
        let running = self
            .tunnels
            .read()
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| t.status.is_running());
        let cmd = if running {
            TunnelCommand::Stop(id)
        } else {
            TunnelCommand::Start(id)
        };
        self.send_command(cmd);
    }

    pub fn set_endpoint_id(&self, id: String) {
        *self.endpoint_id.write() = Some(id);
    }

    pub fn set_auth_token(&self, token: String) {
        *self.auth_token.write() = Some(token);
    }

    pub fn set_conn_status(&self, status: ConnStatus) {
        *self.conn_status.write() = status;
    }

    pub fn set_path(&self, path: PathInfo) {
        *self.path.write() = path;
    }

    /// Record the live stream limiter so the gauge tracks it exactly.
    pub fn set_semaphore(&self, semaphore: Arc<Semaphore>, max: usize) {
        *self.semaphore.write() = Some(semaphore);
        *self.streams_max.write() = max;
    }

    /// Update the path of a connected inbound peer, matched by `remote_id`.
    pub fn set_peer_path(&self, remote_id: &str, path: PathInfo) {
        let mut peers = self.peers.write();
        if let Some(peer) = peers.iter_mut().find(|p| p.remote_id == remote_id) {
            peer.path = path;
        }
    }

    /// Register a newly-authenticated inbound peer. The serve half handles many
    /// peers at once, so this simply adds a row; duplicate `remote_id`s (a brief
    /// reconnect overlap) are de-duplicated rather than rejected.
    pub fn add_peer(&self, remote_id: String) {
        let mut peers = self.peers.write();
        if !peers.iter().any(|p| p.remote_id == remote_id) {
            peers.push(PeerRow {
                remote_id,
                connected_since: Instant::now(),
                path: PathInfo::establishing(),
            });
        }
    }

    pub fn remove_peer(&self, remote_id: &str) {
        self.peers.write().retain(|p| p.remote_id != remote_id);
    }

    /// Rebuild the tunnel table from the current spec list (all `Idle`), carrying
    /// each tunnel's stable id. Called once per (re)connection; runtime additions
    /// and deletions persist because they live in `specs`.
    pub fn seed_tunnels(&self) {
        let rows = self
            .specs
            .read()
            .iter()
            .map(|s| tunnel_row_for(s.id, &s.entry))
            .collect();
        *self.tunnels.write() = rows;
    }

    /// The tunnel with `id`, cloned (used by the connection supervisor on `Start`).
    pub fn get_tunnel(&self, id: TunnelId) -> Option<TunnelEntry> {
        self.specs
            .read()
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.entry.clone())
    }

    /// Ids of all configured tunnels, in display order (used by the autostart
    /// path to start each one).
    pub fn tunnel_ids(&self) -> Vec<TunnelId> {
        self.specs.read().iter().map(|s| s.id).collect()
    }

    /// Whether the tunnel `id` is currently running (used to gate the edit action).
    pub fn tunnel_running(&self, id: TunnelId) -> bool {
        self.tunnels
            .read()
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| t.status.is_running())
    }

    /// Whether `name` is already used by a tunnel, optionally ignoring `except` (the
    /// row being edited). Used to keep tunnel names unique.
    pub fn tunnel_name_taken(&self, name: &str, except: Option<TunnelId>) -> bool {
        self.specs
            .read()
            .iter()
            .any(|s| Some(s.id) != except && s.entry.name == name)
    }

    /// Append a new tunnel at runtime and its matching `Idle` row. Returns
    /// its freshly allocated id.
    pub fn add_tunnel(&self, entry: TunnelEntry) -> TunnelId {
        let id = self.alloc_id();
        let row = tunnel_row_for(id, &entry);
        // Hold both locks for the duration so `specs` and `tunnels` are never
        // observed out of sync. Lock order is specs-then-tunnels, matching
        // `seed_tunnels`; no site takes them the other way, so this can't deadlock.
        let mut specs = self.specs.write();
        let mut tunnels = self.tunnels.write();
        specs.push(TunnelSpec { id, entry });
        tunnels.push(row);
        id
    }

    /// Replace the spec of tunnel `id` in place, rebuilding its row to `Idle` (caller
    /// guarantees it is not running). No `Start` is sent; the tunnel keeps its id and
    /// position. A no-op if `id` is unknown.
    pub fn edit_tunnel(&self, id: TunnelId, entry: TunnelEntry) {
        // Same specs-then-tunnels lock order as `add_tunnel`.
        let mut specs = self.specs.write();
        let mut tunnels = self.tunnels.write();
        if let Some(spec) = specs.iter_mut().find(|s| s.id == id) {
            spec.entry = entry.clone();
        } else {
            return;
        }
        if let Some(row) = tunnels.iter_mut().find(|t| t.id == id) {
            *row = tunnel_row_for(id, &entry);
        }
    }

    /// Remove the tunnel `id` from the session (config is never touched). If it is
    /// running, a `Stop` is broadcast first so the supervisor cancels its task and
    /// frees the bound local port; the row is then dropped from both lists.
    pub fn delete_tunnel(&self, id: TunnelId) {
        // Free the port if running. `Stop` for a non-running id is a harmless no-op in
        // the supervisor, so we send unconditionally.
        self.send_command(TunnelCommand::Stop(id));
        let mut specs = self.specs.write();
        let mut tunnels = self.tunnels.write();
        specs.retain(|s| s.id != id);
        tunnels.retain(|t| t.id != id);
    }

    /// Number of configured tunnel rows (used to clamp the TUI selection cursor).
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.read().len()
    }

    /// The id of the tunnel at display position `pos`, if any. Resolves the TUI's
    /// transient cursor position to a stable id at action time.
    pub fn tunnel_id_at(&self, pos: usize) -> Option<TunnelId> {
        self.tunnels.read().get(pos).map(|t| t.id)
    }

    /// Update the status/detail of the tunnel `id` (no-op if it has been deleted, so a
    /// late update from a just-stopped task is harmless).
    pub fn update_tunnel(&self, id: TunnelId, status: TunnelStatus, detail: impl Into<String>) {
        let mut tunnels = self.tunnels.write();
        if let Some(row) = tunnels.iter_mut().find(|t| t.id == id) {
            row.status = status;
            row.detail = detail.into();
        }
    }

    /// Take an owned snapshot for rendering (releases all locks before returning).
    pub fn snapshot(&self) -> AppSnapshot {
        let streams_max = *self.streams_max.read();
        let streams_used = self
            .semaphore
            .read()
            .as_ref()
            .map(|s| streams_max.saturating_sub(s.available_permits()))
            .unwrap_or(0);
        AppSnapshot {
            role: self.role,
            hostname: self.hostname.clone(),
            token_generated: self.token_generated,
            nostr_discovery: self.nostr_discovery,
            own_name: self.own_name.clone(),
            endpoint_id: self.endpoint_id.read().clone(),
            auth_token: self.auth_token.read().clone(),
            conn_status: self.conn_status.read().clone(),
            path: self.path.read().clone(),
            dial_target: self.dial_target.read().clone(),
            name_conflict: self.name_conflict.read().clone(),
            peers: self.peers.read().clone(),
            tunnels: self.tunnels.read().clone(),
            streams_used,
            streams_max,
        }
    }
}

/// Owned, lock-free view of [`AppState`] for a single render pass.
pub struct AppSnapshot {
    pub role: Role,
    pub hostname: String,
    pub token_generated: bool,
    pub nostr_discovery: bool,
    pub own_name: Option<String>,
    pub endpoint_id: Option<String>,
    pub auth_token: Option<String>,
    pub conn_status: ConnStatus,
    pub path: PathInfo,
    /// Current dial target's display string; `None` when idle (serving only).
    pub dial_target: Option<String>,
    /// Current nostr name-conflict state (drives the conflict modal / warning).
    pub name_conflict: NameConflict,
    pub peers: Vec<PeerRow>,
    pub tunnels: Vec<TunnelRow>,
    pub streams_used: usize,
    pub streams_max: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogBuffer;

    fn req(name: &str, src: &str, listen: &str) -> TunnelEntry {
        TunnelEntry {
            name: name.into(),
            remote_source: src.into(),
            local_listen: listen.into(),
        }
    }

    #[test]
    fn add_tunnel_appends_tunnel_and_idle_row() {
        let seed = vec![req("db", "tcp://127.0.0.1:5678", "127.0.0.1:15678")];
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), seed, false, None);
        // Rows mirror the specs only after seeding.
        state.seed_tunnels();
        assert_eq!(state.tunnel_ids().len(), 1);
        assert_eq!(state.tunnel_count(), 1);
        let db_id = state.tunnel_id_at(0).expect("seeded id");

        let id = state.add_tunnel(req("ssh", "tcp://127.0.0.1:22", "127.0.0.1:2222"));
        assert_ne!(id, db_id, "append allocates a fresh id");
        assert_eq!(state.tunnel_ids().len(), 2);
        assert_eq!(state.tunnel_count(), 2);

        // The tunnel round-trips and the row is Idle with the right spec.
        let got = state.get_tunnel(id).expect("tunnel present");
        assert_eq!(got.remote_source, "tcp://127.0.0.1:22");
        let row = state.snapshot().tunnels[1].clone();
        assert_eq!(row.id, id);
        assert_eq!(row.name, "ssh");
        assert_eq!(row.spec, "127.0.0.1:2222 <- tcp://127.0.0.1:22");
        assert_eq!(row.status, TunnelStatus::Idle);

        // A second append keeps allocating distinct ids.
        let id2 = state.add_tunnel(req("c", "udp://127.0.0.1:53", "127.0.0.1:5353"));
        assert_ne!(id2, id);
        assert_eq!(state.get_tunnel(db_id).unwrap().name, "db");
    }

    #[test]
    fn delete_tunnel_drops_row_and_preserves_other_ids() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![], false, None);
        let a = state.add_tunnel(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        let b = state.add_tunnel(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        let c = state.add_tunnel(req("c", "tcp://127.0.0.1:3", "127.0.0.1:13"));
        assert_eq!(state.tunnel_count(), 3);

        // Delete the middle tunnel.
        state.delete_tunnel(b);
        assert_eq!(state.tunnel_count(), 2);
        assert!(state.get_tunnel(b).is_none(), "deleted tunnel is gone");

        // The survivors keep their ids and shift up by one position.
        assert_eq!(state.get_tunnel(a).unwrap().name, "a");
        assert_eq!(state.get_tunnel(c).unwrap().name, "c");
        assert_eq!(state.tunnel_id_at(0), Some(a));
        assert_eq!(state.tunnel_id_at(1), Some(c));

        // Deleting an unknown id is a no-op.
        state.delete_tunnel(b);
        assert_eq!(state.tunnel_count(), 2);
    }

    #[test]
    fn update_tunnel_replaces_spec_and_row_in_place() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![], false, None);
        let a = state.add_tunnel(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        let b = state.add_tunnel(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));

        state.edit_tunnel(a, req("a2", "udp://127.0.0.1:9", "127.0.0.1:99"));
        // Same id and position; spec and row reflect the edit.
        assert_eq!(state.tunnel_id_at(0), Some(a));
        let got = state.get_tunnel(a).expect("tunnel present");
        assert_eq!(got.name, "a2");
        assert_eq!(got.remote_source, "udp://127.0.0.1:9");
        let row = state.snapshot().tunnels[0].clone();
        assert_eq!(row.id, a);
        assert_eq!(row.name, "a2");
        assert_eq!(row.spec, "127.0.0.1:99 <- udp://127.0.0.1:9");
        assert_eq!(row.status, TunnelStatus::Idle);
        // The other tunnel is untouched.
        assert_eq!(state.get_tunnel(b).unwrap().name, "b");
    }

    #[test]
    fn tunnel_name_taken_honors_except() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![], false, None);
        let a = state.add_tunnel(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        state.add_tunnel(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));

        assert!(state.tunnel_name_taken("b", None));
        assert!(!state.tunnel_name_taken("c", None));
        // "a" excluding its own row is free (lets an edit keep its name).
        assert!(!state.tunnel_name_taken("a", Some(a)));
        // But "b" still collides even when editing "a".
        assert!(state.tunnel_name_taken("b", Some(a)));
    }

    #[test]
    fn listener_tracks_multiple_peers() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![], false, None);

        // Many distinct peers connect at once — all are tracked.
        state.add_peer("peer-a".into());
        state.add_peer("peer-b".into());
        assert_eq!(state.snapshot().peers.len(), 2);

        // A duplicate remote_id (brief reconnect overlap) is de-duplicated.
        state.add_peer("peer-a".into());
        assert_eq!(state.snapshot().peers.len(), 2);

        // Peers drop independently as they disconnect.
        state.remove_peer("peer-a");
        let peers = state.snapshot().peers;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].remote_id, "peer-b");
    }

    #[test]
    fn snapshot_carries_mode_metadata() {
        let state = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            vec![],
            true,
            Some("web1".to_string()),
        );

        let snap = state.snapshot();

        assert!(snap.nostr_discovery);
        assert_eq!(snap.own_name.as_deref(), Some("web1"));
    }

    #[test]
    fn name_conflict_state_transitions_in_snapshot() {
        let state = AppState::new(Role::Both, false, LogBuffer::new(16), vec![], true, None);
        assert_eq!(state.snapshot().name_conflict, NameConflict::Inactive);

        state.set_name_conflict(NameConflict::Prompt {
            message: "in use".to_string(),
        });
        assert!(matches!(
            state.name_conflict(),
            NameConflict::Prompt { .. }
        ));
        assert!(matches!(
            state.snapshot().name_conflict,
            NameConflict::Prompt { .. }
        ));

        state.set_name_conflict(NameConflict::Degraded {
            message: "serving only".to_string(),
        });
        assert!(matches!(
            state.snapshot().name_conflict,
            NameConflict::Degraded { .. }
        ));

        state.clear_name_conflict();
        assert_eq!(state.snapshot().name_conflict, NameConflict::Inactive);
    }
}
