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

use crate::config::RequestEntry;
use crate::logging::LogBuffer;

/// Capacity of the tunnel-command broadcast channel (commands are tiny; this
/// only bounds how far a lagging connection supervisor may fall behind).
const TUNNEL_COMMAND_CAPACITY: usize = 64;
const DIAL_COMMAND_CAPACITY: usize = 16;

/// Stable identity for a tunnel request, allocated once when the request is added
/// (config-seeded or runtime) and unchanged for the life of the session, including
/// across reconnect reseeds. Identity is decoupled from the vec position so requests
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

/// Connection role for this peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Dial,
    Listen,
    /// Both at once in one process: serve inbound peers (listen) *and* maintain one
    /// outbound connection that requests tunnels (dial). Each underlying connection
    /// still has exactly one requester and one server — the two roles run side by
    /// side over separate endpoints and never interact at the connection layer.
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

/// High-level connection status (primarily meaningful for the dial role, which
/// has a single connection at a time).
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

/// Lifecycle status of a configured tunnel request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TunnelStatus {
    /// Configured but not started (or stopped).
    Idle,
    /// Local listener is bound and the request is active.
    Listening,
    /// The request failed (bind error, peer rejection, etc.).
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

/// A configured tunnel request and its current status. Carries the request's stable
/// [`TunnelId`]; rows are kept in display order, but the id (not the position) is the
/// identity used to start/stop/delete it.
#[derive(Clone)]
pub struct TunnelRow {
    /// Stable identity of the underlying request.
    pub id: TunnelId,
    /// Display label from the request's `name`.
    pub name: String,
    /// Human-readable "LISTEN <- SOURCE" description.
    pub spec: String,
    pub status: TunnelStatus,
    /// Bound address or rejection/error reason.
    pub detail: String,
}

/// A configured tunnel request paired with its stable id. The authoritative spec
/// list (`AppState::requests`) is seeded from config and appended to at runtime.
struct Request {
    id: TunnelId,
    entry: RequestEntry,
}

/// Build the `Idle` tunnel row for a request (centralizes the spec format used by
/// both seeding and runtime additions).
fn tunnel_row_for(id: TunnelId, entry: &RequestEntry) -> TunnelRow {
    TunnelRow {
        id,
        name: entry.name.clone(),
        spec: format!("{} <- {}", entry.local_listen, entry.remote_source),
        status: TunnelStatus::Idle,
        detail: String::new(),
    }
}

/// A currently-connected, authenticated peer (listen role). The listener serves
/// many of these at once — one row per live connection.
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
    /// The shared auth token, shown in the listen-role dashboard so the dialer
    /// can copy it (it may be freshly generated each run).
    auth_token: RwLock<Option<String>>,
    endpoint_id: RwLock<Option<String>>,
    conn_status: RwLock<ConnStatus>,
    path: RwLock<PathInfo>,
    /// Currently-connected peers (listen role serves many at once; dial role tracks
    /// its own path separately via `path`).
    peers: RwLock<Vec<PeerRow>>,
    /// Monotonic allocator for [`TunnelId`]s. Never reused within a session.
    next_id: AtomicU64,
    /// Authoritative tunnel-request list (dial role): seeded from config and appended
    /// to at runtime via [`AppState::add_request`]. `tunnels` is kept 1:1 with this
    /// (same order), but identity is the [`TunnelId`], not the vec position.
    requests: RwLock<Vec<Request>>,
    tunnels: RwLock<Vec<TunnelRow>>,
    /// Live stream limiter; `used = max - available_permits()`. One global cap on
    /// concurrent forwarded streams across all tunnels and all connected peers.
    semaphore: RwLock<Option<Arc<Semaphore>>>,
    streams_max: RwLock<usize>,
    /// Broadcast channel for tunnel start/stop commands (TUI -> connection supervisor).
    tunnel_tx: broadcast::Sender<TunnelCommand>,
    /// Broadcast channel for dial connect/disconnect commands (TUI -> dial manager).
    dial_tx: broadcast::Sender<DialCommand>,
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
        requests: Vec<RequestEntry>,
        nostr_discovery: bool,
        own_name: Option<String>,
    ) -> Arc<Self> {
        let (tunnel_tx, _) = broadcast::channel(TUNNEL_COMMAND_CAPACITY);
        let (dial_tx, _) = broadcast::channel(DIAL_COMMAND_CAPACITY);
        // Assign a stable id to each config-seeded request; runtime adds continue
        // from the same counter via `alloc_id`.
        let requests: Vec<Request> = requests
            .into_iter()
            .enumerate()
            .map(|(i, entry)| Request {
                id: TunnelId(i as u64),
                entry,
            })
            .collect();
        let next_id = AtomicU64::new(requests.len() as u64);
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
            requests: RwLock::new(requests),
            tunnels: RwLock::new(Vec::new()),
            semaphore: RwLock::new(None),
            streams_max: RwLock::new(0),
            tunnel_tx,
            dial_tx,
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

    /// Send a dial command to the dial manager (TUI connect/disconnect).
    pub fn send_dial(&self, cmd: DialCommand) {
        let _ = self.dial_tx.send(cmd);
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

    /// Update the path of a connected peer (listen role), matched by `remote_id`.
    pub fn set_peer_path(&self, remote_id: &str, path: PathInfo) {
        let mut peers = self.peers.write();
        if let Some(peer) = peers.iter_mut().find(|p| p.remote_id == remote_id) {
            peer.path = path;
        }
    }

    /// Register a newly-authenticated peer (listen role). The listener serves many
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

    /// Rebuild the tunnel table from the current request list (all `Idle`), carrying
    /// each request's stable id. Called once per (re)connection; runtime additions
    /// and deletions persist because they live in `requests`.
    pub fn seed_tunnels_from_requests(&self) {
        let rows = self
            .requests
            .read()
            .iter()
            .map(|r| tunnel_row_for(r.id, &r.entry))
            .collect();
        *self.tunnels.write() = rows;
    }

    /// The request with `id`, cloned (used by the connection supervisor on `Start`).
    pub fn get_request(&self, id: TunnelId) -> Option<RequestEntry> {
        self.requests
            .read()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.entry.clone())
    }

    /// Ids of all configured tunnel requests, in display order (used by the autostart
    /// path to start each one).
    pub fn request_ids(&self) -> Vec<TunnelId> {
        self.requests.read().iter().map(|r| r.id).collect()
    }

    /// Append a new tunnel request at runtime and its matching `Idle` row. Returns
    /// its freshly allocated id.
    pub fn add_request(&self, entry: RequestEntry) -> TunnelId {
        let id = self.alloc_id();
        let row = tunnel_row_for(id, &entry);
        // Hold both locks for the duration so `requests` and `tunnels` are never
        // observed out of sync. Lock order is requests-then-tunnels, matching
        // `seed_tunnels_from_requests`; no site takes them the other way, so this
        // can't deadlock.
        let mut requests = self.requests.write();
        let mut tunnels = self.tunnels.write();
        requests.push(Request { id, entry });
        tunnels.push(row);
        id
    }

    /// Remove the tunnel `id` from the session (config is never touched). If it is
    /// running, a `Stop` is broadcast first so the supervisor cancels its task and
    /// frees the bound local port; the row is then dropped from both lists.
    pub fn delete_request(&self, id: TunnelId) {
        // Free the port if running. `Stop` for a non-running id is a harmless no-op in
        // the supervisor, so we send unconditionally.
        self.send_command(TunnelCommand::Stop(id));
        let mut requests = self.requests.write();
        let mut tunnels = self.tunnels.write();
        requests.retain(|r| r.id != id);
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
            endpoint_id: self.endpoint_id.read().clone(),
            auth_token: self.auth_token.read().clone(),
            conn_status: self.conn_status.read().clone(),
            path: self.path.read().clone(),
            dial_target: self.dial_target.read().clone(),
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
    pub endpoint_id: Option<String>,
    pub auth_token: Option<String>,
    pub conn_status: ConnStatus,
    pub path: PathInfo,
    /// Current dial target's display string; `None` when idle (serving only).
    pub dial_target: Option<String>,
    pub peers: Vec<PeerRow>,
    pub tunnels: Vec<TunnelRow>,
    pub streams_used: usize,
    pub streams_max: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogBuffer;

    fn req(name: &str, src: &str, listen: &str) -> RequestEntry {
        RequestEntry {
            name: name.into(),
            remote_source: src.into(),
            local_listen: listen.into(),
        }
    }

    #[test]
    fn add_request_appends_request_and_idle_row() {
        let seed = vec![req("db", "tcp://127.0.0.1:5678", "127.0.0.1:15678")];
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), seed, false, None);
        // Rows mirror the requests only after seeding.
        state.seed_tunnels_from_requests();
        assert_eq!(state.request_ids().len(), 1);
        assert_eq!(state.tunnel_count(), 1);
        let db_id = state.tunnel_id_at(0).expect("seeded id");

        let id = state.add_request(req("ssh", "tcp://127.0.0.1:22", "127.0.0.1:2222"));
        assert_ne!(id, db_id, "append allocates a fresh id");
        assert_eq!(state.request_ids().len(), 2);
        assert_eq!(state.tunnel_count(), 2);

        // The request round-trips and the row is Idle with the right spec.
        let got = state.get_request(id).expect("request present");
        assert_eq!(got.remote_source, "tcp://127.0.0.1:22");
        let row = state.snapshot().tunnels[1].clone();
        assert_eq!(row.id, id);
        assert_eq!(row.name, "ssh");
        assert_eq!(row.spec, "127.0.0.1:2222 <- tcp://127.0.0.1:22");
        assert_eq!(row.status, TunnelStatus::Idle);

        // A second append keeps allocating distinct ids.
        let id2 = state.add_request(req("c", "udp://127.0.0.1:53", "127.0.0.1:5353"));
        assert_ne!(id2, id);
        assert_eq!(state.get_request(db_id).unwrap().name, "db");
    }

    #[test]
    fn delete_request_drops_row_and_preserves_other_ids() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![], false, None);
        let a = state.add_request(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        let b = state.add_request(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        let c = state.add_request(req("c", "tcp://127.0.0.1:3", "127.0.0.1:13"));
        assert_eq!(state.tunnel_count(), 3);

        // Delete the middle tunnel.
        state.delete_request(b);
        assert_eq!(state.tunnel_count(), 2);
        assert!(state.get_request(b).is_none(), "deleted request is gone");

        // The survivors keep their ids and shift up by one position.
        assert_eq!(state.get_request(a).unwrap().name, "a");
        assert_eq!(state.get_request(c).unwrap().name, "c");
        assert_eq!(state.tunnel_id_at(0), Some(a));
        assert_eq!(state.tunnel_id_at(1), Some(c));

        // Deleting an unknown id is a no-op.
        state.delete_request(b);
        assert_eq!(state.tunnel_count(), 2);
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
}
