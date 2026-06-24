//! Shared runtime state surfaced by the TUI.
//!
//! The peer runtime writes status transitions here; the TUI polls
//! [`AppState::snapshot`] on a tick and renders from the owned snapshot. All
//! writers are synchronous and never hold a lock across `.await`, so the
//! `parking_lot` locks are safe inside async tasks. The session gauge reads the
//! live [`Semaphore`] so it can never drift from the real limiter.
//!
//! Tunnel state is **per connected peer**: each live connection owns a
//! [`PeerSession`] (its tunnel table, command channel, and path). A listener may
//! hold several at once; a dialer holds at most one. The prefilled `[[request]]`
//! list is a *template* held on [`AppState`] that seeds every new session.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use crate::config::RequestEntry;
use crate::logging::LogBuffer;

/// Capacity of the tunnel-command broadcast channel (commands are tiny; this
/// only bounds how far a lagging connection supervisor may fall behind).
const TUNNEL_COMMAND_CAPACITY: usize = 64;

/// Stable identity for a tunnel request within a [`PeerSession`], allocated once
/// when the request is added (template-seeded or runtime) and unchanged for the
/// life of that session. Identity is decoupled from the vec position so requests
/// can be removed without disturbing the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelId(u64);

impl std::fmt::Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A request to start or stop a configured tunnel, addressed by its stable
/// [`TunnelId`]. Sent by the TUI, consumed by a peer's connection supervisor.
#[derive(Debug, Clone, Copy)]
pub enum TunnelCommand {
    Start(TunnelId),
    Stop(TunnelId),
}

/// Connection role for this peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Dial,
    Listen,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Dial => "Dial",
            Role::Listen => "Listen",
        }
    }
}

/// High-level connection status (primarily meaningful for the dial role, which
/// has a single connection at a time and surfaces its reconnect state here).
#[derive(Clone, PartialEq)]
pub enum ConnStatus {
    Connecting,
    Authenticating,
    Connected,
    Closed,
    Reconnecting { backoff_secs: u64 },
}

impl ConnStatus {
    pub fn label(&self) -> String {
        match self {
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

/// A configured tunnel request paired with its stable id. Each [`PeerSession`]
/// owns its own list, seeded from the [`AppState`] template and appended to at
/// runtime.
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

/// Per-connected-peer tunnel runtime. Created when a connection authenticates
/// (seeded from the [`AppState`] request template) and dropped when it closes.
/// Owns its own tunnel table, command channel, and observed network path, so
/// peers are fully independent: starting a tunnel addresses exactly one peer.
pub struct PeerSession {
    /// The authenticated peer's node id (its stable identity for the session).
    pub remote_id: String,
    /// When this connection was admitted.
    pub connected_since: Instant,
    /// Observed network path to this peer.
    path: RwLock<PathInfo>,
    /// Monotonic allocator for this session's [`TunnelId`]s.
    next_id: AtomicU64,
    /// Authoritative tunnel-request list for this peer (template-seeded, then
    /// appended to via [`PeerSession::add_request`]). `tunnels` mirrors it 1:1.
    requests: RwLock<Vec<Request>>,
    tunnels: RwLock<Vec<TunnelRow>>,
    /// Tunnel start/stop commands (TUI -> this peer's connection supervisor).
    tunnel_tx: broadcast::Sender<TunnelCommand>,
}

impl PeerSession {
    /// Create a session for `remote_id`, seeding its tunnel table from `template`.
    fn new(remote_id: String, template: &[RequestEntry]) -> Arc<Self> {
        let (tunnel_tx, _) = broadcast::channel(TUNNEL_COMMAND_CAPACITY);
        let requests: Vec<Request> = template
            .iter()
            .enumerate()
            .map(|(i, entry)| Request {
                id: TunnelId(i as u64),
                entry: entry.clone(),
            })
            .collect();
        let tunnels = requests
            .iter()
            .map(|r| tunnel_row_for(r.id, &r.entry))
            .collect();
        Arc::new(Self {
            remote_id,
            connected_since: Instant::now(),
            path: RwLock::new(PathInfo::establishing()),
            next_id: AtomicU64::new(requests.len() as u64),
            requests: RwLock::new(requests),
            tunnels: RwLock::new(tunnels),
            tunnel_tx,
        })
    }

    /// Subscribe to this session's tunnel commands. The connection supervisor
    /// subscribes once; only commands sent after subscribing are delivered.
    pub fn subscribe_commands(&self) -> broadcast::Receiver<TunnelCommand> {
        self.tunnel_tx.subscribe()
    }

    /// Send a tunnel command to this session's supervisor (no-op if none is live).
    pub fn send_command(&self, cmd: TunnelCommand) {
        let _ = self.tunnel_tx.send(cmd);
    }

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

    pub fn set_path(&self, path: PathInfo) {
        *self.path.write() = path;
    }

    /// The request with `id`, cloned (used by the connection supervisor on `Start`).
    pub fn get_request(&self, id: TunnelId) -> Option<RequestEntry> {
        self.requests
            .read()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.entry.clone())
    }

    /// Ids of all this session's tunnel requests, in display order.
    pub fn request_ids(&self) -> Vec<TunnelId> {
        self.requests.read().iter().map(|r| r.id).collect()
    }

    /// Append a new tunnel request at runtime and its matching `Idle` row. Returns
    /// its freshly allocated id.
    pub fn add_request(&self, entry: RequestEntry) -> TunnelId {
        let id = self.alloc_id();
        let row = tunnel_row_for(id, &entry);
        // Hold both locks for the duration so `requests` and `tunnels` are never
        // observed out of sync. Lock order is requests-then-tunnels; no site takes
        // them the other way, so this can't deadlock.
        let mut requests = self.requests.write();
        let mut tunnels = self.tunnels.write();
        requests.push(Request { id, entry });
        tunnels.push(row);
        id
    }

    /// Remove the tunnel `id` from this session. If it is running, a `Stop` is
    /// broadcast first so the supervisor cancels its task and frees the bound local
    /// port; the row is then dropped from both lists.
    pub fn delete_request(&self, id: TunnelId) {
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

    /// The id of the tunnel at display position `pos`, if any.
    pub fn tunnel_id_at(&self, pos: usize) -> Option<TunnelId> {
        self.tunnels.read().get(pos).map(|t| t.id)
    }

    /// Update the status/detail of the tunnel `id` (no-op if it has been deleted, so
    /// a late update from a just-stopped task is harmless).
    pub fn update_tunnel(&self, id: TunnelId, status: TunnelStatus, detail: impl Into<String>) {
        let mut tunnels = self.tunnels.write();
        if let Some(row) = tunnels.iter_mut().find(|t| t.id == id) {
            row.status = status;
            row.detail = detail.into();
        }
    }

    fn snapshot(&self) -> PeerSnapshot {
        PeerSnapshot {
            remote_id: self.remote_id.clone(),
            connected_since: self.connected_since,
            path: self.path.read().clone(),
            tunnels: self.tunnels.read().clone(),
        }
    }
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
    /// High-level connection status for the dial role (its single connection /
    /// reconnect state). Unused by the listen role, which tracks per-peer status.
    conn_status: RwLock<ConnStatus>,
    /// Prefilled `[[request]]` list. A *template* only: each new [`PeerSession`] is
    /// seeded from it, then evolves independently.
    request_template: Vec<RequestEntry>,
    /// Live per-peer sessions, one per authenticated connection. The listen role
    /// may hold several; the dial role holds at most one.
    peers: RwLock<Vec<Arc<PeerSession>>>,
    /// Live stream limiter; `used = max - available_permits()`. A single global cap
    /// on concurrent forwarded streams across *all* peers.
    semaphore: RwLock<Option<Arc<Semaphore>>>,
    streams_max: RwLock<usize>,
    pub shutdown: CancellationToken,
    pub logs: Arc<LogBuffer>,
}

impl AppState {
    pub fn new(
        role: Role,
        token_generated: bool,
        logs: Arc<LogBuffer>,
        requests: Vec<RequestEntry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            token_generated,
            auth_token: RwLock::new(None),
            endpoint_id: RwLock::new(None),
            conn_status: RwLock::new(ConnStatus::Connecting),
            request_template: requests,
            peers: RwLock::new(Vec::new()),
            semaphore: RwLock::new(None),
            streams_max: RwLock::new(0),
            shutdown: CancellationToken::new(),
            logs,
        })
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

    /// Record the live stream limiter so the gauge tracks it exactly. Set once at
    /// startup; the same global semaphore is shared by every peer.
    pub fn set_semaphore(&self, semaphore: Arc<Semaphore>, max: usize) {
        *self.semaphore.write() = Some(semaphore);
        *self.streams_max.write() = max;
    }

    /// Admit an authenticated peer: register a fresh [`PeerSession`] (seeded from
    /// the request template) and return it. Returns `None` if a session for this
    /// `remote_id` is already live — the caller should reject the duplicate as
    /// transiently busy so a reconnect race can't bind the same local ports twice.
    pub fn attach_peer(&self, remote_id: String) -> Option<Arc<PeerSession>> {
        let mut peers = self.peers.write();
        if peers.iter().any(|p| p.remote_id == remote_id) {
            return None;
        }
        let session = PeerSession::new(remote_id, &self.request_template);
        peers.push(session.clone());
        Some(session)
    }

    /// Drop the session for `remote_id` on connection teardown.
    pub fn detach_peer(&self, remote_id: &str) {
        self.peers.write().retain(|p| p.remote_id != remote_id);
    }

    /// The live session at display position `index`, if any (resolves the TUI's
    /// transient peer cursor to a concrete session at action time).
    pub fn peer_at(&self, index: usize) -> Option<Arc<PeerSession>> {
        self.peers.read().get(index).cloned()
    }

    /// Number of live peer sessions (used to clamp the TUI peer cursor).
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Update the observed path of a connected peer, matched by `remote_id`.
    pub fn set_peer_path(&self, remote_id: &str, path: PathInfo) {
        if let Some(peer) = self.peers.read().iter().find(|p| p.remote_id == remote_id) {
            peer.set_path(path);
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
        let peers = self.peers.read().iter().map(|p| p.snapshot()).collect();
        AppSnapshot {
            role: self.role,
            hostname: self.hostname.clone(),
            token_generated: self.token_generated,
            endpoint_id: self.endpoint_id.read().clone(),
            auth_token: self.auth_token.read().clone(),
            conn_status: self.conn_status.read().clone(),
            peers,
            streams_used,
            streams_max,
        }
    }
}

/// Owned, lock-free view of a [`PeerSession`] for a single render pass.
#[derive(Clone)]
pub struct PeerSnapshot {
    pub remote_id: String,
    pub connected_since: Instant,
    pub path: PathInfo,
    pub tunnels: Vec<TunnelRow>,
}

/// Owned, lock-free view of [`AppState`] for a single render pass.
pub struct AppSnapshot {
    pub role: Role,
    pub hostname: String,
    pub token_generated: bool,
    pub endpoint_id: Option<String>,
    pub auth_token: Option<String>,
    /// Dial-role connection/reconnect status (the listen role uses per-peer rows).
    pub conn_status: ConnStatus,
    /// Live peer sessions, each with its own tunnels and path.
    pub peers: Vec<PeerSnapshot>,
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
    fn attached_session_seeds_tunnels_from_template() {
        let seed = vec![req("db", "tcp://127.0.0.1:5678", "127.0.0.1:15678")];
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), seed);
        let session = state.attach_peer("peer-a".into()).expect("first attach");
        assert_eq!(session.tunnel_count(), 1);
        let db_id = session.tunnel_id_at(0).expect("seeded id");
        assert_eq!(session.get_request(db_id).unwrap().name, "db");
    }

    #[test]
    fn multiple_distinct_peers_attach_independently() {
        let seed = vec![req("db", "tcp://127.0.0.1:5678", "127.0.0.1:15678")];
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), seed);

        let a = state.attach_peer("peer-a".into()).expect("a attaches");
        let b = state.attach_peer("peer-b".into()).expect("b attaches too");
        assert_eq!(state.peer_count(), 2);

        // Each peer has its own independently-seeded tunnel table.
        let a_id = a.tunnel_id_at(0).unwrap();
        a.add_request(req("ssh", "tcp://127.0.0.1:22", "127.0.0.1:2222"));
        assert_eq!(a.tunnel_count(), 2);
        assert_eq!(b.tunnel_count(), 1, "b is unaffected by a's runtime add");

        // A second concurrent connection from an already-connected id is refused.
        assert!(
            state.attach_peer("peer-a".into()).is_none(),
            "duplicate live remote_id is rejected as busy"
        );
        assert_eq!(state.peer_count(), 2);

        // Detaching frees the id so the same peer may reconnect later.
        state.detach_peer("peer-a");
        assert_eq!(state.peer_count(), 1);
        let a2 = state.attach_peer("peer-a".into()).expect("reattach after detach");
        assert_eq!(
            a2.tunnel_count(),
            1,
            "reconnect re-seeds from the template (runtime add not preserved)"
        );
        // The original handle still resolves; its id space is its own.
        assert!(a.get_request(a_id).is_some());
    }

    #[test]
    fn add_request_appends_request_and_idle_row() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![]);
        let session = state.attach_peer("peer-a".into()).unwrap();

        let id = session.add_request(req("ssh", "tcp://127.0.0.1:22", "127.0.0.1:2222"));
        assert_eq!(session.tunnel_count(), 1);
        let got = session.get_request(id).expect("request present");
        assert_eq!(got.remote_source, "tcp://127.0.0.1:22");
        let row = session.snapshot().tunnels[0].clone();
        assert_eq!(row.id, id);
        assert_eq!(row.name, "ssh");
        assert_eq!(row.spec, "127.0.0.1:2222 <- tcp://127.0.0.1:22");
        assert_eq!(row.status, TunnelStatus::Idle);

        // A second append keeps allocating distinct ids.
        let id2 = session.add_request(req("c", "udp://127.0.0.1:53", "127.0.0.1:5353"));
        assert_ne!(id2, id);
    }

    #[test]
    fn delete_request_drops_row_and_preserves_other_ids() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![]);
        let session = state.attach_peer("peer-a".into()).unwrap();
        let a = session.add_request(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        let b = session.add_request(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        let c = session.add_request(req("c", "tcp://127.0.0.1:3", "127.0.0.1:13"));
        assert_eq!(session.tunnel_count(), 3);

        // Delete the middle tunnel.
        session.delete_request(b);
        assert_eq!(session.tunnel_count(), 2);
        assert!(session.get_request(b).is_none(), "deleted request is gone");

        // The survivors keep their ids and shift up by one position.
        assert_eq!(session.get_request(a).unwrap().name, "a");
        assert_eq!(session.get_request(c).unwrap().name, "c");
        assert_eq!(session.tunnel_id_at(0), Some(a));
        assert_eq!(session.tunnel_id_at(1), Some(c));

        // Deleting an unknown id is a no-op.
        session.delete_request(b);
        assert_eq!(session.tunnel_count(), 2);
    }
}
