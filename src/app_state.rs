//! Shared runtime state surfaced by the TUI.
//!
//! The peer runtime writes status transitions here; the TUI polls
//! [`AppState::snapshot`] on a tick and renders from the owned snapshot. All
//! writers are synchronous and never hold a lock across `.await`, so the
//! `parking_lot` locks are safe inside async tasks. The session gauge reads the
//! live [`Semaphore`] so it can never drift from the real limiter.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::{broadcast, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::config::RequestEntry;
use crate::logging::LogBuffer;

/// Capacity of the tunnel-command broadcast channel (commands are tiny; this
/// only bounds how far a lagging connection supervisor may fall behind).
const TUNNEL_COMMAND_CAPACITY: usize = 64;

/// A request to start or stop a configured tunnel, addressed by its index in the
/// configured request list. Sent by the TUI, consumed by the connection supervisor.
#[derive(Debug, Clone, Copy)]
pub enum TunnelCommand {
    Start(usize),
    Stop(usize),
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
/// has a single connection at a time).
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

/// A configured tunnel request and its current status. Rows are kept in config
/// order, so a row's position is its request index (used to start/stop it).
#[derive(Clone)]
pub struct TunnelRow {
    /// Display label from the request's `name`.
    pub name: String,
    /// Human-readable "LISTEN <- SOURCE" description.
    pub spec: String,
    pub status: TunnelStatus,
    /// Bound address or rejection/error reason.
    pub detail: String,
}

/// Build the `Idle` tunnel row for a request (centralizes the spec format used by
/// both seeding and runtime additions).
fn tunnel_row_for(req: &RequestEntry) -> TunnelRow {
    TunnelRow {
        name: req.name.clone(),
        spec: format!("{} <- {}", req.local_listen, req.remote_source),
        status: TunnelStatus::Idle,
        detail: String::new(),
    }
}

/// A currently-connected, authenticated peer (listen role may have several).
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
    peers: RwLock<Vec<PeerRow>>,
    /// Single-owner slot for the listen role: holds the `remote_id` of the one
    /// authenticated peer allowed to drive tunnels at a time. Claimed atomically
    /// after auth so a second dialer is rejected rather than duplicating binds and
    /// reseeding the shared tunnel table. `None` when no peer is connected.
    active_peer: RwLock<Option<String>>,
    /// Authoritative tunnel-request list, seeded from config and appended to at
    /// runtime via [`AppState::add_request`]. `tunnels` is kept 1:1 with this, so a
    /// row's position is its request index (used to start/stop it).
    requests: RwLock<Vec<RequestEntry>>,
    tunnels: RwLock<Vec<TunnelRow>>,
    /// Live session limiter; `used = max - available_permits()`.
    semaphore: RwLock<Option<Arc<Semaphore>>>,
    sessions_max: RwLock<usize>,
    /// Broadcast channel for tunnel start/stop commands (TUI -> connection supervisor).
    tunnel_tx: broadcast::Sender<TunnelCommand>,
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
        let (tunnel_tx, _) = broadcast::channel(TUNNEL_COMMAND_CAPACITY);
        Arc::new(Self {
            role,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            token_generated,
            auth_token: RwLock::new(None),
            endpoint_id: RwLock::new(None),
            conn_status: RwLock::new(ConnStatus::Connecting),
            path: RwLock::new(PathInfo::establishing()),
            peers: RwLock::new(Vec::new()),
            active_peer: RwLock::new(None),
            requests: RwLock::new(requests),
            tunnels: RwLock::new(Vec::new()),
            semaphore: RwLock::new(None),
            sessions_max: RwLock::new(0),
            tunnel_tx,
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

    /// Toggle the tunnel at `idx`: stop it if running, otherwise (re)start it.
    pub fn toggle_tunnel(&self, idx: usize) {
        let running = self
            .tunnels
            .read()
            .get(idx)
            .is_some_and(|t| t.status.is_running());
        let cmd = if running {
            TunnelCommand::Stop(idx)
        } else {
            TunnelCommand::Start(idx)
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

    /// Record the live session limiter so the gauge tracks it exactly.
    pub fn set_semaphore(&self, semaphore: Arc<Semaphore>, max: usize) {
        *self.semaphore.write() = Some(semaphore);
        *self.sessions_max.write() = max;
    }

    /// Update the path of a connected peer (listen role), matched by `remote_id`.
    pub fn set_peer_path(&self, remote_id: &str, path: PathInfo) {
        let mut peers = self.peers.write();
        if let Some(peer) = peers.iter_mut().find(|p| p.remote_id == remote_id) {
            peer.path = path;
        }
    }

    /// Claim the single peer slot for `remote_id` (listen role). Returns `true` if
    /// the slot was free and is now held by the caller, `false` if another peer
    /// already holds it (the caller should reject this connection). The write lock
    /// serializes simultaneous auths so exactly one claimant wins.
    pub fn try_claim_peer(&self, remote_id: &str) -> bool {
        let mut slot = self.active_peer.write();
        if slot.is_none() {
            *slot = Some(remote_id.to_string());
            true
        } else {
            false
        }
    }

    /// Release the peer slot if `remote_id` holds it. A no-op for a connection that
    /// never claimed it (e.g. one rejected as a duplicate), so it is safe to call
    /// unconditionally on teardown.
    pub fn release_peer(&self, remote_id: &str) {
        let mut slot = self.active_peer.write();
        if slot.as_deref() == Some(remote_id) {
            *slot = None;
        }
    }

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

    /// Rebuild the tunnel table from the current request list (all `Idle`). Called
    /// once per (re)connection; runtime additions persist because they live in
    /// `requests`.
    pub fn seed_tunnels_from_requests(&self) {
        let rows = self.requests.read().iter().map(tunnel_row_for).collect();
        *self.tunnels.write() = rows;
    }

    /// The request at `idx`, cloned (used by the connection supervisor on `Start`).
    pub fn get_request(&self, idx: usize) -> Option<RequestEntry> {
        self.requests.read().get(idx).cloned()
    }

    /// Number of tunnel requests (config + runtime-added).
    pub fn request_count(&self) -> usize {
        self.requests.read().len()
    }

    /// Append a new tunnel request at runtime and its matching `Idle` row. Returns
    /// the new index. Appends only, so existing indices never shift.
    pub fn add_request(&self, req: RequestEntry) -> usize {
        let row = tunnel_row_for(&req);
        // Hold both locks for the duration so `requests` and `tunnels` are never
        // observed out of sync (e.g. request_count() vs tunnel_count()). Lock order
        // is requests-then-tunnels, matching `seed_tunnels_from_requests`; no site
        // takes them the other way, so this can't deadlock.
        let mut requests = self.requests.write();
        let mut tunnels = self.tunnels.write();
        let idx = requests.len();
        requests.push(req);
        tunnels.push(row);
        idx
    }

    /// Number of configured tunnel rows (used to clamp the TUI selection cursor).
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.read().len()
    }

    /// Update the status/detail of the tunnel at request index `idx`.
    pub fn update_tunnel(&self, idx: usize, status: TunnelStatus, detail: impl Into<String>) {
        let mut tunnels = self.tunnels.write();
        if let Some(row) = tunnels.get_mut(idx) {
            row.status = status;
            row.detail = detail.into();
        }
    }

    /// Take an owned snapshot for rendering (releases all locks before returning).
    pub fn snapshot(&self) -> AppSnapshot {
        let sessions_max = *self.sessions_max.read();
        let sessions_used = self
            .semaphore
            .read()
            .as_ref()
            .map(|s| sessions_max.saturating_sub(s.available_permits()))
            .unwrap_or(0);
        AppSnapshot {
            role: self.role,
            hostname: self.hostname.clone(),
            token_generated: self.token_generated,
            endpoint_id: self.endpoint_id.read().clone(),
            auth_token: self.auth_token.read().clone(),
            conn_status: self.conn_status.read().clone(),
            path: self.path.read().clone(),
            peers: self.peers.read().clone(),
            tunnels: self.tunnels.read().clone(),
            sessions_used,
            sessions_max,
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
    pub peers: Vec<PeerRow>,
    pub tunnels: Vec<TunnelRow>,
    pub sessions_used: usize,
    pub sessions_max: usize,
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
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), seed);
        // Rows mirror the requests only after seeding.
        state.seed_tunnels_from_requests();
        assert_eq!(state.request_count(), 1);
        assert_eq!(state.tunnel_count(), 1);

        let idx = state.add_request(req("ssh", "tcp://127.0.0.1:22", "127.0.0.1:2222"));
        assert_eq!(idx, 1, "append returns the new index");
        assert_eq!(state.request_count(), 2);
        assert_eq!(state.tunnel_count(), 2);

        // The request round-trips and the row is Idle with the right spec.
        let got = state.get_request(idx).expect("request present");
        assert_eq!(got.remote_source, "tcp://127.0.0.1:22");
        let row = &state.snapshot().tunnels[idx];
        assert_eq!(row.name, "ssh");
        assert_eq!(row.spec, "127.0.0.1:2222 <- tcp://127.0.0.1:22");
        assert_eq!(row.status, TunnelStatus::Idle);

        // A second append keeps incrementing without shifting existing indices.
        let idx2 = state.add_request(req("c", "udp://127.0.0.1:53", "127.0.0.1:5353"));
        assert_eq!(idx2, 2);
        assert_eq!(state.get_request(0).unwrap().name, "db");
    }

    #[test]
    fn single_active_peer_slot_admits_one_and_frees_on_release() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), vec![]);

        // First claimant wins the slot; a second, different peer is rejected.
        assert!(state.try_claim_peer("peer-a"));
        assert!(!state.try_claim_peer("peer-b"));

        // Releasing a non-holder is a no-op (rejected peers call this on teardown),
        // so the holder keeps the slot.
        state.release_peer("peer-b");
        assert!(!state.try_claim_peer("peer-b"));

        // Once the holder releases, the next dialer can take over.
        state.release_peer("peer-a");
        assert!(state.try_claim_peer("peer-b"));
    }
}
