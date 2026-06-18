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
#[derive(Clone, Copy, PartialEq, Eq)]
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
    pub fn new(role: Role, token_generated: bool, logs: Arc<LogBuffer>) -> Arc<Self> {
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

    /// Replace the tunnel table (called once per connection from its config).
    pub fn set_tunnels(&self, tunnels: Vec<TunnelRow>) {
        *self.tunnels.write() = tunnels;
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
