//! Shared runtime state surfaced by the TUI.
//!
//! The peer runtime writes status transitions here; the TUI polls
//! [`AppState::snapshot`] on a tick and renders from the owned snapshot. All
//! writers are synchronous and never hold a lock across `.await`, so the
//! `parking_lot` locks are safe inside async tasks. The session gauge reads the
//! live [`Semaphore`] so it can never drift from the real limiter.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use iroh::EndpointId;
use parking_lot::RwLock;
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use crate::logging::LogBuffer;

/// Capacity of the SOCKS-command broadcast channel (commands are tiny; this
/// only bounds how far a lagging connection supervisor may fall behind).
const SOCKS_COMMAND_CAPACITY: usize = 64;
const DIAL_COMMAND_CAPACITY: usize = 16;
const NAME_COMMAND_CAPACITY: usize = 8;
const LISTEN_COMMAND_CAPACITY: usize = 8;

/// A request to start or stop this peer's local SOCKS5 proxy. Sent by the TUI,
/// consumed by the connection supervisor.
#[derive(Debug, Clone, Copy)]
pub enum SocksCommand {
    Start,
    Stop,
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

/// A request to start or stop this peer's serve (listen) half. Sent by the TUI when the
/// user presses Shift+L, consumed by `run_listen_supervisor`. The serve half does not
/// auto-start; it idles until a `Start` arrives.
#[derive(Debug, Clone, Copy)]
pub enum ListenCommand {
    Start,
    Stop,
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

/// What to dial, as typed at runtime: a full node id (quick manual mode), a peer name
/// looked up via nostr (config mode), or a rotating PIN resolved via nostr to the peer's
/// node id + auth token (quick PIN mode).
#[derive(Debug, Clone)]
pub enum DialTarget {
    NodeId(EndpointId),
    Name(String),
    /// Canonical (de-grouped, uppercase) PIN; resolved at runtime to `(node_id, token)`.
    Pin(String),
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
            // Never echo the rotating PIN secret. This placeholder shows only during the
            // brief pre-resolution / reconnect window; once the PIN resolves, the dial
            // session swaps in the resolved peer's (truncated) node id.
            DialTarget::Pin(_) => "PIN".to_string(),
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

/// Lifecycle status of the serve (listen) half. Unlike the tunnel, the serve half does
/// not auto-start: it begins `Stopped` and the user toggles it with Shift+L.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ListenStatus {
    /// Not listening: no public endpoint, no node id / PIN / token displayed.
    #[default]
    Stopped,
    /// The serve endpoint is up (or coming up) and accepting inbound peers.
    Listening,
}

/// Lifecycle status of the local SOCKS5 proxy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SocksStatus {
    /// Port configured but the proxy is not started (or stopped).
    Idle,
    /// The local loopback listener is bound and proxying.
    Listening,
    /// The proxy failed (bind error, etc.).
    Error,
}

impl SocksStatus {
    pub fn label(self) -> &'static str {
        match self {
            SocksStatus::Idle => "Idle",
            SocksStatus::Listening => "Listening",
            SocksStatus::Error => "Error",
        }
    }

    /// Whether the proxy is currently running (toggling it should stop it).
    pub fn is_running(self) -> bool {
        matches!(self, SocksStatus::Listening)
    }
}

/// The configured SOCKS5 proxy and its current status, as rendered by the TUI.
#[derive(Clone)]
pub struct SocksRow {
    /// Configured local port (0 = auto-assign; see `detail` for the bound address).
    pub port: u16,
    pub status: SocksStatus,
    /// Bound address or error reason.
    pub detail: String,
}

/// The single inbound peer the serve half is paired with this listen session. duopipe pairs one
/// dialer at a time, so there is at most one. The peer is [`connected`](Self::connected) while it
/// holds at least one live authenticated connection; when that count reaches zero it is still
/// retained as the endpoint's reservation — it stays reserved for that peer (which may reconnect
/// without re-authenticating) until the user stops listening.
///
/// `active_conns` is a refcount rather than a bool so a brief **reconnect overlap** (the peer's new
/// connection authenticates before its previous one has finished closing) never shows as
/// "disconnected": the count only reaches zero once *every* connection from the peer is gone.
#[derive(Clone)]
pub struct InboundPeer {
    pub remote_id: String,
    /// Number of live authenticated connections from this peer (normally 0 or 1; transiently 2
    /// during a reconnect overlap).
    pub active_conns: usize,
    pub connected_since: Instant,
    pub path: PathInfo,
}

impl InboundPeer {
    /// Whether the peer currently holds any live connection. `false` means it is disconnected but
    /// the endpoint remains reserved for it.
    pub fn connected(&self) -> bool {
        self.active_conns > 0
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
    /// The shared auth token, shown in the dashboard so a peer can copy it (it may be
    /// freshly generated each run).
    auth_token: RwLock<Option<String>>,
    endpoint_id: RwLock<Option<String>>,
    conn_status: RwLock<ConnStatus>,
    path: RwLock<PathInfo>,
    /// The single inbound peer paired with the serve half this listen session (`None` until one
    /// authenticates). Retained through a disconnect as the endpoint's reservation and cleared only
    /// when the serve half stops. The dial session tracks its own outbound path separately via `path`.
    inbound: RwLock<Option<InboundPeer>>,
    /// The configured local SOCKS5 proxy port (`None` until set from config or the
    /// TUI). The supervisor reads it on `Start`; the TUI sets/clears it.
    socks_port: RwLock<Option<u16>>,
    /// Current status of the local SOCKS5 proxy.
    socks_status: RwLock<SocksStatus>,
    /// Bound address or error reason for the local SOCKS5 proxy.
    socks_detail: RwLock<String>,
    /// The proxy's actually-bound loopback address while it is running (`None`
    /// otherwise). With port 0 this is where the OS-assigned port surfaces.
    socks_bound: RwLock<Option<SocketAddr>>,
    /// Live stream limiter; `used = max - available_permits()`. One global cap on
    /// concurrent proxied streams across both directions.
    semaphore: RwLock<Option<Arc<Semaphore>>>,
    streams_max: RwLock<usize>,
    /// Broadcast channel for SOCKS start/stop commands (TUI -> connection supervisor).
    socks_tx: broadcast::Sender<SocksCommand>,
    /// Broadcast channel for dial connect/disconnect commands (TUI -> dial manager).
    dial_tx: broadcast::Sender<DialCommand>,
    /// Broadcast channel for serve-half start/stop commands (TUI -> listen supervisor).
    listen_tx: broadcast::Sender<ListenCommand>,
    /// Current status of the serve (listen) half. Starts `Stopped`; toggled by Shift+L.
    listen_status: RwLock<ListenStatus>,
    /// Broadcast channel for name-conflict decisions (TUI -> node-id publisher).
    name_tx: broadcast::Sender<NameCommand>,
    /// Current nostr name-conflict state, surfaced to the TUI.
    name_conflict: RwLock<NameConflict>,
    /// Display string for the current dial target (`Some` while a session is up or
    /// being established), shown in the header. `None` when idle (serving only).
    dial_target: RwLock<Option<String>>,
    /// Whether nostr discovery is active (config mode). Read by the connect prompt to
    /// decide whether the user types a peer name (true) or a node id (false).
    pub nostr_discovery: bool,
    /// Quick mode's nostr PIN signaling: the listener publishes a rotating PIN carrying its
    /// node id + token, and the connect prompt asks for a PIN instead of a node id. `false`
    /// in config mode and in quick manual (copy-paste) mode.
    pub pin_mode: bool,
    /// The current rotating PIN (canonical form) and the instant it rolls over, set by the
    /// PIN publisher each rotation. Drives the PIN + refresh-countdown header in PIN mode.
    current_pin: RwLock<Option<String>>,
    pin_deadline: RwLock<Option<Instant>>,
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
        socks_port: Option<u16>,
        nostr_discovery: bool,
        own_name: Option<String>,
        pin_mode: bool,
    ) -> Arc<Self> {
        let (socks_tx, _) = broadcast::channel(SOCKS_COMMAND_CAPACITY);
        let (dial_tx, _) = broadcast::channel(DIAL_COMMAND_CAPACITY);
        let (name_tx, _) = broadcast::channel(NAME_COMMAND_CAPACITY);
        let (listen_tx, _) = broadcast::channel(LISTEN_COMMAND_CAPACITY);
        Arc::new(Self {
            role,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            token_generated,
            auth_token: RwLock::new(None),
            endpoint_id: RwLock::new(None),
            conn_status: RwLock::new(ConnStatus::Connecting),
            path: RwLock::new(PathInfo::establishing()),
            inbound: RwLock::new(None),
            socks_port: RwLock::new(socks_port),
            socks_status: RwLock::new(SocksStatus::Idle),
            socks_detail: RwLock::new(String::new()),
            socks_bound: RwLock::new(None),
            semaphore: RwLock::new(None),
            streams_max: RwLock::new(0),
            socks_tx,
            dial_tx,
            listen_tx,
            listen_status: RwLock::new(ListenStatus::Stopped),
            name_tx,
            name_conflict: RwLock::new(NameConflict::Inactive),
            dial_target: RwLock::new(None),
            nostr_discovery,
            pin_mode,
            current_pin: RwLock::new(None),
            pin_deadline: RwLock::new(None),
            own_name,
            shutdown: CancellationToken::new(),
            logs,
        })
    }

    /// Subscribe to SOCKS commands. Each connection supervisor subscribes once;
    /// only commands sent after subscribing are delivered (so reconnects start clean).
    pub fn subscribe_socks(&self) -> broadcast::Receiver<SocksCommand> {
        self.socks_tx.subscribe()
    }

    /// Send a SOCKS command to any active connection supervisor(s).
    pub fn send_socks_cmd(&self, cmd: SocksCommand) {
        let _ = self.socks_tx.send(cmd);
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

    /// Subscribe to serve-half commands. The listen supervisor subscribes once at startup.
    pub fn subscribe_listen(&self) -> broadcast::Receiver<ListenCommand> {
        self.listen_tx.subscribe()
    }

    /// Current serve-half status.
    pub fn listen_status(&self) -> ListenStatus {
        *self.listen_status.read()
    }

    /// Whether the serve half is currently up (drives node-id / PIN / token display).
    pub fn listening(&self) -> bool {
        matches!(self.listen_status(), ListenStatus::Listening)
    }

    /// Set the serve-half status (listen supervisor -> TUI).
    pub fn set_listen_status(&self, status: ListenStatus) {
        *self.listen_status.write() = status;
    }

    /// Toggle the serve half from the TUI (Shift+L): start it when stopped, stop it when
    /// listening. The supervisor guards against redundant Start/Stop, so a stale read here
    /// is harmless.
    pub fn toggle_listen(&self) {
        let cmd = match self.listen_status() {
            ListenStatus::Stopped => ListenCommand::Start,
            ListenStatus::Listening => ListenCommand::Stop,
        };
        let _ = self.listen_tx.send(cmd);
    }

    /// Tear down the serve half's surfaced state once it has stopped: back to `Stopped`,
    /// drop the displayed node id, and clear any rotating PIN (a fresh start mints new
    /// ones). Also drops the paired inbound peer / reservation (set only by the listener side)
    /// and any nostr name-conflict prompt/warning (raised only by the serve half's publisher):
    /// their owning tasks are aborted on stop and don't run their own cleanup, so without
    /// this the TUI would show a stale pairing/conflict after the serve half is down. The auth
    /// token value is left seeded — the UI gates its display on `listening()` instead. Clearing
    /// the reservation here matches the serve half minting a fresh, empty pairing claim on the
    /// next start, so a different device can then pair.
    pub fn clear_listen(&self) {
        *self.listen_status.write() = ListenStatus::Stopped;
        *self.endpoint_id.write() = None;
        *self.current_pin.write() = None;
        *self.pin_deadline.write() = None;
        *self.inbound.write() = None;
        *self.name_conflict.write() = NameConflict::Inactive;
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

    /// Whether an outbound dial session exists (connecting, connected, or backing off).
    pub fn dial_session_active(&self) -> bool {
        self.dial_target.read().is_some()
    }

    /// One-pairing rule: dialing out is allowed only while this run is not the
    /// listening side of a pairing. Strict exclusivity — listening at all (even
    /// before a peer pairs in) blocks dialing, so there is no window where an
    /// inbound pairing lands mid-dial.
    pub fn can_dial(&self) -> bool {
        !self.listening()
    }

    /// One-pairing rule, the other direction: listening may start only while no
    /// outbound dial session exists.
    pub fn can_listen(&self) -> bool {
        !self.dial_session_active()
    }

    /// Record the current rotating PIN (canonical form) and the instant it rolls over,
    /// for the PIN + refresh-countdown header. Set by the PIN publisher each rotation.
    pub fn set_current_pin(&self, pin: String, deadline: Instant) {
        *self.current_pin.write() = Some(pin);
        *self.pin_deadline.write() = Some(deadline);
    }

    /// Start the local SOCKS5 proxy. A no-op when no port is configured; the
    /// supervisor ignores a redundant Start if it is already running.
    pub fn start_socks(&self) {
        if self.socks_port.read().is_none() {
            return;
        }
        self.send_socks_cmd(SocksCommand::Start);
    }

    /// Stop the local SOCKS5 proxy. A no-op when no port is configured; the
    /// supervisor ignores a Stop if it is not running.
    pub fn stop_socks(&self) {
        if self.socks_port.read().is_none() {
            return;
        }
        self.send_socks_cmd(SocksCommand::Stop);
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

    /// Update the path of the paired inbound peer, matched by `remote_id`.
    pub fn set_peer_path(&self, remote_id: &str, path: PathInfo) {
        let mut inbound = self.inbound.write();
        if let Some(peer) = inbound.as_mut().filter(|p| p.remote_id == remote_id) {
            peer.path = path;
        }
    }

    /// Register a newly-authenticated connection from the inbound peer — called after each
    /// successful auth (including reconnects). It becomes (or, in the rare case a different id
    /// appears, replaces) this listen session's single paired peer. Since only one pair is allowed
    /// this is a set, not an append; overlapping connections from the same peer bump a refcount so a
    /// reconnect overlap never reads as disconnected. `connected_since` is stamped only on the
    /// idle→connected transition so it reflects the current session, not each overlapping dial.
    pub fn mark_peer_connected(&self, remote_id: String) {
        let mut inbound = self.inbound.write();
        match inbound.as_mut() {
            Some(p) if p.remote_id == remote_id => {
                if p.active_conns == 0 {
                    p.connected_since = Instant::now();
                    p.path = PathInfo::establishing();
                }
                p.active_conns += 1;
            }
            _ => {
                *inbound = Some(InboundPeer {
                    remote_id,
                    active_conns: 1,
                    connected_since: Instant::now(),
                    path: PathInfo::establishing(),
                });
            }
        }
    }

    /// Drop one live connection from the paired inbound peer. When its last connection closes the
    /// peer is kept as the endpoint's reservation (just flagged disconnected), so the header still
    /// shows the endpoint is reserved for it (it may reconnect without re-authenticating); the
    /// reservation is released only when the serve half stops (`clear_listen`). The refcount means a
    /// reconnect overlap (a newer connection still live) keeps the peer shown as connected.
    pub fn mark_peer_disconnected(&self, remote_id: &str) {
        let mut inbound = self.inbound.write();
        if let Some(p) = inbound.as_mut().filter(|p| p.remote_id == remote_id) {
            p.active_conns = p.active_conns.saturating_sub(1);
        }
    }

    /// Reset the proxy's status to `Idle` (clearing any detail and bound address)
    /// on each (re)connection. The configured port persists across reconnects.
    pub fn reset_socks_status(&self) {
        *self.socks_status.write() = SocksStatus::Idle;
        self.socks_detail.write().clear();
        *self.socks_bound.write() = None;
    }

    /// The configured SOCKS5 port (used by the connection supervisor on `Start`).
    pub fn socks_port(&self) -> Option<u16> {
        *self.socks_port.read()
    }

    /// Whether a SOCKS5 port is configured.
    pub fn has_socks(&self) -> bool {
        self.socks_port.read().is_some()
    }

    /// Whether the proxy is currently running (used to gate the set/clear actions).
    pub fn socks_running(&self) -> bool {
        self.socks_status.read().is_running()
    }

    /// Set (or replace) the SOCKS5 port, resetting the status to `Idle`. The caller
    /// guarantees the proxy is not running. No `Start` is sent here.
    pub fn set_socks_port(&self, port: u16) {
        *self.socks_port.write() = Some(port);
        self.reset_socks_status();
    }

    /// Remove the SOCKS5 port from the session (config is never touched). If the
    /// proxy is running, a `Stop` is broadcast first so the supervisor cancels its
    /// task and frees the bound local port.
    pub fn clear_socks(&self) {
        self.send_socks_cmd(SocksCommand::Stop);
        *self.socks_port.write() = None;
        self.reset_socks_status();
    }

    /// Update the proxy's status/detail.
    pub fn update_socks(&self, status: SocksStatus, detail: impl Into<String>) {
        *self.socks_status.write() = status;
        *self.socks_detail.write() = detail.into();
    }

    /// Record (or clear) the proxy's actually-bound loopback address.
    pub fn set_socks_bound(&self, addr: Option<SocketAddr>) {
        *self.socks_bound.write() = addr;
    }

    /// The proxy's bound loopback address while running (`None` otherwise). Used by
    /// tests to learn the OS-assigned port when binding with port 0.
    #[cfg(test)]
    pub fn socks_bound(&self) -> Option<SocketAddr> {
        *self.socks_bound.read()
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
        let socks = self.socks_port.read().map(|port| SocksRow {
            port,
            status: *self.socks_status.read(),
            detail: self.socks_detail.read().clone(),
        });
        AppSnapshot {
            role: self.role,
            hostname: self.hostname.clone(),
            listening: self.listening(),
            token_generated: self.token_generated,
            nostr_discovery: self.nostr_discovery,
            pin_mode: self.pin_mode,
            current_pin: self.current_pin.read().clone(),
            pin_deadline: *self.pin_deadline.read(),
            own_name: self.own_name.clone(),
            endpoint_id: self.endpoint_id.read().clone(),
            auth_token: self.auth_token.read().clone(),
            conn_status: self.conn_status.read().clone(),
            path: self.path.read().clone(),
            dial_target: self.dial_target.read().clone(),
            name_conflict: self.name_conflict.read().clone(),
            inbound: self.inbound.read().clone(),
            socks,
            streams_used,
            streams_max,
        }
    }
}

/// Owned, lock-free view of [`AppState`] for a single render pass.
pub struct AppSnapshot {
    pub role: Role,
    pub hostname: String,
    /// Whether the serve half is currently up. `false` until the user presses Shift+L;
    /// gates the node-id / PIN / auth-token display.
    pub listening: bool,
    pub token_generated: bool,
    pub nostr_discovery: bool,
    pub pin_mode: bool,
    /// Current rotating PIN (canonical form) and the instant it rolls over; `Some` only
    /// in quick PIN mode once the publisher has generated the first PIN.
    pub current_pin: Option<String>,
    pub pin_deadline: Option<Instant>,
    pub own_name: Option<String>,
    pub endpoint_id: Option<String>,
    pub auth_token: Option<String>,
    pub conn_status: ConnStatus,
    pub path: PathInfo,
    /// Current dial target's display string; `None` when idle (serving only).
    pub dial_target: Option<String>,
    /// Current nostr name-conflict state (drives the conflict modal / warning).
    pub name_conflict: NameConflict,
    /// The single inbound peer paired this listen session, or `None`. `connected == false` means it
    /// is currently disconnected but the endpoint stays reserved for it.
    pub inbound: Option<InboundPeer>,
    /// The configured SOCKS5 proxy's row, or `None` when no port is set.
    pub socks: Option<SocksRow>,
    pub streams_used: usize,
    pub streams_max: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogBuffer;

    #[test]
    fn config_socks_port_seeded_into_snapshot_at_construction() {
        // A configured SOCKS port must be visible (Idle) in the dashboard from launch.
        let state = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            Some(1080),
            false,
            None,
            false,
        );
        assert!(state.has_socks());
        let row = state.snapshot().socks.expect("socks row present");
        assert_eq!(row.port, 1080);
        assert_eq!(row.status, SocksStatus::Idle);
    }

    #[test]
    fn set_and_clear_socks_port() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), None, false, None, false);
        assert!(!state.has_socks());
        assert!(state.snapshot().socks.is_none());

        state.set_socks_port(1080);
        assert!(state.has_socks());
        assert_eq!(state.socks_port(), Some(1080));
        let row = state.snapshot().socks.expect("row present");
        assert_eq!(row.port, 1080);
        assert_eq!(row.status, SocksStatus::Idle);

        // Replacing in place keeps a single port.
        state.set_socks_port(1081);
        assert_eq!(state.socks_port(), Some(1081));

        state.clear_socks();
        assert!(!state.has_socks());
        assert!(state.snapshot().socks.is_none());
    }

    #[test]
    fn update_socks_reflects_in_snapshot() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), None, false, None, false);
        state.set_socks_port(1080);

        state.update_socks(SocksStatus::Listening, "127.0.0.1:1080");
        state.set_socks_bound(Some("127.0.0.1:1080".parse().unwrap()));
        assert!(state.socks_running());
        assert_eq!(state.socks_bound(), Some("127.0.0.1:1080".parse().unwrap()));
        let row = state.snapshot().socks.expect("row present");
        assert_eq!(row.status, SocksStatus::Listening);
        assert_eq!(row.detail, "127.0.0.1:1080");

        // A (re)connection resets the status back to Idle and drops the bound addr.
        state.reset_socks_status();
        assert!(!state.socks_running());
        assert!(state.socks_bound().is_none());
        assert_eq!(
            state.snapshot().socks.expect("row present").status,
            SocksStatus::Idle
        );
    }

    #[test]
    fn pairing_gates_enforce_listen_xor_dial() {
        let state = AppState::new(Role::Both, false, LogBuffer::new(16), None, false, None, false);
        // Idle: both directions available.
        assert!(state.can_dial());
        assert!(state.can_listen());

        // Listening blocks dialing (even before an inbound peer pairs).
        state.set_listen_status(ListenStatus::Listening);
        assert!(!state.can_dial());
        assert!(state.can_listen());
        state.clear_listen();
        assert!(state.can_dial());

        // An outbound dial session blocks listening.
        state.set_dial_target(Some("peer".into()));
        assert!(state.dial_session_active());
        assert!(!state.can_listen());
        assert!(state.can_dial());
        state.set_dial_target(None);
        assert!(state.can_listen());
    }

    #[test]
    fn listener_pairs_with_one_peer_and_reserves_on_disconnect() {
        let state = AppState::new(Role::Listen, false, LogBuffer::new(16), None, false, None, false);

        // The first peer to authenticate becomes the single paired peer.
        state.mark_peer_connected("peer-a".into());
        let p = state.snapshot().inbound.expect("paired");
        assert_eq!(p.remote_id, "peer-a");
        assert!(p.connected());

        // Reconnect overlap: a second connection from the same peer authenticates before the first
        // has closed (refcount 2). Dropping the older one must keep the peer shown as connected.
        state.mark_peer_connected("peer-a".into());
        state.mark_peer_disconnected("peer-a");
        let p = state.snapshot().inbound.expect("still paired");
        assert_eq!(p.remote_id, "peer-a");
        assert!(p.connected(), "an overlapping live connection must stay connected");

        // Once the last connection closes the peer is retained as the reservation, flagged
        // disconnected.
        state.mark_peer_disconnected("peer-a");
        let p = state.snapshot().inbound.expect("still reserved");
        assert_eq!(p.remote_id, "peer-a");
        assert!(!p.connected());

        // An extra disconnect (e.g. a late close) cannot underflow the refcount.
        state.mark_peer_disconnected("peer-a");
        assert!(!state.snapshot().inbound.expect("still reserved").connected());

        // Stopping the serve half releases the reservation.
        state.clear_listen();
        assert!(state.snapshot().inbound.is_none());
    }

    #[test]
    fn snapshot_carries_mode_metadata() {
        let state = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            None,
            true,
            Some("web1".to_string()),
            false,
        );

        let snap = state.snapshot();

        assert!(snap.nostr_discovery);
        assert_eq!(snap.own_name.as_deref(), Some("web1"));
    }

    #[test]
    fn name_conflict_state_transitions_in_snapshot() {
        let state = AppState::new(Role::Both, false, LogBuffer::new(16), None, true, None, false);
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

    #[test]
    fn pin_dial_target_describe_never_echoes_the_pin() {
        // The rotating PIN is a secret and must not appear in the outbound display string;
        // the placeholder is shown until the dial session swaps in the resolved node id.
        let d = DialTarget::Pin("AH5AFBEJ".to_string()).describe();
        assert_eq!(d, "PIN");
        assert!(!d.contains("AH5A"));
        assert!(!d.contains("AH5A-FBEJ"));
    }

    #[test]
    fn node_id_dial_target_describe_truncates() {
        let id = iroh::SecretKey::generate().public();
        let d = DialTarget::NodeId(id).describe();
        assert!(d.ends_with('…'), "truncated form ends with ellipsis: {d}");
        // First 12 id chars plus the ellipsis.
        assert_eq!(d.chars().count(), 13);
        assert!(id.to_string().starts_with(&d[..d.len() - '…'.len_utf8()]));
    }
}
