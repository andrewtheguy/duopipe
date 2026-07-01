//! iroh peer runtime: on-demand serving plus on-demand dial sessions.
//!
//! Interactive peers run as `Role::Both`: a `Role::Listen` half that serves inbound
//! peers (started on-demand via Shift+L; idle until then), plus a dial manager that
//! owns at most one outbound `Role::Dial` session. Within any one connection, only the dialer opens its
//! single tunnel: the tunnel binds a local listener and, per accepted connection,
//! asks the connected peer to connect out over TCP to a bare `host:port` source,
//! bridging the two. The tunnel is activated on demand (the TUI sends start/stop
//! commands); nothing starts automatically unless `DUOPIPE_AUTOSTART_TUNNELS` is
//! set (test mode only).
//!
//! Every non-auth stream begins with a [`StreamHello`] so the acceptor can route
//! it without positional assumptions. Trust model: once token auth passes, the
//! peer is fully trusted — the acceptor connects out to any `host:port` it
//! requests (there is no source allowlist).

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::endpoint::ConnectionError;
use iroh::{Endpoint, EndpointId};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::app_state::{
    AppState, ConnStatus, DialCommand, DialTarget, ListenCommand, ListenStatus, NameCommand,
    NameConflict, Role, TunnelCommand, TunnelStatus,
};
use crate::auth::is_token_valid;
use crate::config::{TransportTuning, TunnelEntry};
use crate::error::{ErrorCategory, TunnelError};
use crate::net::{
    resolve_all_target_addrs, resolve_listen_addrs, try_connect_tcp, tune_tcp_stream,
};

use crate::iroh_mode::endpoint::{
    ALPN, connect_to_server, create_client_endpoint, create_server_endpoint, validate_relay_only,
    watch_connection_paths,
};
use crate::iroh_mode::helpers::{bridge_streams, open_bi_with_retry};
use crate::signaling::{
    AuthRequest, AuthResponse, StreamAck, StreamHello, decode_auth_request, decode_auth_response,
    decode_stream_ack, decode_stream_hello, encode_auth_request, encode_auth_response,
    encode_stream_ack, encode_stream_hello, read_length_prefixed,
};

/// How many recent buckets' PIN keys the listener retains for in-band PIN auth. Mirrors the
/// dialer's adjacent-bucket look-back in `nostr_discovery::lookup_pin_record`.
const RECENT_PIN_CACHE: usize = 3;

/// Recent PIN auth keypairs (newest first), one per rotation bucket the quick-mode listener has
/// published. Written by the PIN publisher, read by the listener auth path to verify a dialer's
/// proof. Cheap to clone (shared handle).
#[derive(Clone, Default)]
struct RecentPins(Arc<parking_lot::RwLock<VecDeque<nostr_sdk::Keys>>>);

impl RecentPins {
    fn push(&self, keys: nostr_sdk::Keys) {
        let mut g = self.0.write();
        g.push_front(keys);
        while g.len() > RECENT_PIN_CACHE {
            g.pop_back();
        }
    }

    fn snapshot(&self) -> Vec<nostr_sdk::Keys> {
        self.0.read().iter().cloned().collect()
    }
}

/// How a connection authenticates. Chosen by the caller from the dial target (outbound) or the
/// listener's mode (inbound), and consumed by [`handle_connection`].
enum AuthMode {
    /// Outbound: present a pre-shared token (connect mode, manual quick mode, headless test).
    DialToken(String),
    /// Outbound: prove PIN possession in-band (quick PIN mode).
    DialPin(String),
    /// Inbound: accept any of `tokens`; if `pin_cache` is `Some` (quick-mode listener), also
    /// accept a valid PIN proof against the retained recent-bucket keys.
    Listen {
        tokens: HashSet<String>,
        pin_cache: Option<RecentPins>,
    },
}

/// Default maximum concurrent forwarded streams across all tunnels in the session.
const DEFAULT_MAX_STREAMS: usize = 100;

/// Timeout for the authentication handshake.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading a stream's leading [`StreamHello`] (prevents a stalled
/// opener from holding a stream permit indefinitely).
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading a [`StreamAck`].
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection close code for authentication failure (invalid token).
const AUTH_FAILED_CODE: u32 = 1;

/// Connection close code for authentication timeout (no auth within deadline).
const AUTH_TIMEOUT_CODE: u32 = 2;

/// Connection close code for a clean local shutdown (Ctrl-C). "No error" by
/// convention; the peer just sees the connection go away.
const SHUTDOWN_CODE: u32 = 0;

/// Maximum reconnect backoff for the dialing peer.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// Maximum number of attempts to establish the *first* connection before giving
/// up. Once a connection has been established and served at least once, the
/// dialer reconnects without limit. This bounds the startup phase so a peer that
/// is unreachable — or a node id already held by another live process (which
/// leaves the dialer endlessly `peer_busy`) — fails fast instead of looping
/// forever.
const MAX_INITIAL_CONNECT_ATTEMPTS: u32 = 10;

/// Runtime configuration for a symmetric peer.
#[derive(Clone)]
pub struct PeerConfig {
    /// Connection role (dial out, listen, or both at once).
    pub role: Role,
    /// EndpointId of the peer to dial (required for `Dial`; the dial half's target
    /// for `Both` in quick mode).
    pub peer_node_id: Option<EndpointId>,
    /// When true, start every configured tunnel as soon as a connection is up
    /// (set from `DUOPIPE_AUTOSTART_TUNNELS` in test mode; see `DUOPIPE_TEST_MODE`).
    pub autostart_tunnels: bool,
    /// The shared auth token (presented when dialing, required when listening).
    /// Also the rendezvous secret for nostr discovery: both peers derive the same
    /// nostr key from it. **Sensitive - redacted in Debug.**
    pub auth_token: String,
    /// Nostr relay URLs used for node-id discovery.
    pub nostr_relays: Vec<String>,
    /// When true, use the nostr side channel: the listener publishes its current
    /// ephemeral node id; the dialer looks it up (keyed off `auth_token`). The iroh
    /// identity itself is always ephemeral. Disabled in headless test mode, where
    /// the dialer's node id is wired directly.
    pub nostr_discovery: bool,
    /// Short identifier for nostr discovery. For the always-on serve half (and the
    /// combined interactive process) this is the name it publishes its node id under;
    /// for the headless dial test path it is the target peer's name to look up. (An
    /// interactive dial session resolves its target's name at connect time instead.)
    /// `None` outside config mode.
    pub nostr_identifier: Option<String>,
    /// Quick mode's nostr PIN signaling. When true, the listener half publishes a rotating
    /// PIN record (just the ephemeral node id, encrypted under a PIN-derived key) over
    /// `nostr_relays`; the dial manager resolves a [`DialTarget::Pin`] to that node id and then
    /// authenticates the connection in-band with the same PIN (see `crate::pin_auth`) — the auth
    /// token is never on a relay. Distinct from `nostr_discovery` (the name-based node-id
    /// discovery used by connect mode). `false` in config mode and headless test mode.
    pub pin_rendezvous: bool,
    /// Whether this config's endpoint owns the node id surfaced in the TUI / published
    /// to nostr. Single roles set `true`; in `Role::Both` only the listen sub-config is
    /// `true` so the dial half's separate ephemeral endpoint id doesn't clobber it.
    pub report_endpoint_id: bool,
    /// Iroh relay URLs.
    pub relay_urls: Vec<String>,
    /// Whether to force relay-only mode (disables direct P2P).
    pub relay_only: bool,
    /// Custom DNS server, or "none" to disable DNS discovery.
    pub dns_server: Option<String>,
    /// Maximum concurrent forwarded streams across all tunnels (None = default).
    pub max_streams: Option<usize>,
    /// Transport layer tuning.
    pub transport: TransportTuning,
    /// When true (non-interactive/test mode), print the bound node id + token to
    /// stderr so a test harness can wire up the dialing side. The interactive TUI
    /// shows them in its header instead and leaves this false.
    pub announce_endpoint: bool,
    /// Path to the loaded peer config file (config mode), used to append a rename nudge
    /// when the user resolves a name conflict. `None` in quick/headless modes.
    pub config_path: Option<PathBuf>,
    /// Shared state surfaced by the TUI.
    pub status: Arc<AppState>,
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("role", &self.role.label())
            .field("peer_node_id", &self.peer_node_id)
            .field("autostart_tunnels", &self.autostart_tunnels)
            .field("auth_token", &"[REDACTED]")
            .field("nostr_relays", &self.nostr_relays)
            .field("nostr_discovery", &self.nostr_discovery)
            .field("nostr_identifier", &self.nostr_identifier)
            .field("pin_rendezvous", &self.pin_rendezvous)
            .field("report_endpoint_id", &self.report_endpoint_id)
            .field("relay_urls", &self.relay_urls)
            .field("relay_only", &self.relay_only)
            .field("dns_server", &self.dns_server)
            .field("max_streams", &self.max_streams)
            .field("transport", &self.transport)
            .field("announce_endpoint", &self.announce_endpoint)
            .field("config_path", &self.config_path)
            .field("status", &"<present>")
            .finish()
    }
}

/// Run a symmetric peer: dial or listen, then serve tunnels in both directions.
pub async fn run_peer(config: PeerConfig) -> Result<()> {
    validate_relay_only(config.relay_only, &config.relay_urls)?;

    // One global stream limiter for the whole process, created up front so the
    // combined process shares a single cap across its serve and dial halves.
    let semaphore = new_stream_semaphore(&config)?;

    match config.role {
        // Headless test mode listens immediately; its child token simply mirrors the
        // global shutdown (there is no interactive Shift+L toggle here). This path bypasses
        // the supervisor, so set the status here to keep it consistent with an active
        // listener.
        Role::Listen => {
            let listen_shutdown = config.status.shutdown.child_token();
            config.status.set_listen_status(ListenStatus::Listening);
            run_listen(config, semaphore, listen_shutdown).await
        }
        Role::Dial => run_dial(config, semaphore).await,
        Role::Both => run_serve_and_dial(config, semaphore).await,
    }
}

/// Split the interactive `Role::Both` config into a listen sub-config (run on-demand by
/// the listen supervisor) and a dial sub-config (used by the dial manager). Both share the same `Arc<AppState>`
/// and the one stream semaphore; the dial target itself is supplied at runtime via
/// [`DialCommand`], not by config.
fn split_serve_dial_config(config: &PeerConfig) -> (PeerConfig, PeerConfig) {
    let mut listen = config.clone();
    listen.role = Role::Listen;
    listen.peer_node_id = None;
    listen.autostart_tunnels = false;
    // The listen endpoint owns the displayed/published node id.
    listen.report_endpoint_id = true;

    let mut dial = config.clone();
    dial.role = Role::Dial;
    // No fixed target: the dial manager dials whatever the user requests at runtime.
    dial.peer_node_id = None;
    dial.nostr_identifier = None;
    // The dial endpoint is secondary; its node id is internal.
    dial.report_endpoint_id = false;

    (listen, dial)
}

/// Interactive runtime: a listen supervisor (the serve half, started on-demand via
/// Shift+L) alongside a dial manager that maintains at most one user-initiated outbound
/// session. The two halves share `AppState` and the stream semaphore but never interact at
/// the connection layer. If either half returns, the shared shutdown is cancelled so the
/// other unwinds.
async fn run_serve_and_dial(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    let (listen_cfg, dial_cfg) = split_serve_dial_config(&config);
    let shutdown = config.status.shutdown.clone();

    let listen_sem = semaphore.clone();
    // Tag every record from each half so the single combined log pane is attributable.
    // The serve half no longer auto-starts: the supervisor idles until the TUI sends a
    // Shift+L `ListenCommand::Start`.
    let mut listen_task = tokio::spawn(crate::logging::scoped(
        "serve",
        run_listen_supervisor(listen_cfg, listen_sem),
    ));
    let mut dial_task = tokio::spawn(crate::logging::scoped(
        "dial",
        run_dial_manager(dial_cfg, semaphore),
    ));

    let first = tokio::select! {
        r = &mut listen_task => ("listen", r),
        r = &mut dial_task => ("dial manager", r),
    };
    shutdown.cancel();
    let second = if first.0 == "listen" {
        ("dial manager", dial_task.await)
    } else {
        ("listen", listen_task.await)
    };

    for (which, joined) in [first, second] {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.context(format!("{which} half failed"))),
            Err(e) => anyhow::bail!("{which} half panicked: {e}"),
        }
    }
    Ok(())
}

/// Drive the single on-demand dial session. Owns one reused client endpoint, idles until
/// the TUI sends [`DialCommand::Connect`], runs a session until it is disconnected,
/// replaced, or the process shuts down, then returns to idle. At most one session lives
/// at a time, so a `Connect` while connected replaces the current target.
async fn run_dial_manager(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    let endpoint = create_client_endpoint(
        &config.relay_urls,
        config.relay_only,
        config.dns_server.as_deref(),
        Some(&config.transport),
    )
    .await?;
    let own_id = endpoint.id();
    let shutdown = config.status.shutdown.clone();
    let config = Arc::new(config);
    let mut dial_rx = config.status.subscribe_dial();

    // No session yet: serving only.
    config.status.set_conn_status(ConnStatus::Idle);

    // The single active dial session, if any: its cancel token + task handle.
    let mut current: Option<(CancellationToken, tokio::task::JoinHandle<()>)> = None;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            cmd = dial_rx.recv() => match cmd {
                Ok(DialCommand::Connect(target)) => {
                    // Single session: tear down any current one first.
                    if let Some((tok, h)) = current.take() {
                        tok.cancel();
                        let _ = h.await;
                    }
                    config.status.set_dial_target(Some(target.describe()));
                    config.status.set_conn_status(ConnStatus::Connecting);
                    let tok = CancellationToken::new();
                    let session_tok = tok.clone();
                    let cfg = config.clone();
                    let sem = semaphore.clone();
                    let ep = endpoint.clone();
                    let h = tokio::spawn(crate::logging::inherit_source(async move {
                        run_managed_dial_session(cfg, sem, &ep, own_id, target, session_tok).await;
                    }));
                    current = Some((tok, h));
                }
                Ok(DialCommand::Disconnect) => {
                    if let Some((tok, h)) = current.take() {
                        tok.cancel();
                        let _ = h.await;
                    }
                    config.status.set_dial_target(None);
                    config.status.set_conn_status(ConnStatus::Idle);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("Dial command channel lagged by {n}");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }

    if let Some((tok, h)) = current.take() {
        tok.cancel();
        let _ = h.await;
    }
    endpoint.close().await;
    Ok(())
}

/// One on-demand dial session against a single `target`. Mirrors `run_dial`'s
/// connect/reconnect/backoff loop, but resolves the runtime-typed [`DialTarget`] each
/// attempt, also bails on session `cancel` (disconnect/replace), and **ends the session
/// rather than the process** on a fatal auth failure or self-dial (the serving half
/// keeps running). Transient connect/disconnect just reconnects with backoff until the
/// user disconnects.
async fn run_managed_dial_session(
    config: Arc<PeerConfig>,
    semaphore: Arc<Semaphore>,
    endpoint: &Endpoint,
    own_id: EndpointId,
    target: DialTarget,
    cancel: CancellationToken,
) {
    let shutdown = config.status.shutdown.clone();
    let mut backoff = Duration::from_secs(1);

    loop {
        config.status.set_conn_status(ConnStatus::Connecting);

        // Resolve the target each attempt: a nostr name re-resolves so a listener that
        // restarted with a fresh ephemeral id self-heals on the next try. A PIN resolves to just
        // the node id — the token is never on the relay; the PIN authenticates the connection
        // in-band after we dial (see the `AuthMode` selection below).
        let resolved: Result<EndpointId> = match &target {
            DialTarget::NodeId(id) => Ok(*id),
            DialTarget::Name(name) => {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = cancel.cancelled() => return,
                    r = crate::nostr_discovery::lookup_node_id(
                        &config.auth_token,
                        name,
                        &config.nostr_relays,
                    ) => match r {
                        Ok(id) => {
                            log::info!("Discovered peer '{name}' node id via nostr: {id}");
                            Ok(id)
                        }
                        Err(e) => Err(e.context("nostr node-id lookup failed")),
                    },
                }
            }
            DialTarget::Pin(pin) => {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = cancel.cancelled() => return,
                    r = crate::nostr_discovery::lookup_pin_record(pin, &config.nostr_relays) => {
                        match r {
                            Ok(Some(id)) => {
                                log::info!("Resolved PIN to peer node id via nostr: {id}");
                                Ok(id)
                            }
                            Ok(None) => Err(anyhow::anyhow!(
                                "no peer found for that PIN (it refreshes every 60s — check the current code on the other device)"
                            )),
                            Err(e) => Err(e.context("nostr PIN lookup failed")),
                        }
                    }
                }
            }
        };

        // Self-dial guard: end the session (not the process) — the target won't change.
        // Reject both the dial endpoint's own id *and* this process's published (serve)
        // node id, which is a separate endpoint in the combined process — so dialing our
        // own published id (a quick-mode paste, or a name that resolves back to us) is
        // caught here as a last line of defense behind the connect prompt's checks.
        if let Ok(id) = &resolved {
            let id_str = id.to_string();
            let is_own_published =
                config.status.snapshot().endpoint_id.as_deref() == Some(id_str.as_str());
            if *id == own_id || is_own_published {
                log::error!("Refusing to dial this peer's own node id ({id}); ending session.");
                config.status.set_conn_status(ConnStatus::Closed);
                config.status.set_dial_target(None);
                return;
            }
            // A PIN dial starts out displaying the bare "PIN" placeholder (the rotating
            // secret is never echoed); now that it resolved, surface the peer's truncated
            // node id so the outbound line is meaningful. Other targets keep their display.
            if matches!(target, DialTarget::Pin(_)) {
                config
                    .status
                    .set_dial_target(Some(DialTarget::NodeId(*id).describe()));
            }
        }

        let connect = match resolved {
            Ok(id) => {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = cancel.cancelled() => return,
                    c = connect_to_server(
                        endpoint,
                        id,
                        &config.relay_urls,
                        config.relay_only,
                        ALPN,
                    ) => c,
                }
            }
            Err(e) => Err(e),
        };

        match connect {
            Ok(conn) => {
                config.status.set_conn_status(ConnStatus::Connected);
                log::info!("Connected to peer!");
                // A PIN dial authenticates in-band with the PIN (no token on the wire); every
                // other target presents this process's own token.
                let auth = match &target {
                    DialTarget::Pin(pin) => AuthMode::DialPin(pin.clone()),
                    _ => AuthMode::DialToken(config.auth_token.clone()),
                };
                // handle_connection returns on conn-close or process shutdown; also race
                // the session cancel so a disconnect/replace tears it down promptly.
                let outcome = tokio::select! {
                    r = handle_connection(conn, config.clone(), semaphore.clone(), auth) => Some(r),
                    _ = cancel.cancelled() => None,
                };
                match outcome {
                    // Session cancelled (disconnect or replaced by a new target).
                    None => return,
                    Some(Ok(())) => {
                        backoff = Duration::from_secs(1);
                        log::info!("Connection closed; will reconnect");
                    }
                    Some(Err(e)) => {
                        // Auth failures are fatal for this target (the shared token is
                        // wrong for it) — end the session and surface it.
                        if e.downcast_ref::<TunnelError>()
                            .is_some_and(|te| matches!(te.category, ErrorCategory::Auth))
                        {
                            log::error!("Dial session ended (auth failure): {e}");
                            config.status.set_conn_status(ConnStatus::Closed);
                            config.status.set_dial_target(None);
                            return;
                        }
                        log::warn!("Connection ended: {e}");
                    }
                }
            }
            Err(e) => log::warn!("Failed to connect to peer: {e}"),
        }

        config.status.set_conn_status(ConnStatus::Reconnecting {
            backoff_secs: backoff.as_secs(),
        });
        log::info!("Reconnecting in {:?}...", backoff);
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
    }
}

// ============================================================================
// Serve half (always-on, handles inbound peers) — also the headless `Role::Listen`
// test path
// ============================================================================

/// Create the global stream limiter and register it for the TUI gauge. Shared by
/// every peer connection — one process-wide cap on concurrent forwarded streams.
///
/// Fails fast on `max_streams = 0`: a zero-permit semaphore would reject *every*
/// forwarded stream, silently breaking all tunnels. `Config::validate()` doesn't
/// cover this, so guard it here before any tunnel setup runs.
fn new_stream_semaphore(config: &PeerConfig) -> Result<Arc<Semaphore>> {
    let max_streams = config.max_streams.unwrap_or(DEFAULT_MAX_STREAMS);
    if max_streams == 0 {
        anyhow::bail!("max_streams must be greater than 0 (got 0; it caps concurrent streams)");
    }
    let semaphore = Arc::new(Semaphore::new(max_streams));
    config.status.set_semaphore(semaphore.clone(), max_streams);
    Ok(semaphore)
}

/// Supervise the serve half for interactive `Role::Both`. The serve half does not
/// auto-start: this idles with the endpoint down (no node id / PIN / token shown) until
/// the TUI sends [`ListenCommand::Start`] (Shift+L). `Start` brings up one [`run_listen`]
/// under a child cancellation token; `Stop` cancels it and returns to idle (a later
/// `Start` mints a fresh ephemeral id). At most one serve endpoint lives at a time.
async fn run_listen_supervisor(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    let shutdown = config.status.shutdown.clone();
    let mut listen_rx = config.status.subscribe_listen();
    config.status.set_listen_status(ListenStatus::Stopped);

    // The single active serve endpoint, if any: its cancel token + task handle.
    let mut current: Option<(CancellationToken, tokio::task::JoinHandle<Result<()>>)> = None;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            cmd = listen_rx.recv() => match cmd {
                Ok(ListenCommand::Start) => {
                    if current.is_none() {
                        let tok = shutdown.child_token();
                        config.status.set_listen_status(ListenStatus::Listening);
                        let cfg = config.clone();
                        let sem = semaphore.clone();
                        let listen_tok = tok.clone();
                        let h = tokio::spawn(crate::logging::scoped(
                            "serve",
                            run_listen(cfg, sem, listen_tok),
                        ));
                        current = Some((tok, h));
                    }
                }
                Ok(ListenCommand::Stop) => {
                    if let Some((tok, h)) = current.take() {
                        tok.cancel();
                        join_stopped_listen(h).await;
                        config.status.clear_listen();
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("Listen command channel lagged by {n}");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            // The serve half ended on its own (e.g. a fatal endpoint error): reflect that
            // in the UI and propagate the error so the process unwinds.
            res = async { (&mut current.as_mut().unwrap().1).await }, if current.is_some() => {
                current = None;
                config.status.clear_listen();
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e.context("serve half failed")),
                    Err(e) => anyhow::bail!("serve half panicked: {e}"),
                }
            }
        }
    }

    if let Some((tok, h)) = current.take() {
        tok.cancel();
        join_stopped_listen(h).await;
    }
    Ok(())
}

/// Await a serve task that was just cancelled (user Stop or global shutdown). A clean
/// teardown returns `Ok(())`; an error or panic is logged rather than propagated, since
/// the cancellation was intentional and must not crash the process or the dial half.
async fn join_stopped_listen(h: tokio::task::JoinHandle<Result<()>>) {
    match h.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("serve half stopped with error: {e:#}"),
        Err(e) => log::warn!("serve half panicked on stop: {e}"),
    }
}

/// Run the serve half: create the public endpoint, publish/display the node id and auth
/// token, start the nostr/PIN publishers, and accept inbound peers until `listen_shutdown`
/// fires. `listen_shutdown` is a child of the global shutdown (so process shutdown still
/// stops it) but can also be cancelled on its own (Shift+L stop) to tear down just this
/// half without ending the process.
async fn run_listen(
    config: PeerConfig,
    semaphore: Arc<Semaphore>,
    listen_shutdown: CancellationToken,
) -> Result<()> {
    log::info!("duopipe serve half — listening for inbound peers");
    log::info!("=================================================");

    let endpoint = create_server_endpoint(
        &config.relay_urls,
        config.relay_only,
        config.dns_server.as_deref(),
        ALPN,
        Some(&config.transport),
    )
    .await?;

    let endpoint_id = endpoint.id();
    if config.report_endpoint_id {
        config.status.set_endpoint_id(endpoint_id.to_string());
    }
    config.status.set_auth_token(config.auth_token.clone());
    if config.announce_endpoint {
        // Non-interactive mode: surface both on stderr for a test harness.
        eprintln!("node_id: {endpoint_id}");
        eprintln!("auth_token: {}", config.auth_token);
    }
    log::info!("node id: {}", endpoint_id);
    log::info!("Dial this instance with the node id and auth token.");
    log::info!("Waiting for peers to connect...");

    // Publish the (ephemeral) node id to nostr under this peer's identifier so a peer
    // sharing the auth token can discover it by name without a manual node-id
    // exchange. Runs in the background and republishes periodically; relay failures
    // are logged but non-fatal (peers who already have the node id still connect).
    let _publisher = match (config.nostr_discovery, config.nostr_identifier.clone()) {
        (true, Some(identifier)) => Some(spawn_node_id_publisher(PublisherParams {
            auth_token: config.auth_token.clone(),
            identifier,
            node_id: endpoint_id,
            relays: config.nostr_relays.clone(),
            shutdown: listen_shutdown.clone(),
            state: config.status.clone(),
            // The interactive TUI can prompt; headless test mode (announce_endpoint)
            // cannot, so it degrades silently instead of blocking.
            interactive: !config.announce_endpoint,
            config_path: config.config_path.clone(),
        })),
        _ => None,
    };

    // Quick PIN mode: publish a rotating PIN record (just the ephemeral node id, encrypted under
    // a PIN-derived key) so a dialer can connect by typing a short code, and authenticate the
    // connection in-band with that same PIN. The publisher also records each bucket's PIN auth key
    // in `recent_pins` so the listener auth path can verify a dialer's proof. Independent of the
    // name-based node-id discovery above; runs only when explicitly enabled.
    let recent_pins = RecentPins::default();
    let pin_cache = config.pin_rendezvous.then(|| recent_pins.clone());
    let _pin_publisher = if config.pin_rendezvous {
        Some(PublisherGuard(tokio::spawn(crate::logging::inherit_source(
            run_pin_publisher(
                endpoint_id,
                recent_pins,
                config.nostr_relays.clone(),
                config.status.clone(),
                listen_shutdown.clone(),
            ),
        ))))
    } else {
        None
    };

    let shutdown = listen_shutdown;
    let config = Arc::new(config);
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        while connection_tasks.try_join_next().is_some() {}

        let incoming = tokio::select! {
            _ = shutdown.cancelled() => break,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => {
                    log::info!("Endpoint closed");
                    break;
                }
            },
        };

        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let remote_id = conn.remote_id();
        log::info!("Peer connected: {} (awaiting auth)", remote_id);

        let config = config.clone();
        let semaphore = semaphore.clone();
        // Inbound peers authenticate with this process's token, plus (in quick mode) a valid PIN
        // proof against the recent-bucket keys.
        let auth = AuthMode::Listen {
            tokens: std::iter::once(config.auth_token.clone()).collect(),
            pin_cache: pin_cache.clone(),
        };
        connection_tasks.spawn(crate::logging::inherit_source(async move {
            if let Err(e) = handle_connection(conn, config, semaphore, auth).await {
                log::warn!("Connection error for {}: {}", remote_id, e);
            }
        }));
    }

    connection_tasks.shutdown().await;
    endpoint.close().await;
    log::info!("Serve half stopped.");
    Ok(())
}

/// Background guard that aborts the node-id publisher task on drop.
struct PublisherGuard(tokio::task::JoinHandle<()>);

impl Drop for PublisherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Steady-state interval between node-id republishes. Replaceable nostr events can be
/// dropped by relays at varying times, so we refresh periodically while listening. The
/// same loop re-checks for a name conflict each cycle (conflict detection happens only
/// at these nostr touch-points — there is no separate monitor).
const NODE_ID_REPUBLISH_INTERVAL: Duration = Duration::from_secs(300);

/// Interval for the initial conflict-detection burst. Startup deliberately does no
/// nostr lookup (so a sole device's restart, whose own stale relay record carries a
/// different ephemeral node id, is never a false conflict). That means a second device
/// launched against a live name would otherwise go unnoticed until the first 300s
/// republish. To detect it promptly we re-check a few times soon after the initial
/// claim: each re-check publishes first, so it still sees our *own* fresh record when
/// there is no competitor (no false positive) and a foreign newer record when there is.
const STARTUP_RECHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Number of publish cycles that use [`STARTUP_RECHECK_INTERVAL`] before settling into
/// [`NODE_ID_REPUBLISH_INTERVAL`]. Bounds the fast phase to ~1 minute after launch so
/// steady state remains the slow, "no continuous monitoring" cadence.
const STARTUP_RECHECK_CYCLES: u32 = 6;

/// Short prefix of a node id for human-readable conflict messages.
fn short_node_id(id: &str) -> String {
    id.chars().take(12).collect::<String>() + "…"
}

/// Inputs for the node-id publisher task.
struct PublisherParams {
    auth_token: String,
    identifier: String,
    node_id: EndpointId,
    relays: Vec<String>,
    shutdown: CancellationToken,
    state: Arc<AppState>,
    /// Whether a TUI is present to prompt the user (false in headless test mode).
    interactive: bool,
    /// Loaded config path, for the rename nudge. `None` ⇒ rename only logs.
    config_path: Option<PathBuf>,
}

/// What the per-cycle conflict check decided.
enum CheckOutcome {
    /// No conflict — go ahead and (re)publish.
    Publish,
    /// Another device holds the name; carries its node id for the prompt.
    Conflict { other_node_id: String },
}

/// Spawn the node-id publisher: claim/refresh this peer's name on nostr while
/// resolving conflicts with other devices using the same name.
///
/// Detection uses no stored identifier (which could be duplicated by an accidental
/// clone): a mid-session conflict is simply the relay's current node id differing from
/// *our own* ephemeral node id, and a startup conflict is a local flag file left when
/// this device previously lost the name. On a conflict the publisher stops publishing,
/// writes the flag, and (interactively) prompts the user to take over, rename, or
/// decline — quitting at startup or degrading to serve-only mid-session.
fn spawn_node_id_publisher(params: PublisherParams) -> PublisherGuard {
    PublisherGuard(tokio::spawn(crate::logging::inherit_source(
        run_node_id_publisher(params),
    )))
}

async fn run_node_id_publisher(params: PublisherParams) {
    let PublisherParams {
        auth_token,
        identifier,
        node_id,
        relays,
        shutdown,
        state,
        interactive,
        config_path,
    } = params;

    // State/lock files are namespaced by the token fingerprint (matches the lock taken
    // at startup, since the resolved token is validated against the config fingerprint).
    let fingerprint = crate::auth::token_fingerprint(&auth_token);

    let mut commands = state.subscribe_name();
    let mut first = true;
    // Count of completed publishes; the first few cycles re-check quickly (see
    // STARTUP_RECHECK_CYCLES) so a same-name conflict surfaces without waiting a full
    // republish interval.
    let mut publishes: u32 = 0;

    loop {
        // Decide whether this cycle can publish. Startup keys off the local flag (never
        // the relay record, so a fresh node id each run is not a false conflict);
        // subsequent cycles compare the relay's node id against our own.
        let outcome = if first {
            match crate::peer_state::read_flag(&identifier, &fingerprint) {
                Some(flag) => CheckOutcome::Conflict {
                    other_node_id: flag.other_node_id,
                },
                None => CheckOutcome::Publish,
            }
        } else {
            match crate::nostr_discovery::lookup_node_id_opt(&auth_token, &identifier, &relays).await
            {
                // A live competitor overwrote our record with a different node id.
                Ok(Some(id)) if id != node_id => CheckOutcome::Conflict {
                    other_node_id: id.to_string(),
                },
                // Our own record, no record, or a network error: can't prove a
                // conflict, so just (re)publish.
                _ => CheckOutcome::Publish,
            }
        };

        if let CheckOutcome::Conflict { other_node_id } = outcome {
            let at_startup = first;
            // Stop publishing and remember the conflict so it survives a restart.
            if let Err(e) = crate::peer_state::write_flag(&identifier, &fingerprint, &other_node_id)
            {
                log::warn!("Could not write name-conflict flag: {e}");
            }

            if !interactive {
                // No TUI to prompt: degrade to serve-only.
                let msg = format!(
                    "nostr name '{}' is in use by another device ({}); not publishing (serving only).",
                    identifier,
                    short_node_id(&other_node_id)
                );
                log::warn!("{msg}");
                state.set_name_conflict(NameConflict::Degraded { message: msg });
                break;
            }

            state.set_name_conflict(NameConflict::Prompt {
                message: conflict_prompt_message(&identifier, &other_node_id, at_startup),
            });

            // Discard any decisions buffered before this prompt so a stale keypress
            // can't auto-resolve a later conflict.
            while commands.try_recv().is_ok() {}

            let cmd = tokio::select! {
                _ = shutdown.cancelled() => break,
                r = commands.recv() => match r {
                    Ok(c) => c,
                    // Sender dropped: nothing more can decide this; stop publishing.
                    Err(_) => break,
                },
            };

            match cmd {
                NameCommand::TakeOver => {
                    if let Err(e) = crate::peer_state::clear_flag(&identifier, &fingerprint) {
                        log::warn!("Could not clear name-conflict flag: {e}");
                    }
                    state.clear_name_conflict();
                    log::info!("Taking over nostr name '{identifier}'.");
                    // Fall through to publish below.
                }
                NameCommand::Rename => {
                    nudge_rename(&config_path, &identifier);
                    if at_startup {
                        log::warn!(
                            "Name '{identifier}' is in use; quitting (rename it in the config and restart)."
                        );
                        shutdown.cancel();
                        break;
                    }
                    state.set_name_conflict(NameConflict::Degraded {
                        message: degraded_message(&identifier, true),
                    });
                    break;
                }
                NameCommand::Decline => {
                    if at_startup {
                        log::warn!("Name '{identifier}' is in use; quitting.");
                        shutdown.cancel();
                        break;
                    }
                    state.set_name_conflict(NameConflict::Degraded {
                        message: degraded_message(&identifier, false),
                    });
                    break;
                }
            }
        }

        // Publish (claim or refresh) our node id under the name.
        match crate::nostr_discovery::publish_node_id(&auth_token, &identifier, &node_id, &relays)
            .await
        {
            Ok(()) => log::info!("Published node id to nostr for peer discovery"),
            Err(e) => log::warn!("Failed to publish node id to nostr: {e:#}"),
        }
        state.set_name_conflict(NameConflict::Inactive);
        first = false;
        publishes = publishes.saturating_add(1);

        // Re-check quickly for the first few cycles, then settle to the slow cadence.
        let interval = if publishes <= STARTUP_RECHECK_CYCLES {
            STARTUP_RECHECK_INTERVAL
        } else {
            NODE_ID_REPUBLISH_INTERVAL
        };
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Quick PIN mode publisher: mint a fresh PIN each rotation period, publish the
/// `{node_id, token}` record under it, and surface the PIN + rollover deadline to the TUI
/// for the header's refresh countdown. The PIN is set on `AppState` *before* the network publish
/// so the header and connect prompt see it immediately; relay failures are logged but
/// non-fatal (a dialer simply retries on the next code).
async fn run_pin_publisher(
    node_id: EndpointId,
    recent: RecentPins,
    relays: Vec<String>,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) {
    loop {
        let pin = crate::pin::generate_pin();
        let bucket = crate::pin::current_bucket();
        let remaining = crate::pin::secs_until_next_bucket();
        // Show the new code right away (deadline = the bucket boundary it rotates on).
        state.set_current_pin(pin.clone(), Instant::now() + Duration::from_secs(remaining));

        // Record this bucket's PIN auth key so an inbound dialer holding this PIN can be
        // authenticated in-band, even after the code rotates (the cache retains recent buckets).
        match crate::pin_auth::derive_auth_keys(&pin) {
            Ok(keys) => recent.push(keys),
            Err(e) => log::warn!("Failed to derive PIN auth key: {e:#}"),
        }

        match crate::nostr_discovery::publish_pin_record(&pin, bucket, &node_id, &relays).await {
            Ok(()) => log::info!("Published rotating PIN to nostr (refreshes in {remaining}s)"),
            Err(e) => log::warn!("Failed to publish PIN to nostr: {e:#}"),
        }

        // Sleep to the next bucket boundary, then rotate. `max(1)` avoids a busy spin if we
        // happen to land exactly on the boundary.
        let sleep_for = Duration::from_secs(crate::pin::secs_until_next_bucket().max(1));
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(sleep_for) => {}
        }
    }
}

/// Build the conflict-prompt body shown in the TUI, including the consequence of each
/// choice (which differs at startup vs mid-session).
fn conflict_prompt_message(identifier: &str, other_node_id: &str, at_startup: bool) -> String {
    let decline = if at_startup {
        "quit"
    } else {
        "serve only (stop publishing this name)"
    };
    let take = if at_startup { "take over" } else { "reclaim" };
    let when = if at_startup {
        "was claimed by another device (it may have taken over while this peer was down)"
    } else {
        "was just taken over by another device"
    };
    format!(
        "Name '{identifier}' {when}.\nOther node id: {other}\n\n\
         [t] {take} the name (publish and gain precedence)\n\
         [r] rename: note the conflict in the config, then {decline}\n\
         [n] decline: {decline}",
        other = short_node_id(other_node_id),
    )
}

/// Persistent degraded-mode warning shown in the header after declining/renaming.
fn degraded_message(identifier: &str, renamed: bool) -> String {
    let tail = if renamed {
        "see the rename note added to your config"
    } else {
        "restart to reclaim or rename"
    };
    format!("name '{identifier}' taken over by another device — serving only (not published); {tail}.")
}

/// Append the non-destructive rename nudge to the config file, if we know its path.
fn nudge_rename(config_path: &Option<PathBuf>, identifier: &str) {
    match config_path {
        Some(path) => match crate::config::append_name_conflict_comment(path, identifier) {
            Ok(()) => log::info!("Added a rename note to {}.", path.display()),
            Err(e) => log::warn!("Could not add a rename note to the config: {e:#}"),
        },
        None => log::warn!("No config file to annotate; rename '{identifier}' manually."),
    }
}

// ============================================================================
// Dial half (on-demand, one outbound session) — also the headless `Role::Dial`
// test path
// ============================================================================

async fn run_dial(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    if config.peer_node_id.is_none() && config.nostr_identifier.is_none() {
        anyhow::bail!(
            "dialing requires a peer node id (quick mode) or a peer identifier (config mode)"
        );
    }

    log::info!("duopipe dial half — connecting to peer");
    log::info!("======================================");

    let endpoint = create_client_endpoint(
        &config.relay_urls,
        config.relay_only,
        config.dns_server.as_deref(),
        Some(&config.transport),
    )
    .await?;

    let own_id = endpoint.id();
    if config.report_endpoint_id {
        config.status.set_endpoint_id(own_id.to_string());
    }

    let shutdown = config.status.shutdown.clone();
    let config = Arc::new(config);
    // The peer's node id: either supplied directly (manual entry / test fast-path)
    // or discovered via nostr. When discovered it is re-resolved on each connect
    // attempt so a listener that restarted with a fresh ephemeral id self-heals.
    let peer_id: Option<EndpointId> = config.peer_node_id;
    let mut backoff = Duration::from_secs(1);
    // Until the first connection is fully established and served, cap retries (see
    // `MAX_INITIAL_CONNECT_ATTEMPTS`). Once we have served a real session at least
    // once, reconnect without limit so a transient outage doesn't kill a working
    // peer relationship.
    let mut established = false;
    let mut attempts: u32 = 0;

    loop {
        config.status.set_conn_status(ConnStatus::Connecting);

        // Resolve the target node id. If one was supplied directly (quick mode), use
        // it as-is. Otherwise look it up on nostr by the target's identifier —
        // re-resolving every attempt means a listener that restarted with a fresh
        // ephemeral id (same identifier) is picked up here.
        let target: Result<EndpointId> = match peer_id {
            Some(id) => Ok(id),
            None => {
                // Guaranteed Some: run_dial bails earlier unless a node id or
                // identifier is set, and peer_id is None here.
                let identifier = config
                    .nostr_identifier
                    .as_deref()
                    .expect("dial without a node id requires a nostr identifier");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    r = crate::nostr_discovery::lookup_node_id(
                        &config.auth_token,
                        identifier,
                        &config.nostr_relays,
                    ) => match r {
                        Ok(id) => {
                            log::info!("Discovered peer '{identifier}' node id via nostr: {id}");
                            Ok(id)
                        }
                        Err(e) => Err(e.context("nostr node-id lookup failed")),
                    },
                }
            }
        };

        // Refuse to dial ourselves: a quick-mode node id pasted by mistake, or a
        // nostr identifier that maps back to this peer. Fatal — the target won't
        // change without reconfiguring, so retrying can't help.
        if let Ok(id) = &target
            && *id == own_id
        {
            anyhow::bail!(
                "Refusing to dial this peer's own node id ({own_id}). Set a different target node id (quick mode) or peer identifier (config mode)."
            );
        }

        let connect = match target {
            Ok(id) => {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    connect = connect_to_server(
                        &endpoint,
                        id,
                        &config.relay_urls,
                        config.relay_only,
                        ALPN,
                    ) => connect,
                }
            }
            Err(e) => Err(e),
        };

        match connect {
            Ok(conn) => {
                config.status.set_conn_status(ConnStatus::Connected);
                log::info!("Connected to peer!");
                let auth = AuthMode::DialToken(config.auth_token.clone());
                match handle_connection(conn, config.clone(), semaphore.clone(), auth).await {
                    Ok(()) => {
                        // A real session was served; reset the initial-connect cap so a
                        // later transient outage doesn't count against startup.
                        established = true;
                        attempts = 0;
                        backoff = Duration::from_secs(1);
                        log::info!("Connection closed; will reconnect");
                    }
                    Err(e) => {
                        // Auth failures (bad token) are fatal — reconnecting can't
                        // succeed because a bad token stays bad.
                        if e.downcast_ref::<TunnelError>()
                            .is_some_and(|te| matches!(te.category, ErrorCategory::Auth))
                        {
                            endpoint.close().await;
                            return Err(e);
                        }
                        log::warn!("Connection ended: {}", e);
                    }
                }
            }
            Err(e) => log::warn!("Failed to connect to peer: {}", e),
        }

        // Bound the initial-connection phase. After the first established session
        // this never trips (attempts is reset to 0 above).
        if !established {
            attempts += 1;
            if attempts >= MAX_INITIAL_CONNECT_ATTEMPTS {
                endpoint.close().await;
                return Err(TunnelError::connection(anyhow::anyhow!(
                    "could not establish a connection after {MAX_INITIAL_CONNECT_ATTEMPTS} \
                     attempts; the peer may be unreachable, or another process may be using \
                     this node id"
                ))
                .into());
            }
        }

        config.status.set_conn_status(ConnStatus::Reconnecting {
            backoff_secs: backoff.as_secs(),
        });
        log::info!("Reconnecting in {:?}...", backoff);
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
    }

    endpoint.close().await;
    Ok(())
}

// ============================================================================
// Connection handling (symmetric)
// ============================================================================

/// Handle one established connection. Returns `Ok(true)` when a real session was
/// served, `Ok(false)` when the connection was rejected as transiently busy (the
/// dialer should retry but not treat it as established). Fatal conditions (auth
/// failure, wrong-peer rejection) return `Err`.
async fn handle_connection(
    conn: iroh::endpoint::Connection,
    config: Arc<PeerConfig>,
    semaphore: Arc<Semaphore>,
    auth: AuthMode,
) -> Result<()> {
    let remote_id = conn.remote_id();
    let is_dialer = matches!(auth, AuthMode::DialToken(_) | AuthMode::DialPin(_));

    // Phase 1: authenticate. The listener serves any number of peers concurrently,
    // so there is no session binding — authentication is the only gate.
    match &auth {
        AuthMode::DialToken(token) => {
            config.status.set_conn_status(ConnStatus::Authenticating);
            auth_as_dialer(&conn, token).await?;
            config.status.set_conn_status(ConnStatus::Connected);
        }
        AuthMode::DialPin(pin) => {
            config.status.set_conn_status(ConnStatus::Authenticating);
            auth_as_dialer_pin(&conn, pin).await?;
            config.status.set_conn_status(ConnStatus::Connected);
        }
        AuthMode::Listen { tokens, pin_cache } => {
            auth_as_listener(&conn, tokens, pin_cache.as_ref()).await?;
            config.status.add_peer(remote_id.to_string());
            log::info!("Peer {remote_id} authenticated");
        }
    }

    let _path_watcher =
        watch_connection_paths(&conn, config.status.clone(), remote_id.to_string(), is_dialer);

    let conn = Arc::new(conn);

    let mut tasks: JoinSet<()> = JoinSet::new();

    // Acceptor side (both roles): accept incoming tunnel requests from the peer and
    // connect out (the peer is trusted once auth passed — no source allowlist).
    // Streams are capped by the global semaphore shared across all peers.
    {
        let conn = conn.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(crate::logging::inherit_source(async move {
            if let Err(e) = accept_loop(conn, semaphore).await {
                log::debug!("Accept loop ended: {}", e);
            }
        }));
    }

    // Requester side (dialing side only): a dialer drives a single connection, so it
    // owns the tunnel table and supervises start/stop of its own tunnels. The serve
    // half handles many peers at once and initiates no tunnels — there is no single
    // connection a tunnel could be bound to — so it only runs the acceptor above.
    if is_dialer {
        config.status.reset_tunnel_status();
        // Subscribe before spawning so an autostart burst cannot race the subscription.
        let command_rx = config.status.subscribe_commands();
        {
            let conn = conn.clone();
            let semaphore = semaphore.clone();
            let status = config.status.clone();
            tasks.spawn(crate::logging::inherit_source(async move {
                tunnel_supervisor(conn, semaphore, status, command_rx).await;
            }));
        }
        // Optionally autostart the configured tunnel (non-interactive/test mode).
        if config.autostart_tunnels && config.status.has_tunnel() {
            config.status.send_command(TunnelCommand::Start);
        }
    }

    // Run until the connection closes or a local shutdown is requested, then tear
    // everything down. Observing `shutdown` here is essential for the dialing side:
    // `run_dial` awaits this function inline (not in an abortable task), so without
    // this branch a Ctrl-C while connected would block forever on `conn.closed()`
    // (keep-alive prevents the idle timeout from ever firing).
    let reason = tokio::select! {
        reason = conn.closed() => reason,
        _ = config.status.shutdown.cancelled() => {
            conn.close(SHUTDOWN_CODE.into(), b"shutdown");
            ConnectionError::LocallyClosed
        }
    };
    log::info!("Connection to {} closed: {}", remote_id, reason);
    if is_dialer {
        config.status.set_conn_status(ConnStatus::Closed);
    } else {
        config.status.remove_peer(&remote_id.to_string());
    }
    tasks.shutdown().await;
    Ok(())
}

/// Supervise this peer's single tunnel over one connection. Listens for
/// [`TunnelCommand`]s and starts/stops the tunnel, tracking a cancellation token
/// while it runs so a `Stop` (or the connection closing) frees the bound local
/// port. The tunnel spec is read live from [`AppState`] so a runtime change is
/// visible without restarting the supervisor.
async fn tunnel_supervisor(
    conn: Arc<iroh::endpoint::Connection>,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
    mut command_rx: broadcast::Receiver<TunnelCommand>,
) {
    let mut running: Option<CancellationToken> = None;
    // The task signals here when it ends on its own (error/EOF), so the supervisor
    // can drop the stale token and allow a restart.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();

    loop {
        tokio::select! {
            cmd = command_rx.recv() => match cmd {
                Ok(TunnelCommand::Start) => {
                    if running.is_some() {
                        continue; // already running
                    }
                    let Some(req) = status.tunnel() else { continue };
                    let token = CancellationToken::new();
                    running = Some(token.clone());

                    let conn = conn.clone();
                    let semaphore = semaphore.clone();
                    let status = status.clone();
                    let done_tx = done_tx.clone();
                    tokio::spawn(crate::logging::inherit_source(async move {
                        let outcome = tokio::select! {
                            r = run_tunnel(conn.clone(), req, semaphore, status.clone()) => Some(r),
                            _ = token.cancelled() => None,
                            // Tie the listener's lifetime to the connection so it
                            // never outlives it (which would leak the bound port).
                            _ = conn.closed() => None,
                        };
                        match outcome {
                            Some(Err(e)) => {
                                status.update_tunnel(TunnelStatus::Error, e.to_string());
                                log::warn!("Tunnel ended: {}", e);
                            }
                            // Stopped, connection closed, or the listen loop ended cleanly.
                            Some(Ok(())) | None => {
                                status.update_tunnel(TunnelStatus::Idle, String::new());
                            }
                        }
                        let _ = done_tx.send(());
                    }));
                }
                Ok(TunnelCommand::Stop) => {
                    if let Some(token) = running.take() {
                        token.cancel();
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("Tunnel command channel lagged by {n}");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            Some(()) = done_rx.recv() => {
                running = None;
            }
        }
    }
}

// ============================================================================
// Authentication
// ============================================================================

/// Authenticate as the dialer.
async fn auth_as_dialer(conn: &iroh::endpoint::Connection, auth_token: &str) -> Result<()> {
    let (mut send, mut recv) = open_bi_with_retry(conn).await?;

    let request = AuthRequest::new(auth_token);
    send.write_all(&encode_auth_request(&request)?).await?;
    send.finish()?;

    let response_bytes = tokio::time::timeout(AUTH_TIMEOUT, read_length_prefixed(&mut recv))
        .await
        .map_err(|_| TunnelError::auth(anyhow::anyhow!("Auth response timed out")))?
        .context("Failed to read auth response")?;
    let response = decode_auth_response(&response_bytes).context("Invalid auth response")?;

    if !response.accepted {
        let reason = response.reason.unwrap_or_else(|| "Unknown".to_string());
        return Err(
            TunnelError::auth(anyhow::anyhow!("Authentication rejected: {}", reason)).into(),
        );
    }

    log::info!("Authenticated with peer successfully");
    Ok(())
}

/// Authenticate as the dialer using the quick-mode PIN (in-band challenge-response). No token
/// crosses the wire. The whole exchange is bounded by [`AUTH_TIMEOUT`] and any failure is an
/// [`ErrorCategory::Auth`] error — fatal for this target, exactly like a wrong token.
async fn auth_as_dialer_pin(conn: &iroh::endpoint::Connection, pin: &str) -> Result<()> {
    let (mut send, mut recv) = open_bi_with_retry(conn).await?;
    match tokio::time::timeout(
        AUTH_TIMEOUT,
        crate::pin_auth::dialer_handshake(&mut send, &mut recv, pin),
    )
    .await
    {
        Err(_) => return Err(TunnelError::auth(anyhow::anyhow!("PIN auth timed out")).into()),
        Ok(Err(e)) => return Err(TunnelError::auth(e).into()),
        Ok(Ok(())) => {}
    }
    let _ = send.finish();
    log::info!("Authenticated with peer via PIN");
    Ok(())
}

/// Authenticate as the listener. Accepts either a pre-shared token or (quick mode) a PIN proof;
/// `pin_cache` holds the recent-bucket PIN keys and is `None` outside quick mode.
async fn auth_as_listener(
    conn: &iroh::endpoint::Connection,
    auth_tokens: &HashSet<String>,
    pin_cache: Option<&RecentPins>,
) -> Result<()> {
    let remote_id = conn.remote_id();

    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("Failed to accept auth stream")?;

        let request_bytes = read_length_prefixed(&mut recv)
            .await
            .context("Failed to read auth request")?;
        match decode_auth_request(&request_bytes).context("Invalid auth request")? {
            AuthRequest::Token { auth_token, .. } => {
                if !is_token_valid(auth_token.as_str(), auth_tokens) {
                    log::warn!("Invalid auth token from {}", remote_id);
                    let response = AuthResponse::rejected("Invalid authentication token");
                    send.write_all(&encode_auth_response(&response)?).await?;
                    send.finish()?;
                    anyhow::bail!("Invalid auth token");
                }
                let response = AuthResponse::accepted();
                send.write_all(&encode_auth_response(&response)?).await?;
                send.finish()?;
                Ok::<_, anyhow::Error>(())
            }
            AuthRequest::Pin { nonce, .. } => {
                // Verify the dialer's PIN proof against the recent-bucket keys. An empty candidate
                // set (this listener isn't in quick mode) yields a clean rejection.
                let candidates = pin_cache.map(|c| c.snapshot()).unwrap_or_default();
                crate::pin_auth::listener_handshake(&mut send, &mut recv, &candidates, &nonce)
                    .await?;
                let _ = send.finish();
                log::info!("Peer {remote_id} authenticated via PIN");
                Ok(())
            }
        }
    })
    .await;

    match auth_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            conn.close(AUTH_FAILED_CODE.into(), b"auth_failed");
            Err(TunnelError::auth(anyhow::anyhow!("auth_failed: {}", e)).into())
        }
        Err(_) => {
            log::warn!("Authentication timeout for {}", remote_id);
            conn.close(AUTH_TIMEOUT_CODE.into(), b"auth_timeout");
            Err(TunnelError::auth(anyhow::anyhow!("auth_timeout")).into())
        }
    }
}

// ============================================================================
// Accept loop (acceptor / connect side)
// ============================================================================

async fn accept_loop(
    conn: Arc<iroh::endpoint::Connection>,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let mut stream_tasks: JoinSet<()> = JoinSet::new();

    loop {
        let (send, recv) = conn
            .accept_bi()
            .await
            .context("accept_bi failed (connection closed)")?;

        let semaphore = semaphore.clone();
        stream_tasks.spawn(crate::logging::inherit_source(async move {
            if let Err(e) = handle_incoming_stream(send, recv, semaphore).await {
                log::warn!("Stream error: {}", e);
            }
        }));

        while stream_tasks.try_join_next().is_some() {}
    }
}

async fn handle_incoming_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let hello_bytes = tokio::time::timeout(HELLO_TIMEOUT, read_length_prefixed(&mut recv))
        .await
        .context("Timed out reading stream hello")?
        .context("Failed to read stream hello")?;
    let hello = decode_stream_hello(&hello_bytes).context("Invalid stream hello")?;

    match hello {
        StreamHello::LocalForward { source, .. } => {
            // The peer is trusted once auth passed, so we connect out to whatever
            // source it requests — no allowlist check. Streams are still capped by
            // the global session permit.
            let Some(permit) = acquire_or_reject(&semaphore, &mut send).await? else {
                return Ok(());
            };
            let _permit = permit;
            connect_side(send, recv, &source).await
        }
    }
}

/// Try to acquire a session permit; on exhaustion, send a rejection ack and return None.
async fn acquire_or_reject(
    semaphore: &Arc<Semaphore>,
    send: &mut iroh::endpoint::SendStream,
) -> Result<Option<OwnedSemaphorePermit>> {
    match semaphore.clone().try_acquire_owned() {
        Ok(permit) => Ok(Some(permit)),
        Err(_) => {
            log::warn!("Session limit reached, rejecting stream");
            let ack = StreamAck::rejected("Session limit reached");
            let _ = send.write_all(&encode_stream_ack(&ack)?).await;
            let _ = send.finish();
            Ok(None)
        }
    }
}

/// Connect out over TCP to `dest` (a bare `host:port`) and bridge it with the
/// stream (acceptor / connect side).
async fn connect_side(
    mut send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    dest: &str,
) -> Result<()> {
    let target_addrs = resolve_all_target_addrs(dest).await?;
    match try_connect_tcp(&target_addrs).await {
        Ok(tcp_stream) => {
            send.write_all(&encode_stream_ack(&StreamAck::accepted())?)
                .await?;
            log::info!("-> Connected to TCP {}", dest);
            bridge_streams(recv, send, tcp_stream).await?;
            log::info!("<- TCP connection to {} closed", dest);
        }
        Err(e) => {
            let ack = StreamAck::rejected(format!("connect failed: {}", e));
            send.write_all(&encode_stream_ack(&ack)?).await?;
            let _ = send.finish();
            anyhow::bail!("Failed to connect to TCP {}: {}", dest, e);
        }
    }

    Ok(())
}

// ============================================================================
// Tunnel requests: opener / listen side
// ============================================================================

/// Run one tunnel: bind the local `local_listen` address and, for each
/// incoming connection, open a stream asking the peer to connect out to
/// `remote_source`. Runs until the listener errors or the caller cancels it
/// (freeing the bound port).
async fn run_tunnel(
    conn: Arc<iroh::endpoint::Connection>,
    req: TunnelEntry,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
) -> Result<()> {
    let hello = StreamHello::local_forward(&req.remote_source);
    let listen_addrs = resolve_listen_addrs(&req.local_listen)
        .await
        .with_context(|| format!("Invalid tunnel listen address '{}'", req.local_listen))?;

    let listeners = bind_tcp_listeners(&listen_addrs, &req.remote_source).await?;
    status.update_tunnel(TunnelStatus::Listening, req.local_listen.clone());
    tcp_accept_and_tunnel(conn, listeners, hello, semaphore).await
}

// ============================================================================
// Shared listen-side helpers
// ============================================================================

async fn bind_tcp_listeners(listen_addrs: &[SocketAddr], label: &str) -> Result<Vec<TcpListener>> {
    let mut listeners = Vec::with_capacity(listen_addrs.len());
    for addr in listen_addrs {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                log::info!("Listening on TCP {} -> {}", addr, label);
                listeners.push(listener);
            }
            Err(e) => log::warn!("Failed to bind TCP listener on {}: {}", addr, e),
        }
    }
    if listeners.is_empty() {
        anyhow::bail!("Failed to bind any TCP listener for {}", label);
    }
    Ok(listeners)
}

/// Accept TCP connections from the given listeners; per connection open a data
/// stream (tagged with `hello`) and bridge it.
async fn tcp_accept_and_tunnel(
    conn: Arc<iroh::endpoint::Connection>,
    listeners: Vec<TcpListener>,
    hello: StreamHello,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::channel::<(TcpStream, SocketAddr)>(32);
    let mut accept_tasks: JoinSet<()> = JoinSet::new();
    for listener in listeners {
        let tx = tx.clone();
        accept_tasks.spawn(crate::logging::inherit_source(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        tune_tcp_stream(&stream);
                        if tx.send((stream, peer)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => log::warn!("Failed to accept TCP connection: {}", e),
                }
            }
        }));
    }
    drop(tx);

    let mut conn_tasks: JoinSet<()> = JoinSet::new();
    while let Some((tcp_stream, peer)) = rx.recv().await {
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                log::warn!("Session limit reached, dropping connection from {}", peer);
                continue;
            }
        };
        let conn = conn.clone();
        let hello = hello.clone();
        conn_tasks.spawn(crate::logging::inherit_source(async move {
            let _permit = permit;
            if let Err(e) = open_tcp_data_stream(&conn, hello, tcp_stream).await {
                log::warn!("Tunnel for {} failed: {}", peer, e);
            }
        }));
        while conn_tasks.try_join_next().is_some() {}
    }

    accept_tasks.shutdown().await;
    conn_tasks.shutdown().await;
    Ok(())
}

/// Open a data stream, send the hello, await the ack, then bridge the TCP stream.
async fn open_tcp_data_stream(
    conn: &iroh::endpoint::Connection,
    hello: StreamHello,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (mut send, mut recv) = open_bi_with_retry(conn).await?;
    send.write_all(&encode_stream_hello(&hello)?).await?;
    expect_ack(&mut recv).await?;
    bridge_streams(recv, send, tcp_stream).await
}

/// Read a [`StreamAck`] from the stream and fail if it was rejected.
async fn expect_ack(recv: &mut iroh::endpoint::RecvStream) -> Result<()> {
    let ack_bytes = tokio::time::timeout(ACK_TIMEOUT, read_length_prefixed(recv))
        .await
        .context("Timed out waiting for stream ack")?
        .context("Failed to read stream ack")?;
    let ack = decode_stream_ack(&ack_bytes).context("Invalid stream ack")?;
    if !ack.accepted {
        anyhow::bail!(
            "Peer rejected stream: {}",
            ack.reason.as_deref().unwrap_or("Unknown")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iroh_mode::endpoint::create_endpoint_builder;
    use crate::logging::LogBuffer;
    use iroh::Endpoint;
    use iroh::endpoint::RelayMode;

    fn test_semaphore() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(DEFAULT_MAX_STREAMS))
    }

    fn test_peer_config(role: Role, token: &str) -> Arc<PeerConfig> {
        let status = AppState::new(role, false, LogBuffer::new(16), None, false, None, false);
        Arc::new(PeerConfig {
            role,
            peer_node_id: None,
            autostart_tunnels: false,
            auth_token: token.to_string(),
            nostr_relays: vec![],
            nostr_discovery: false,
            nostr_identifier: None,
            pin_rendezvous: false,
            report_endpoint_id: true,
            relay_urls: vec![],
            relay_only: false,
            dns_server: Some("none".to_string()),
            max_streams: None,
            transport: TransportTuning::default(),
            announce_endpoint: false,
            config_path: None,
            status,
        })
    }

    /// `split_serve_dial_config` keeps the own name on the listen half (which owns the
    /// reported node id and is started on-demand via Shift+L), gives the dial half no
    /// fixed target, and shares one `AppState`.
    #[test]
    fn split_serve_dial_config_shapes_both_halves() {
        let status = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            None,
            true,
            Some("homelab".to_string()),
            false,
        );
        let both = PeerConfig {
            role: Role::Both,
            peer_node_id: None,
            autostart_tunnels: true,
            auth_token: "tok".to_string(),
            nostr_relays: vec![],
            nostr_discovery: true,
            nostr_identifier: Some("homelab".to_string()),
            pin_rendezvous: false,
            report_endpoint_id: true,
            relay_urls: vec![],
            relay_only: false,
            dns_server: Some("none".to_string()),
            max_streams: None,
            transport: TransportTuning::default(),
            announce_endpoint: false,
            config_path: None,
            status,
        };

        let (listen, dial) = split_serve_dial_config(&both);

        assert_eq!(listen.role, Role::Listen);
        assert_eq!(dial.role, Role::Dial);

        // Listen publishes under its own name and owns the reported node id.
        assert_eq!(listen.nostr_identifier.as_deref(), Some("homelab"));
        assert!(listen.report_endpoint_id);
        assert!(!listen.autostart_tunnels);

        // The dial half carries no fixed target (it dials runtime requests) and its
        // endpoint id is internal.
        assert_eq!(dial.peer_node_id, None);
        assert_eq!(dial.nostr_identifier, None);
        assert!(!dial.report_endpoint_id);

        // Both halves share the one AppState.
        assert!(Arc::ptr_eq(&both.status, &listen.status));
        assert!(Arc::ptr_eq(&both.status, &dial.status));
    }

    /// Dial commands round-trip through the broadcast channel and `set_dial_target`
    /// surfaces in the snapshot.
    #[test]
    fn dial_command_roundtrip_and_target_in_snapshot() {
        let status = AppState::new(Role::Both, false, LogBuffer::new(16), None, true, None, false);
        let mut rx = status.subscribe_dial();
        status.set_dial_target(Some("laptop".to_string()));
        assert_eq!(status.snapshot().dial_target.as_deref(), Some("laptop"));

        status.send_dial(DialCommand::Connect(DialTarget::Name("laptop".to_string())));
        match rx.try_recv() {
            Ok(DialCommand::Connect(DialTarget::Name(n))) => assert_eq!(n, "laptop"),
            other => panic!("expected Connect(Name), got {other:?}"),
        }

        status.send_dial(DialCommand::Disconnect);
        assert!(matches!(rx.try_recv(), Ok(DialCommand::Disconnect)));

        status.set_dial_target(None);
        assert_eq!(status.snapshot().dial_target, None);
    }

    async fn hermetic_endpoint() -> Endpoint {
        // Relay disabled + DNS off: a fully local, direct-only endpoint. The shared
        // transport config still applies keep-alive (15s) and a 300s idle timeout,
        // so a connection between two of these stays alive for the whole test.
        create_endpoint_builder(RelayMode::Disabled, false, Some("none"), None)
            .expect("endpoint builder")
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("bind endpoint")
    }

    /// Regression test: a dialer parked on an established connection must return
    /// promptly when the shutdown token is cancelled. `run_dial` awaits
    /// `handle_connection` inline (not in an abortable task), so before the fix a
    /// Ctrl-C while connected blocked forever on `conn.closed()` — keep-alive keeps
    /// the connection up, so the idle timeout never rescues it.
    #[tokio::test]
    async fn dial_handle_connection_returns_on_shutdown() {
        let token = "shutdown-test-token";
        let server_ep = hermetic_endpoint().await;
        let client_ep = hermetic_endpoint().await;

        // Wait until the server publishes a direct address we can dial.
        let server_addr = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let addr = server_ep.addr();
                if addr.ip_addrs().next().is_some() {
                    break addr;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("server direct address ready");

        // Listener side: run the real handler so the dialer's auth completes and it
        // reaches the post-auth connection wait (the path under test).
        let server_cfg = test_peer_config(Role::Listen, token);
        let server_ep2 = server_ep.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server_ep2.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("accept connection");
            let auth = AuthMode::Listen {
                tokens: std::iter::once(token.to_string()).collect(),
                pin_cache: None,
            };
            let _ = handle_connection(conn, server_cfg, test_semaphore(), auth).await;
        });

        // Dialer side: the system under test.
        let client_conn = client_ep
            .connect(server_addr, ALPN)
            .await
            .expect("dial connect");
        let client_cfg = test_peer_config(Role::Dial, token);
        let client_status = client_cfg.status.clone();
        let auth = AuthMode::DialToken(token.to_string());
        let client_task =
            tokio::spawn(handle_connection(client_conn, client_cfg, test_semaphore(), auth));

        // Wait until the dialer has authenticated (parked on the connection).
        tokio::time::timeout(Duration::from_secs(10), async {
            while client_status.snapshot().conn_status != ConnStatus::Connected {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("dialer authenticated");

        // Cancel shutdown; the fix must unblock the connection wait.
        client_status.shutdown.cancel();

        let joined = tokio::time::timeout(Duration::from_secs(5), client_task)
            .await
            .expect("dialer hung after shutdown cancel");
        assert!(joined.is_ok(), "dialer task panicked");
        assert!(
            joined.unwrap().is_ok(),
            "handle_connection should return Ok on shutdown"
        );

        server_task.abort();
        client_ep.close().await;
        server_ep.close().await;
    }

    /// Drive a dialer's `handle_connection` against a listener that authenticates
    /// it and then closes the connection with `close_code`. Returns the dialer's
    /// `handle_connection` result. Synchronizes on the dialer reaching `Connected`
    /// (auth complete) before the listener closes, so the dialer reliably observes
    /// the application close code rather than a torn-down auth stream.
    async fn dial_against_closing_listener(close_code: u32) -> Result<()> {
        let token = "close-code-test-token";
        let server_ep = hermetic_endpoint().await;
        let client_ep = hermetic_endpoint().await;

        let server_addr = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let addr = server_ep.addr();
                if addr.ip_addrs().next().is_some() {
                    break addr;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("server direct address ready");

        let client_cfg = test_peer_config(Role::Dial, token);
        let client_status = client_cfg.status.clone();

        // Listener: authenticate the dialer, wait until it has parked on the
        // connection (Connected), then close with the code under test. Closing only
        // after the dialer authenticates avoids racing the auth stream teardown.
        // Spawned before the dial so the accept is ready to complete the handshake.
        let server_ep2 = server_ep.clone();
        let listener_view = client_status.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server_ep2.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("accept connection");
            let accepted: HashSet<String> = std::iter::once(token.to_string()).collect();
            auth_as_listener(&conn, &accepted, None)
                .await
                .expect("listener auth");
            tokio::time::timeout(Duration::from_secs(10), async {
                while listener_view.snapshot().conn_status != ConnStatus::Connected {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("dialer authenticated");
            conn.close(close_code.into(), b"test_close");
            // Keep the connection alive until the close frame is flushed.
            conn.closed().await;
        });

        let client_conn = client_ep
            .connect(server_addr, ALPN)
            .await
            .expect("dial connect");
        let auth = AuthMode::DialToken(token.to_string());
        let result = handle_connection(client_conn, client_cfg, test_semaphore(), auth).await;

        server_task.abort();
        client_ep.close().await;
        server_ep.close().await;
        result
    }

    /// A listener simply closing the connection ends the dialer's session cleanly
    /// (`Ok(())`); there are no longer any session-rejection close codes, so the
    /// dialer treats it as an established session and `run_dial` reconnects.
    #[tokio::test]
    async fn dial_returns_ok_when_listener_closes() {
        let result = dial_against_closing_listener(SHUTDOWN_CODE).await;
        assert!(
            result.is_ok(),
            "a plain listener close must return Ok(()), got {result:?}"
        );
    }
}
