//! iroh peer runtime: on-demand serving plus on-demand dial sessions.
//!
//! Interactive peers run as `Role::Both`: a `Role::Listen` half that serves an inbound
//! peer (started on-demand via Shift+L; idle until then), plus a dial manager that
//! owns at most one outbound `Role::Dial` session. A run holds ONE pairing: listening
//! and dialing are mutually exclusive (see `AppState::can_dial`/`can_listen`), enforced
//! in both supervisors as well as the TUI.
//!
//! Once paired, the proxy is **symmetric**: each side can bind a loopback-only SOCKS5
//! proxy whose CONNECTs open one QUIC stream per connection, tagged
//! [`StreamHello::SocksConnect`], and the *other* side connects out over TCP to that
//! `host:port` on its own network (domains resolve remotely), bridging the two. The
//! proxy is activated on demand (the TUI sends start/stop commands); nothing starts
//! automatically unless `DUOPIPE_AUTOSTART_SOCKS` is set (test mode only).
//!
//! Every non-auth stream begins with a [`StreamHello`] so the acceptor can route
//! it without positional assumptions. Trust model: once token auth passes, the
//! peer is fully trusted — the acceptor connects out to any `host:port` it
//! requests (there is no destination allowlist).

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
    NameConflict, Role, SocksCommand, SocksStatus,
};
use crate::auth::is_token_valid;
use crate::config::TransportTuning;
use crate::error::{ErrorCategory, TunnelError};
use crate::net::{order_by_loopback_preference, try_connect_tcp, tune_tcp_stream};
use crate::socks5;
use tokio::net::lookup_host;

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

/// The single peer a serve endpoint is paired with, for the lifetime of one listen session
/// (one Shift+L Start→Stop, or the whole process in headless `Role::Listen`). duopipe links a
/// single user's own devices **one pair at a time** by design: once a dialer authenticates, its
/// (QUIC/TLS-authenticated) node id claims the endpoint and any other node id is refused until the
/// user stops listening. The claim is intentionally *not* released when the paired peer
/// disconnects, so that peer — and only that peer — can reconnect without re-authenticating (in
/// quick PIN mode, without re-typing a PIN that may since have rotated). A fresh listen session
/// mints a new endpoint id and a new (empty) claim.
#[derive(Clone, Default)]
struct PairClaim(Arc<parking_lot::Mutex<Option<ClaimedPeer>>>);

/// The peer that holds a [`PairClaim`], plus the material needed to let it reconnect.
#[derive(Clone)]
struct ClaimedPeer {
    /// The paired dialer's node id (its public key; authenticated by the iroh/QUIC handshake).
    node_id: EndpointId,
    /// The PIN auth key that verified this peer at pairing (quick PIN mode only). Retained so the
    /// paired peer can complete the in-band challenge-response on reconnect even after its PIN has
    /// rotated out of the listener's recent-bucket cache. `None` for token-authenticated pairings.
    pin_key: Option<nostr_sdk::Keys>,
}

impl PairClaim {
    /// Snapshot the current claim (cheap clone) for the pre-auth gate.
    fn peek(&self) -> Option<ClaimedPeer> {
        self.0.lock().clone()
    }

    /// Commit a freshly authenticated peer as the pair. Returns `true` if `node_id` now holds the
    /// claim — either because it was unclaimed and we just took it, or because this same peer
    /// already held it (a reconnect/retry). Returns `false` if another node id won the claim first
    /// (a race between two first-time dialers), in which case the caller must reject this peer.
    fn commit(&self, node_id: EndpointId, pin_key: Option<nostr_sdk::Keys>) -> bool {
        let mut g = self.0.lock();
        match g.as_ref() {
            Some(c) if c.node_id != node_id => false,
            Some(_) => true,
            None => {
                *g = Some(ClaimedPeer { node_id, pin_key });
                true
            }
        }
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
    /// accept a valid PIN proof against the retained recent-bucket keys. `claim` enforces the
    /// one-pair-at-a-time rule: the first peer to authenticate claims the endpoint and all other
    /// node ids are refused until the listen session ends.
    Listen {
        tokens: HashSet<String>,
        pin_cache: Option<RecentPins>,
        claim: PairClaim,
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
    /// When true, start the configured SOCKS5 proxy as soon as a connection is up
    /// (set from `DUOPIPE_AUTOSTART_SOCKS` in test mode; see `DUOPIPE_TEST_MODE`).
    pub autostart_socks: bool,
    /// The shared auth token (presented when dialing, accepted when listening), and the
    /// rendezvous secret for nostr node-id discovery. `None` in quick **PIN** mode, which uses
    /// no token — the PIN authenticates the connection in-band and the listener accepts only PIN
    /// proofs. **Sensitive - redacted in Debug.**
    pub auth_token: Option<String>,
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
    /// Maximum concurrent proxied streams (None = default).
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
            .field("autostart_socks", &self.autostart_socks)
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
                    // One-pairing rule: refuse to dial while this run is the listening side of a
                    // pairing. The TUI hides Shift+C in that state; this guards test-mode/races.
                    if !config.status.can_dial() {
                        log::warn!(
                            "Refusing to dial: this run is already listening (a run holds one pairing)."
                        );
                        continue;
                    }
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
    // For a PIN target: the node id resolved on the first successful pairing. Reused on every
    // reconnect thereafter — the typed PIN has since rotated off the relay (so a fresh lookup would
    // fail), but the listener retains our pairing key, so we reconnect by node id and re-prove the
    // same PIN in-band without the user re-typing a code.
    let mut pinned_pin_id: Option<EndpointId> = None;

    loop {
        config.status.set_conn_status(ConnStatus::Connecting);

        // Resolve the target each attempt: a nostr name re-resolves so a listener that
        // restarted with a fresh ephemeral id self-heals on the next try. A PIN resolves to just
        // the node id — the token is never on the relay; the PIN authenticates the connection
        // in-band after we dial (see the `AuthMode` selection below).
        let resolved: Result<EndpointId> = match &target {
            DialTarget::NodeId(id) => Ok(*id),
            // Name discovery is keyed off the shared token (config mode always has one).
            DialTarget::Name(name) => match config.auth_token.as_deref() {
                None => Err(anyhow::anyhow!("dialing by name requires an auth token")),
                Some(token) => {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = cancel.cancelled() => return,
                        r = crate::nostr_discovery::lookup_node_id(
                            token,
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
            },
            // Reconnect fast-path: once paired, dial the remembered node id directly instead of
            // re-resolving the (now-rotated) PIN on the relay.
            DialTarget::Pin(_) if pinned_pin_id.is_some() => Ok(pinned_pin_id.unwrap()),
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

        // The id we're about to dial this attempt, captured before `resolved` is consumed so a
        // successful PIN pairing below can remember it for reconnects.
        let attempt_id: Option<EndpointId> = resolved.as_ref().ok().copied();

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
                // other target presents this process's own token (always present for NodeId/Name).
                let auth = match &target {
                    DialTarget::Pin(pin) => AuthMode::DialPin(pin.clone()),
                    _ => match config.auth_token.clone() {
                        Some(token) => AuthMode::DialToken(token),
                        None => {
                            log::error!(
                                "Dial target requires an auth token but none is configured; ending session."
                            );
                            config.status.set_conn_status(ConnStatus::Closed);
                            config.status.set_dial_target(None);
                            return;
                        }
                    },
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
                        // First successful PIN pairing: remember the node id so reconnects dial it
                        // directly instead of re-resolving the rotated PIN (see `pinned_pin_id`).
                        if matches!(target, DialTarget::Pin(_)) && pinned_pin_id.is_none() {
                            pinned_pin_id = attempt_id;
                        }
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
                    // One-pairing rule: refuse to start listening while an outbound dial session
                    // exists. The TUI hides Shift+L in that state; this guards test-mode/races.
                    if !config.status.can_listen() {
                        log::warn!(
                            "Refusing to listen: this run has an active dial session (a run holds one pairing)."
                        );
                        continue;
                    }
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
    if let Some(token) = &config.auth_token {
        config.status.set_auth_token(token.clone());
    }
    if config.announce_endpoint {
        // Non-interactive mode: surface both on stderr for a test harness. Headless test mode
        // always has a token; quick PIN mode (which has none) never announces.
        eprintln!("node_id: {endpoint_id}");
        if let Some(token) = &config.auth_token {
            eprintln!("auth_token: {token}");
        }
    }
    log::info!("node id: {}", endpoint_id);
    if config.auth_token.is_some() {
        log::info!("Dial this instance with the node id and auth token.");
    } else {
        log::info!("Dial this instance with the rotating PIN (quick PIN mode).");
    }
    log::info!("Waiting for peers to connect...");

    // Publish the (ephemeral) node id to nostr under this peer's identifier so a peer
    // sharing the auth token can discover it by name without a manual node-id
    // exchange. Runs in the background and republishes periodically; relay failures
    // are logged but non-fatal (peers who already have the node id still connect).
    // Requires a token (the rendezvous secret), so quick PIN mode never publishes here.
    let _publisher = match (
        config.nostr_discovery,
        config.nostr_identifier.clone(),
        config.auth_token.clone(),
    ) {
        (true, Some(identifier), Some(auth_token)) => Some(spawn_node_id_publisher(PublisherParams {
            auth_token,
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

    // This serve endpoint pairs with one peer at a time (all modes). The claim is empty until the
    // first dialer authenticates and lives for this whole listen session — a Shift+L stop tears
    // `run_listen` down and starts the next session with a fresh endpoint id and a fresh claim.
    let claim = PairClaim::default();

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
        // Inbound peers authenticate with this process's token (if any), plus (in quick mode) a
        // valid PIN proof against the recent-bucket keys. In quick PIN mode there is no token, so
        // the accepted set is empty and only PIN auth can succeed.
        let auth = AuthMode::Listen {
            tokens: config.auth_token.iter().cloned().collect(),
            pin_cache: pin_cache.clone(),
            claim: claim.clone(),
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
                // Name discovery is keyed off the shared token. A missing token here is a
                // configuration error, not a transient failure, so fail the dial cleanly.
                let Some(token) = config.auth_token.as_deref() else {
                    anyhow::bail!("dial by name requires an auth token");
                };
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    r = crate::nostr_discovery::lookup_node_id(
                        token,
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
                let Some(token) = config.auth_token.clone() else {
                    anyhow::bail!("headless dial requires an auth token");
                };
                let auth = AuthMode::DialToken(token);
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
        AuthMode::Listen {
            tokens,
            pin_cache,
            claim,
        } => {
            auth_as_listener(&conn, tokens, pin_cache.as_ref(), claim).await?;
            config.status.mark_peer_connected(remote_id.to_string());
            log::info!("Peer {remote_id} authenticated");
        }
    }

    let _path_watcher =
        watch_connection_paths(&conn, config.status.clone(), remote_id.to_string(), is_dialer);

    let conn = Arc::new(conn);

    let mut tasks: JoinSet<()> = JoinSet::new();

    // Acceptor side (both roles): accept SOCKS connect-out requests from the peer and
    // connect out (the peer is trusted once auth passed — no destination allowlist).
    // Streams are capped by the global semaphore.
    {
        let conn = conn.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(crate::logging::inherit_source(async move {
            if let Err(e) = accept_loop(conn, semaphore).await {
                log::debug!("Accept loop ended: {}", e);
            }
        }));
    }

    // Local SOCKS5 proxy (both roles): the proxy is symmetric — either side may bind its
    // own loopback proxy and open connect-out streams. Each connection runs a supervisor
    // that starts/stops the proxy on TUI command.
    {
        config.status.reset_socks_status();
        // Subscribe before spawning so an autostart burst cannot race the subscription.
        let command_rx = config.status.subscribe_socks();
        {
            let conn = conn.clone();
            let semaphore = semaphore.clone();
            let status = config.status.clone();
            tasks.spawn(crate::logging::inherit_source(async move {
                socks_supervisor(conn, semaphore, status, command_rx).await;
            }));
        }
        // Optionally autostart the configured proxy (non-interactive/test mode).
        if config.autostart_socks && config.status.has_socks() {
            config.status.send_socks_cmd(SocksCommand::Start);
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
        config.status.mark_peer_disconnected(&remote_id.to_string());
    }
    tasks.shutdown().await;
    Ok(())
}

/// Supervise this peer's local SOCKS5 proxy over one connection. Listens for
/// [`SocksCommand`]s and starts/stops the proxy, tracking a cancellation token
/// while it runs so a `Stop` (or the connection closing) frees the bound local
/// port. The port is read live from [`AppState`] so a runtime change is visible
/// without restarting the supervisor.
async fn socks_supervisor(
    conn: Arc<iroh::endpoint::Connection>,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
    mut command_rx: broadcast::Receiver<SocksCommand>,
) {
    let mut running: Option<CancellationToken> = None;
    // The task signals here when it ends on its own (error/EOF), so the supervisor
    // can drop the stale token and allow a restart.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();

    loop {
        tokio::select! {
            cmd = command_rx.recv() => match cmd {
                Ok(SocksCommand::Start) => {
                    if running.is_some() {
                        continue; // already running
                    }
                    let Some(port) = status.socks_port() else { continue };
                    let token = CancellationToken::new();
                    running = Some(token.clone());

                    let conn = conn.clone();
                    let semaphore = semaphore.clone();
                    let status = status.clone();
                    let done_tx = done_tx.clone();
                    tokio::spawn(crate::logging::inherit_source(async move {
                        let outcome = tokio::select! {
                            r = run_socks_proxy(conn.clone(), port, semaphore, status.clone()) => Some(r),
                            _ = token.cancelled() => None,
                            // Tie the listener's lifetime to the connection so it
                            // never outlives it (which would leak the bound port).
                            _ = conn.closed() => None,
                        };
                        match outcome {
                            Some(Err(e)) => {
                                status.update_socks(SocksStatus::Error, e.to_string());
                                log::warn!("SOCKS proxy ended: {}", e);
                            }
                            // Stopped, connection closed, or the listen loop ended cleanly.
                            Some(Ok(())) | None => {
                                status.update_socks(SocksStatus::Idle, String::new());
                            }
                        }
                        status.set_socks_bound(None);
                        let _ = done_tx.send(());
                    }));
                }
                Ok(SocksCommand::Stop) => {
                    if let Some(token) = running.take() {
                        token.cancel();
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("SOCKS command channel lagged by {n}");
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
///
/// `claim` enforces the one-pair-at-a-time rule across all modes: if another node id already holds
/// the claim this peer is refused up front; otherwise a successful handshake commits this peer as
/// the pair. The claimed peer may reconnect freely — its own node id always passes the gate, and in
/// quick PIN mode the key it paired with is added to the candidate set so its proof still verifies
/// after the PIN has rotated out of `pin_cache`.
async fn auth_as_listener(
    conn: &iroh::endpoint::Connection,
    auth_tokens: &HashSet<String>,
    pin_cache: Option<&RecentPins>,
    claim: &PairClaim,
) -> Result<()> {
    let remote_id = conn.remote_id();

    // Pre-auth gate: this endpoint pairs with one peer at a time. `existing` is the current claim;
    // if it belongs to a different node id we still run the handshake (so the dialer gets a proper
    // rejection instead of a bare connection drop) but with no valid credentials, guaranteeing it
    // fails. If it belongs to this peer, `reconnect_key` lets its rotated PIN still verify.
    let existing = claim.peek();
    let claimed_by_other = existing.as_ref().is_some_and(|c| c.node_id != remote_id);
    let reconnect_key = existing
        .as_ref()
        .filter(|c| c.node_id == remote_id)
        .and_then(|c| c.pin_key.clone());
    if claimed_by_other {
        log::warn!("Refusing {remote_id}: listener is already paired with another device");
    }

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
                if claimed_by_other || !is_token_valid(auth_token.as_str(), auth_tokens) {
                    let reason = if claimed_by_other {
                        "Listener is already paired with another device"
                    } else {
                        log::warn!("Invalid auth token from {}", remote_id);
                        "Invalid authentication token"
                    };
                    let response = AuthResponse::rejected(reason);
                    send.write_all(&encode_auth_response(&response)?).await?;
                    send.finish()?;
                    anyhow::bail!("{reason}");
                }
                // Win the one-pair claim *before* telling the dialer it is accepted, so a race
                // loser is rejected rather than briefly told "accepted" and then dropped.
                if !claim.commit(remote_id, None) {
                    let response =
                        AuthResponse::rejected("Listener is already paired with another device");
                    send.write_all(&encode_auth_response(&response)?).await?;
                    send.finish()?;
                    anyhow::bail!("listener paired with another device first");
                }
                let response = AuthResponse::accepted();
                send.write_all(&encode_auth_response(&response)?).await?;
                send.finish()?;
                Ok::<(), anyhow::Error>(())
            }
            AuthRequest::Pin { nonce, .. } => {
                // Verify the dialer's PIN proof against the recent-bucket keys, plus (for a
                // reconnecting paired peer) the key it originally paired with. An empty candidate
                // set — a non-quick listener, or a peer refused by the gate — yields a clean
                // rejection.
                let mut candidates = if claimed_by_other {
                    Vec::new()
                } else {
                    pin_cache.map(|c| c.snapshot()).unwrap_or_default()
                };
                if let Some(key) = &reconnect_key {
                    candidates.push(key.clone());
                }
                // The claim is committed inside the handshake, right after the proof verifies and
                // *before* the acceptance frame is sent — so a race loser is rejected in-band, not
                // accepted-then-dropped.
                crate::pin_auth::listener_handshake(
                    &mut send,
                    &mut recv,
                    &candidates,
                    &nonce,
                    |key| claim.commit(remote_id, Some(key.clone())),
                )
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
        StreamHello::SocksConnect { host, port, .. } => {
            // The peer is trusted once auth passed, so we connect out to whatever
            // host:port it requests — no allowlist check. Streams are still capped by
            // the global session permit.
            let Some(permit) = acquire_or_reject(&semaphore, &mut send).await? else {
                return Ok(());
            };
            let _permit = permit;
            socks_connect_side(send, recv, &host, port).await
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
            let ack = StreamAck::rejected(socks5::REP_GENERAL_FAILURE, "Session limit reached");
            let _ = send.write_all(&encode_stream_ack(&ack)?).await;
            let _ = send.finish();
            Ok(None)
        }
    }
}

/// Resolve `host:port` on THIS side (remote DNS for domains) and connect out over
/// TCP, then bridge with the stream (acceptor / connect side). On failure, reply
/// with the mapped SOCKS5 REP code so the opener relays it to its local client.
async fn socks_connect_side(
    mut send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let dest = format!("{host}:{port}");
    // Resolve on this peer's network — IP literals (incl. bare IPv6) and domains alike.
    let resolved = match lookup_host((host, port)).await {
        Ok(iter) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if addrs.is_empty() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    "no addresses resolved",
                ))
            } else {
                Ok(order_by_loopback_preference(addrs))
            }
        }
        Err(e) => Err(e),
    };

    let addrs = match resolved {
        Ok(addrs) => addrs,
        Err(e) => {
            let ack = StreamAck::rejected(
                socks5::rep_for_io_error(&e),
                format!("resolve failed: {e}"),
            );
            send.write_all(&encode_stream_ack(&ack)?).await?;
            let _ = send.finish();
            anyhow::bail!("Failed to resolve {}: {}", dest, e);
        }
    };

    match try_connect_tcp(&addrs).await {
        Ok(tcp_stream) => {
            send.write_all(&encode_stream_ack(&StreamAck::accepted())?)
                .await?;
            log::info!("-> Connected to TCP {}", dest);
            bridge_streams(recv, send, tcp_stream).await?;
            log::info!("<- TCP connection to {} closed", dest);
        }
        Err(e) => {
            // `try_connect_tcp` returns an anyhow error; map its io kind when present
            // (usually connection refused) so the client sees a meaningful REP code.
            let rep = e
                .downcast_ref::<std::io::Error>()
                .map(socks5::rep_for_io_error)
                .unwrap_or(socks5::REP_CONN_REFUSED);
            let ack = StreamAck::rejected(rep, format!("connect failed: {e}"));
            send.write_all(&encode_stream_ack(&ack)?).await?;
            let _ = send.finish();
            anyhow::bail!("Failed to connect to TCP {}: {}", dest, e);
        }
    }

    Ok(())
}

// ============================================================================
// Local SOCKS5 proxy: opener side
// ============================================================================

/// Timeout for the local SOCKS5 handshake + connect-out ack, so a silent local
/// client can't pin a stream permit indefinitely before the bridge starts.
const SOCKS_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the local SOCKS5 proxy over one connection: bind loopback (IPv4 + IPv6) at
/// `port` (0 = OS-assigned), then per client run the SOCKS5 handshake, open a
/// connect-out stream, await the ack, reply, and bridge. Runs until it errors or
/// the caller cancels it (freeing the bound port).
async fn run_socks_proxy(
    conn: Arc<iroh::endpoint::Connection>,
    port: u16,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
) -> Result<()> {
    let listeners = bind_socks_listeners(port).await?;
    // Surface the actually-bound address (with port 0, the OS-assigned port).
    let bound = listeners
        .iter()
        .find_map(|l| l.local_addr().ok())
        .expect("at least one bound listener");
    status.update_socks(SocksStatus::Listening, bound.to_string());
    status.set_socks_bound(Some(bound));
    socks_accept_loop(conn, listeners, semaphore).await
}

/// Bind loopback SOCKS listeners on IPv4 (127.0.0.1) and IPv6 (::1). With `port == 0`
/// the OS assigns a port to the first bound family and the second reuses it, so both
/// families share one port. Tolerates one family failing (e.g. no IPv6 loopback).
async fn bind_socks_listeners(port: u16) -> Result<Vec<TcpListener>> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut listeners = Vec::with_capacity(2);
    // Bind IPv4 first; if port is 0 the OS picks one and IPv6 reuses it.
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match TcpListener::bind(v4).await {
        Ok(l) => {
            log::info!("SOCKS5 proxy listening on {}", l.local_addr()?);
            listeners.push(l);
        }
        Err(e) => log::warn!("Failed to bind SOCKS listener on {}: {}", v4, e),
    }
    let v6_port = listeners
        .first()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(port);
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, v6_port));
    match TcpListener::bind(v6).await {
        Ok(l) => {
            log::info!("SOCKS5 proxy listening on {}", l.local_addr()?);
            listeners.push(l);
        }
        Err(e) => log::debug!("Failed to bind SOCKS listener on {}: {}", v6, e),
    }
    if listeners.is_empty() {
        anyhow::bail!("Failed to bind any loopback SOCKS listener on port {}", port);
    }
    Ok(listeners)
}

/// Accept local TCP connections from the SOCKS listeners; per connection acquire a
/// permit and handle the SOCKS5 client.
async fn socks_accept_loop(
    conn: Arc<iroh::endpoint::Connection>,
    listeners: Vec<TcpListener>,
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
                    Err(e) => log::warn!("Failed to accept SOCKS connection: {}", e),
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
                log::warn!("Session limit reached, dropping SOCKS connection from {}", peer);
                continue;
            }
        };
        let conn = conn.clone();
        conn_tasks.spawn(crate::logging::inherit_source(async move {
            let _permit = permit;
            if let Err(e) = handle_socks_client(&conn, tcp_stream).await {
                log::debug!("SOCKS client {} failed: {}", peer, e);
            }
        }));
        while conn_tasks.try_join_next().is_some() {}
    }

    accept_tasks.shutdown().await;
    conn_tasks.shutdown().await;
    Ok(())
}

/// Handle one local SOCKS5 client: negotiate, read the CONNECT target, open a
/// connect-out stream to the peer, relay the peer's REP to the client, then bridge.
async fn handle_socks_client(
    conn: &iroh::endpoint::Connection,
    mut tcp: TcpStream,
) -> Result<()> {
    // Bound the whole pre-bridge phase so a stalled client can't hold the permit.
    let (send, recv, ack) = match tokio::time::timeout(SOCKS_SETUP_TIMEOUT, async {
        socks5::negotiate_method(&mut tcp).await?;
        // read_connect_request writes its own SOCKS error replies before erroring.
        let target = socks5::read_connect_request(&mut tcp).await?;
        let (mut send, mut recv) = open_bi_with_retry(conn)
            .await
            .map_err(|e| std::io::Error::other(format!("open stream: {e}")))?;
        let hello = StreamHello::socks_connect(target.host(), target.port());
        let bytes = encode_stream_hello(&hello)
            .map_err(|e| std::io::Error::other(format!("encode hello: {e}")))?;
        send.write_all(&bytes).await?;
        let ack = read_ack(&mut recv)
            .await
            .map_err(|e| std::io::Error::other(format!("read ack: {e}")))?;
        Ok::<_, std::io::Error>((send, recv, ack))
    })
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            // Best-effort: tell the local client the attempt failed before dropping.
            let _ = socks5::write_reply(&mut tcp, socks5::REP_GENERAL_FAILURE).await;
            return Err(e.into());
        }
        Err(_) => {
            let _ = socks5::write_reply(&mut tcp, socks5::REP_GENERAL_FAILURE).await;
            anyhow::bail!("SOCKS setup timed out");
        }
    };

    // Relay the peer's connect outcome verbatim into the SOCKS reply.
    socks5::write_reply(&mut tcp, ack.rep).await?;
    if !ack.accepted {
        log::debug!(
            "Peer refused connect (rep {:#04x}): {}",
            ack.rep,
            ack.reason.as_deref().unwrap_or("unknown")
        );
        return Ok(());
    }
    bridge_streams(recv, send, tcp).await
}

/// Read a [`StreamAck`] from the stream. Returns the ack (accepted or rejected) so
/// the caller can relay its REP code; only a transport/decode failure errors.
async fn read_ack(recv: &mut iroh::endpoint::RecvStream) -> Result<StreamAck> {
    let ack_bytes = tokio::time::timeout(ACK_TIMEOUT, read_length_prefixed(recv))
        .await
        .context("Timed out waiting for stream ack")?
        .context("Failed to read stream ack")?;
    decode_stream_ack(&ack_bytes).context("Invalid stream ack")
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
            autostart_socks: false,
            auth_token: Some(token.to_string()),
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
            autostart_socks: true,
            auth_token: Some("tok".to_string()),
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
        // Autostart (test-mode) applies to the symmetric proxy on both halves.
        assert!(listen.autostart_socks);
        assert!(dial.autostart_socks);

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
                claim: PairClaim::default(),
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
            auth_as_listener(&conn, &accepted, None, &PairClaim::default())
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

    /// Drive the quick-mode PIN handshake over a real iroh connection: the dialer
    /// proves possession of `dialer_pin` via `auth_as_dialer_pin` (the `DialPin`
    /// path) while the listener verifies it in `auth_as_listener`'s
    /// `AuthRequest::Pin` branch, seeded with `listener_pins` in its recent-bucket
    /// cache (empty ⇒ a non-quick / no-PIN listener). Returns
    /// `(dialer_result, listener_result)`.
    async fn run_pin_auth(dialer_pin: &str, listener_pins: &[&str]) -> (Result<()>, Result<()>) {
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

        // Seed the recent-bucket PIN keys the listener verifies proofs against.
        let recent = RecentPins::default();
        for p in listener_pins {
            recent.push(crate::pin_auth::derive_auth_keys(p).expect("derive PIN auth keys"));
        }

        // Listener: a quick-mode listener accepts no tokens, only PIN proofs. Return the
        // `conn` alongside the result so it stays alive until the dialer has read the final
        // confirm frame — production keeps the connection open after auth, so dropping it here
        // would otherwise race the dialer's last read.
        let server_ep2 = server_ep.clone();
        let listener_task = tokio::spawn(async move {
            let incoming = server_ep2.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("accept connection");
            let res =
                auth_as_listener(&conn, &HashSet::new(), Some(&recent), &PairClaim::default())
                    .await;
            (res, conn)
        });

        let client_conn = client_ep
            .connect(server_addr, ALPN)
            .await
            .expect("dial connect");
        let dialer_result = auth_as_dialer_pin(&client_conn, dialer_pin).await;
        let (listener_result, _conn) = listener_task.await.expect("listener task panicked");

        client_ep.close().await;
        server_ep.close().await;
        (dialer_result, listener_result)
    }

    /// Happy path: a dialer presenting a PIN in the listener's recent-bucket cache
    /// is mutually authenticated through the `AuthRequest::Pin` / `DialPin` branches.
    #[tokio::test]
    async fn pin_auth_accepts_valid_proof() {
        let pin = crate::pin::generate_pin();
        let (dialer, listener) = run_pin_auth(&pin, &[&pin]).await;
        assert!(dialer.is_ok(), "dialer should authenticate: {dialer:?}");
        assert!(listener.is_ok(), "listener should accept: {listener:?}");
    }

    /// A dialer whose PIN is not among the listener's recent buckets is rejected on
    /// both sides — the security-critical branch that must never accept a bad PIN.
    #[tokio::test]
    async fn pin_auth_rejects_wrong_pin() {
        let dialer_pin = crate::pin::generate_pin();
        let listener_pin = crate::pin::generate_pin();
        let (dialer, listener) = run_pin_auth(&dialer_pin, &[&listener_pin]).await;
        assert!(dialer.is_err(), "dialer with wrong PIN must be rejected");
        assert!(listener.is_err(), "listener must reject a wrong PIN");
    }

    /// A listener with no recent PINs (empty candidate set — e.g. not in quick PIN
    /// mode) cleanly rejects any PIN proof rather than accepting or panicking.
    #[tokio::test]
    async fn pin_auth_rejects_when_no_recent_pins() {
        let pin = crate::pin::generate_pin();
        let (dialer, listener) = run_pin_auth(&pin, &[]).await;
        assert!(dialer.is_err(), "dialer must be rejected with no candidates");
        assert!(listener.is_err(), "listener with empty cache must reject");
    }

    /// `PairClaim` gives the first committer exclusive hold: that node id (and only it) may
    /// commit again (reconnect); any other node id is refused until the claim is dropped.
    #[tokio::test]
    async fn pair_claim_is_exclusive_and_reentrant() {
        let a = hermetic_endpoint().await;
        let b = hermetic_endpoint().await;
        let (id_a, id_b) = (a.id(), b.id());
        a.close().await;
        b.close().await;

        let claim = PairClaim::default();
        assert!(claim.peek().is_none(), "starts unclaimed");
        assert!(claim.commit(id_a, None), "first committer wins");
        assert!(claim.commit(id_a, None), "same peer may re-commit (reconnect)");
        assert!(!claim.commit(id_b, None), "a different peer is refused");
        assert_eq!(claim.peek().map(|c| c.node_id), Some(id_a));
    }

    /// Wait until `ep` publishes a direct address, then return it (hermetic endpoints only
    /// ever surface a direct addr — relay is disabled).
    async fn ready_addr(ep: &Endpoint) -> iroh::EndpointAddr {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let addr = ep.addr();
                if addr.ip_addrs().next().is_some() {
                    break addr;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("direct address ready")
    }

    /// One token-auth attempt against a shared listener endpoint + claim. Returns the dialer's
    /// and listener's auth results. Keeps the accepted connection alive until the dialer has read
    /// its response, mirroring production (which holds the connection open after auth).
    async fn token_attempt(
        server_ep: &Endpoint,
        addr: &iroh::EndpointAddr,
        client_ep: &Endpoint,
        token: &str,
        accepted: &HashSet<String>,
        claim: &PairClaim,
    ) -> (Result<()>, Result<()>) {
        let server_ep2 = server_ep.clone();
        let accepted = accepted.clone();
        let claim = claim.clone();
        let listener = tokio::spawn(async move {
            let incoming = server_ep2.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("accept connection");
            let res = auth_as_listener(&conn, &accepted, None, &claim).await;
            (res, conn)
        });
        let conn = client_ep.connect(addr.clone(), ALPN).await.expect("connect");
        let dialer_res = auth_as_dialer(&conn, token).await;
        let (listener_res, _conn) = listener.await.expect("listener task panicked");
        (dialer_res, listener_res)
    }

    /// The serve endpoint pairs with the first peer to authenticate; a second, different node id
    /// is refused even with a valid token, while the paired peer may reconnect freely — the
    /// one-pair-at-a-time rule that now applies to every mode.
    #[tokio::test]
    async fn listener_pairs_with_one_peer_across_reconnects() {
        let token = "one-pair-token";
        let server_ep = hermetic_endpoint().await;
        let addr = ready_addr(&server_ep).await;
        let client_a = hermetic_endpoint().await;
        let client_b = hermetic_endpoint().await;
        let claim = PairClaim::default();
        let accepted: HashSet<String> = std::iter::once(token.to_string()).collect();

        // First peer claims the endpoint.
        let (d, l) = token_attempt(&server_ep, &addr, &client_a, token, &accepted, &claim).await;
        assert!(d.is_ok() && l.is_ok(), "first peer pairs: d={d:?} l={l:?}");

        // A different device with the same valid token is refused.
        let (d, l) = token_attempt(&server_ep, &addr, &client_b, token, &accepted, &claim).await;
        assert!(d.is_err(), "second device must be rejected");
        assert!(l.is_err(), "listener must refuse the second device");

        // The paired peer reconnects without trouble.
        let (d, l) = token_attempt(&server_ep, &addr, &client_a, token, &accepted, &claim).await;
        assert!(d.is_ok() && l.is_ok(), "paired peer reconnects: d={d:?} l={l:?}");

        client_a.close().await;
        client_b.close().await;
        server_ep.close().await;
    }

    /// One PIN-auth attempt against a shared listener endpoint + claim + recent-bucket cache.
    async fn pin_attempt(
        server_ep: &Endpoint,
        addr: &iroh::EndpointAddr,
        client_ep: &Endpoint,
        pin: &str,
        recent: &RecentPins,
        claim: &PairClaim,
    ) -> (Result<()>, Result<()>) {
        let server_ep2 = server_ep.clone();
        let recent = recent.clone();
        let claim = claim.clone();
        let listener = tokio::spawn(async move {
            let incoming = server_ep2.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("accept connection");
            let res = auth_as_listener(&conn, &HashSet::new(), Some(&recent), &claim).await;
            (res, conn)
        });
        let conn = client_ep.connect(addr.clone(), ALPN).await.expect("connect");
        let dialer_res = auth_as_dialer_pin(&conn, pin).await;
        let (listener_res, _conn) = listener.await.expect("listener task panicked");
        (dialer_res, listener_res)
    }

    /// Quick PIN mode: the paired peer reconnects even after its PIN has rotated out of the
    /// recent-bucket cache (the listener retained its pairing key), while a *different* device
    /// presenting the very same, still-cached PIN is refused because the endpoint is already
    /// paired.
    #[tokio::test]
    async fn pin_pair_reconnects_after_rotation_and_blocks_others() {
        let pin = crate::pin::generate_pin();
        let server_ep = hermetic_endpoint().await;
        let addr = ready_addr(&server_ep).await;
        let client_a = hermetic_endpoint().await;
        let client_b = hermetic_endpoint().await;
        let claim = PairClaim::default();

        // First pairing: the PIN is in the recent cache and populates the claim.
        let recent = RecentPins::default();
        recent.push(crate::pin_auth::derive_auth_keys(&pin).unwrap());
        let (d, l) = pin_attempt(&server_ep, &addr, &client_a, &pin, &recent, &claim).await;
        assert!(d.is_ok() && l.is_ok(), "first PIN pairing: d={d:?} l={l:?}");

        // Rotation: the PIN is gone from the cache, but the paired peer still reconnects.
        let rotated = RecentPins::default();
        let (d, l) = pin_attempt(&server_ep, &addr, &client_a, &pin, &rotated, &claim).await;
        assert!(d.is_ok(), "paired peer must reconnect after rotation: {d:?}");
        assert!(l.is_ok(), "listener must accept the reconnect: {l:?}");

        // A different device presenting the same (freshly re-cached) PIN is still refused.
        let same_pin_cached = RecentPins::default();
        same_pin_cached.push(crate::pin_auth::derive_auth_keys(&pin).unwrap());
        let (d, l) = pin_attempt(&server_ep, &addr, &client_b, &pin, &same_pin_cached, &claim).await;
        assert!(d.is_err(), "a second device must be rejected even with the PIN");
        assert!(l.is_err(), "listener must refuse a second device");

        client_a.close().await;
        client_b.close().await;
        server_ep.close().await;
    }

    // ========================================================================
    // End-to-end SOCKS5 proxy tests (hermetic, offline)
    // ========================================================================

    /// A test PeerConfig with a specific SOCKS port + autostart setting.
    fn test_peer_config_socks(
        role: Role,
        token: &str,
        socks_port: Option<u16>,
        autostart_socks: bool,
    ) -> Arc<PeerConfig> {
        let status = AppState::new(role, false, LogBuffer::new(16), socks_port, false, None, false);
        Arc::new(PeerConfig {
            role,
            peer_node_id: None,
            autostart_socks,
            auth_token: Some(token.to_string()),
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

    /// A loopback TCP echo server (echoes each read back). Returns its address and task.
    async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let handle = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        (addr, handle)
    }

    /// Do the SOCKS5 no-auth greeting and return the negotiated stream.
    async fn socks_greet(proxy: SocketAddr) -> TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = TcpStream::connect(proxy).await.expect("connect proxy");
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "no-auth method selected");
        s
    }

    /// Send a SOCKS5 CONNECT and return the (stream, REP code).
    async fn socks_connect(proxy: SocketAddr, req_tail: &[u8]) -> (TcpStream, u8) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = socks_greet(proxy).await;
        let mut req = vec![0x05, 0x01, 0x00];
        req.extend_from_slice(req_tail);
        s.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        (s, reply[1])
    }

    /// CONNECT tail for an IPv4 target (ATYP 0x01).
    fn ipv4_tail(addr: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(v4) = addr else {
            panic!("expected IPv4")
        };
        let mut t = vec![0x01];
        t.extend_from_slice(&v4.ip().octets());
        t.extend_from_slice(&v4.port().to_be_bytes());
        t
    }

    /// CONNECT tail for a domain target (ATYP 0x03), resolved on the remote side.
    fn domain_tail(host: &str, port: u16) -> Vec<u8> {
        let mut t = vec![0x03, host.len() as u8];
        t.extend_from_slice(host.as_bytes());
        t.extend_from_slice(&port.to_be_bytes());
        t
    }

    /// Spawn a paired listener+dialer over hermetic endpoints, with the local SOCKS5
    /// proxy autostarted on one side (`proxy_on_dialer`). Waits for the proxy to bind
    /// and returns its address plus the endpoints and tasks (kept alive by the caller).
    #[allow(clippy::type_complexity)]
    async fn spawn_socks_pair(
        token: &str,
        proxy_on_dialer: bool,
    ) -> (
        SocketAddr,
        Endpoint,
        Endpoint,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let server_ep = hermetic_endpoint().await;
        let addr = ready_addr(&server_ep).await;
        let client_ep = hermetic_endpoint().await;

        let (listener_port, dialer_port) = if proxy_on_dialer {
            (None, Some(0u16))
        } else {
            (Some(0u16), None)
        };

        let server_cfg =
            test_peer_config_socks(Role::Listen, token, listener_port, listener_port.is_some());
        let listener_status = server_cfg.status.clone();
        let server_ep2 = server_ep.clone();
        let token_s = token.to_string();
        let server_task = tokio::spawn(async move {
            let incoming = server_ep2.accept().await.expect("incoming");
            let conn = incoming.await.expect("accept");
            let auth = AuthMode::Listen {
                tokens: std::iter::once(token_s).collect(),
                pin_cache: None,
                claim: PairClaim::default(),
            };
            let _ = handle_connection(conn, server_cfg, test_semaphore(), auth).await;
        });

        let client_conn = client_ep.connect(addr, ALPN).await.expect("connect");
        let client_cfg =
            test_peer_config_socks(Role::Dial, token, dialer_port, dialer_port.is_some());
        let dialer_status = client_cfg.status.clone();
        let auth = AuthMode::DialToken(token.to_string());
        let client_task = tokio::spawn(async move {
            let _ = handle_connection(client_conn, client_cfg, test_semaphore(), auth).await;
        });

        // Wait for the proxy to bind on the chosen side.
        let proxy_status = if proxy_on_dialer {
            dialer_status
        } else {
            listener_status
        };
        let proxy_addr = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(a) = proxy_status.socks_bound() {
                    break a;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("proxy bound");

        (proxy_addr, server_ep, client_ep, server_task, client_task)
    }

    /// Forward direction: a SOCKS5 client on the dialer's proxy reaches a service on
    /// the listener's network, by both IPv4 literal and (remote-resolved) domain.
    #[tokio::test]
    async fn socks_forward_dialer_proxy_reaches_listener_network() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (echo_addr, echo_task) = spawn_echo().await;
        let (proxy, server_ep, client_ep, server_task, client_task) =
            spawn_socks_pair("socks-fwd-token", true).await;

        // IPv4 CONNECT round-trips a payload.
        let (mut s, rep) = socks_connect(proxy, &ipv4_tail(echo_addr)).await;
        assert_eq!(rep, socks5::REP_SUCCESS, "IPv4 CONNECT accepted");
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "echo round-trip over the proxy");
        drop(s);

        // Domain CONNECT resolves "localhost" on the acceptor (remote DNS) and succeeds.
        let (mut s, rep) = socks_connect(proxy, &domain_tail("localhost", echo_addr.port())).await;
        assert_eq!(rep, socks5::REP_SUCCESS, "domain CONNECT accepted (remote DNS)");
        s.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server_task.abort();
        client_task.abort();
        echo_task.abort();
        client_ep.close().await;
        server_ep.close().await;
    }

    /// Reverse direction: a SOCKS5 client on the listener's proxy reaches a service on
    /// the dialer's network — proves the proxy is symmetric and listener-opened
    /// post-auth streams work.
    #[tokio::test]
    async fn socks_reverse_listener_proxy_reaches_dialer_network() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (echo_addr, echo_task) = spawn_echo().await;
        let (proxy, server_ep, client_ep, server_task, client_task) =
            spawn_socks_pair("socks-rev-token", false).await;

        let (mut s, rep) = socks_connect(proxy, &ipv4_tail(echo_addr)).await;
        assert_eq!(rep, socks5::REP_SUCCESS, "reverse CONNECT accepted");
        s.write_all(b"echo").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"echo", "reverse echo round-trip");

        server_task.abort();
        client_task.abort();
        echo_task.abort();
        client_ep.close().await;
        server_ep.close().await;
    }

    /// A CONNECT to a closed port surfaces REP_CONN_REFUSED to the local client,
    /// exercising the remote-side error mapping end-to-end.
    #[tokio::test]
    async fn socks_connect_refused_maps_to_rep() {
        // Bind then immediately drop a listener to obtain a very-likely-closed port.
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let (proxy, server_ep, client_ep, server_task, client_task) =
            spawn_socks_pair("socks-refused-token", true).await;

        let (_s, rep) = socks_connect(proxy, &ipv4_tail(closed)).await;
        assert_eq!(
            rep,
            socks5::REP_CONN_REFUSED,
            "connect to a closed port maps to REP_CONN_REFUSED"
        );

        server_task.abort();
        client_task.abort();
        client_ep.close().await;
        server_ep.close().await;
    }
}
