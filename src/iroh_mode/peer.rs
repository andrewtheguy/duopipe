//! Symmetric iroh peer: one connection, request-based tunnels.
//!
//! A peer either dials another peer (`Role::Dial`) or listens for one
//! (`Role::Listen`). Connection *setup* is asymmetric (QUIC needs a dialer and
//! an acceptor), but once a connection is established each side *requests*
//! tunnels from the other: a request binds a local listener and asks the peer to
//! connect out to a remote `source`, bridging the two. Requests are activated
//! on demand (the TUI sends start/stop commands); nothing starts automatically
//! unless `DUOPIPE_AUTOSTART_REQUESTS` is set (test mode only).
//!
//! Every non-auth stream begins with a [`StreamHello`] so the acceptor can route
//! it without positional assumptions. Trust model: once token auth passes, the
//! peer is trusted, but the *acceptor* still gates each requested `source`
//! against its `allowed_sources` CIDR allowlist before connecting. Empty TCP
//! allowlists are defaulted to localhost at startup.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::ConnectionError;
use iroh::{Endpoint, EndpointId};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::app_state::{
    AppState, ConnStatus, DialCommand, DialTarget, Role, TunnelCommand, TunnelId, TunnelStatus,
};
use crate::auth::is_token_valid;
use crate::config::{AllowedSources, RequestEntry, TransportTuning};
use crate::error::{ErrorCategory, TunnelError};
use crate::net::{
    check_source_allowed, extract_addr_from_source, resolve_all_target_addrs, resolve_listen_addrs,
    try_connect_tcp, tune_tcp_stream,
};

use crate::iroh_mode::endpoint::{
    ALPN, connect_to_server, create_client_endpoint, create_server_endpoint, validate_relay_only,
    watch_connection_paths,
};
use crate::iroh_mode::helpers::{
    bridge_streams, forward_stream_to_udp_client, forward_stream_to_udp_server,
    forward_udp_to_stream, open_bi_with_retry,
};
use crate::signaling::{
    AuthRequest, AuthResponse, StreamAck, StreamHello, decode_auth_request, decode_auth_response,
    decode_stream_ack, decode_stream_hello, encode_auth_request, encode_auth_response,
    encode_stream_ack, encode_stream_hello, read_length_prefixed,
};

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
    /// CIDR allowlist gating which of our sources the peer may request.
    /// Empty protocol allowlists are defaulted to localhost in `run_peer`.
    pub allowed_sources: AllowedSources,
    /// When true, start every configured request as soon as a connection is up
    /// (set from `DUOPIPE_AUTOSTART_REQUESTS` in test mode; see `DUOPIPE_TEST_MODE`).
    pub autostart_requests: bool,
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
    /// Short identifier for nostr discovery (role-dependent): when listening, the
    /// name this peer publishes its node id under; when dialing, the target peer's
    /// name to look up. `None` outside nostr mode.
    pub nostr_identifier: Option<String>,
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
    /// Shared state surfaced by the TUI.
    pub status: Arc<AppState>,
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("role", &self.role.label())
            .field("peer_node_id", &self.peer_node_id)
            .field("allowed_sources", &self.allowed_sources)
            .field("autostart_requests", &self.autostart_requests)
            .field("auth_token", &"[REDACTED]")
            .field("nostr_relays", &self.nostr_relays)
            .field("nostr_discovery", &self.nostr_discovery)
            .field("nostr_identifier", &self.nostr_identifier)
            .field("report_endpoint_id", &self.report_endpoint_id)
            .field("relay_urls", &self.relay_urls)
            .field("relay_only", &self.relay_only)
            .field("dns_server", &self.dns_server)
            .field("max_streams", &self.max_streams)
            .field("transport", &self.transport)
            .field("announce_endpoint", &self.announce_endpoint)
            .field("status", &"<present>")
            .finish()
    }
}

/// Run a symmetric peer: dial or listen, then serve tunnels in both directions.
pub async fn run_peer(mut config: PeerConfig) -> Result<()> {
    validate_relay_only(config.relay_only, &config.relay_urls)?;

    // Empty allowlists default to dual-stack localhost; an empty list would
    // otherwise reject the common loopback-tunnel case.
    config.allowed_sources = config.allowed_sources.with_localhost_defaults();

    // One global stream limiter for the whole process, created up front so a dual-role
    // process shares a single cap across its listen and dial halves.
    let semaphore = new_stream_semaphore(&config)?;

    match config.role {
        Role::Listen => run_listen(config, semaphore).await,
        Role::Dial => run_dial(config, semaphore).await,
        Role::Both => run_serve_and_dial(config, semaphore).await,
    }
}

/// Split the interactive `Role::Both` config into a listen sub-config (always serving)
/// and a dial sub-config (used by the dial manager). Both share the same `Arc<AppState>`
/// and the one stream semaphore; the dial target itself is supplied at runtime via
/// [`DialCommand`], not by config.
fn split_serve_dial_config(config: &PeerConfig) -> (PeerConfig, PeerConfig) {
    let mut listen = config.clone();
    listen.role = Role::Listen;
    listen.peer_node_id = None;
    listen.autostart_requests = false;
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

/// Interactive runtime: serve inbound peers from launch (listen half, always on) while a
/// dial manager maintains at most one user-initiated outbound session. The two halves
/// share `AppState` and the stream semaphore but never interact at the connection layer.
/// If either half returns, the shared shutdown is cancelled so the other unwinds.
async fn run_serve_and_dial(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    let (listen_cfg, dial_cfg) = split_serve_dial_config(&config);
    let shutdown = config.status.shutdown.clone();

    let listen_sem = semaphore.clone();
    let mut listen_task = tokio::spawn(run_listen(listen_cfg, listen_sem));
    let mut dial_task = tokio::spawn(run_dial_manager(dial_cfg, semaphore));

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
                    let h = tokio::spawn(async move {
                        run_managed_dial_session(cfg, sem, &ep, own_id, target, session_tok).await;
                    });
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
        // restarted with a fresh ephemeral id self-heals on the next try.
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
        };

        // Self-dial guard: end the session (not the process) — the target won't change.
        if let Ok(id) = &resolved
            && *id == own_id
        {
            log::error!("Refusing to dial this peer's own node id ({own_id}); ending session.");
            config.status.set_conn_status(ConnStatus::Closed);
            config.status.set_dial_target(None);
            return;
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
                // handle_connection returns on conn-close or process shutdown; also race
                // the session cancel so a disconnect/replace tears it down promptly.
                let outcome = tokio::select! {
                    r = handle_connection(conn, config.clone(), semaphore.clone(), true) => Some(r),
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
// Listen role
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

async fn run_listen(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    log::info!("Symmetric Peer - Listen Mode");
    log::info!("============================");

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
        (true, Some(identifier)) => Some(spawn_node_id_publisher(
            config.auth_token.clone(),
            identifier,
            endpoint_id,
            config.nostr_relays.clone(),
            config.status.shutdown.clone(),
        )),
        _ => None,
    };

    let shutdown = config.status.shutdown.clone();
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
        connection_tasks.spawn(async move {
            if let Err(e) = handle_connection(conn, config, semaphore, false).await {
                log::warn!("Connection error for {}: {}", remote_id, e);
            }
        });
    }

    connection_tasks.shutdown().await;
    endpoint.close().await;
    log::info!("Peer (listen) stopped.");
    Ok(())
}

/// Background guard that aborts the node-id publisher task on drop.
struct PublisherGuard(tokio::task::JoinHandle<()>);

impl Drop for PublisherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Interval between node-id republishes. Replaceable nostr events can be dropped by
/// relays at varying times, so we refresh periodically while listening.
const NODE_ID_REPUBLISH_INTERVAL: Duration = Duration::from_secs(300);

/// Spawn a task that publishes our ephemeral node id to nostr now, then refreshes
/// it every [`NODE_ID_REPUBLISH_INTERVAL`] until shutdown.
fn spawn_node_id_publisher(
    auth_token: String,
    identifier: String,
    node_id: EndpointId,
    relays: Vec<String>,
    shutdown: CancellationToken,
) -> PublisherGuard {
    PublisherGuard(tokio::spawn(async move {
        loop {
            match crate::nostr_discovery::publish_node_id(&auth_token, &identifier, &node_id, &relays)
                .await
            {
                Ok(()) => log::info!("Published node id to nostr for peer discovery"),
                Err(e) => log::warn!("Failed to publish node id to nostr: {e:#}"),
            }
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(NODE_ID_REPUBLISH_INTERVAL) => {}
            }
        }
    }))
}

// ============================================================================
// Dial role
// ============================================================================

async fn run_dial(config: PeerConfig, semaphore: Arc<Semaphore>) -> Result<()> {
    if config.peer_node_id.is_none() && config.nostr_identifier.is_none() {
        anyhow::bail!(
            "dial role requires a peer node id (quick mode) or a peer identifier (nostr mode)"
        );
    }

    log::info!("Symmetric Peer - Dial Mode");
    log::info!("==========================");

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
                "Refusing to dial this peer's own node id ({own_id}). Set a different target node id (quick mode) or peer identifier (nostr mode)."
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
                match handle_connection(conn, config.clone(), semaphore.clone(), true).await {
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
    is_dialer: bool,
) -> Result<()> {
    let remote_id = conn.remote_id();

    // Phase 1: authenticate. The listener serves any number of peers concurrently,
    // so there is no session binding — authentication is the only gate.
    if is_dialer {
        config.status.set_conn_status(ConnStatus::Authenticating);
        auth_as_dialer(&conn, &config.auth_token).await?;
        config.status.set_conn_status(ConnStatus::Connected);
    } else {
        let accepted: HashSet<String> = std::iter::once(config.auth_token.clone()).collect();
        auth_as_listener(&conn, &accepted).await?;
        config.status.add_peer(remote_id.to_string());
        log::info!("Peer {remote_id} authenticated");
    }

    let _path_watcher =
        watch_connection_paths(&conn, config.status.clone(), remote_id.to_string(), is_dialer);

    let conn = Arc::new(conn);

    let mut tasks: JoinSet<()> = JoinSet::new();

    // Acceptor side (both roles): accept incoming tunnel requests from the peer, gate
    // each requested source against our allowed_sources allowlist, then connect out.
    // Streams are capped by the global semaphore shared across all peers.
    {
        let conn = conn.clone();
        let semaphore = semaphore.clone();
        let allowed_sources = Arc::new(config.allowed_sources.clone());
        tasks.spawn(async move {
            if let Err(e) = accept_loop(conn, semaphore, allowed_sources).await {
                log::debug!("Accept loop ended: {}", e);
            }
        });
    }

    // Requester side (dial role only): a dialer drives a single connection, so it
    // owns the tunnel table and supervises start/stop of its own requests. A listener
    // serves many peers at once and initiates no tunnels — there is no single
    // connection a request could be bound to — so it only runs the acceptor above.
    if is_dialer {
        config.status.seed_tunnels_from_requests();
        // Subscribe before spawning so an autostart burst cannot race the subscription.
        let command_rx = config.status.subscribe_commands();
        {
            let conn = conn.clone();
            let semaphore = semaphore.clone();
            let status = config.status.clone();
            tasks.spawn(async move {
                request_supervisor(conn, semaphore, status, command_rx).await;
            });
        }
        // Optionally autostart every configured request (non-interactive/test mode).
        if config.autostart_requests {
            for id in config.status.request_ids() {
                config.status.send_command(TunnelCommand::Start(id));
            }
        }
    }

    // Run until the connection closes or a local shutdown is requested, then tear
    // everything down. Observing `shutdown` here is essential for the dial role:
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

/// Supervise this peer's tunnel requests over one connection. Listens for
/// [`TunnelCommand`]s and starts/stops each request, tracking a cancellation
/// token per running request so a `Stop` (or the connection closing) frees the
/// bound local port. Requests are read live from [`AppState`] so runtime-added
/// ones are visible without restarting the supervisor.
async fn request_supervisor(
    conn: Arc<iroh::endpoint::Connection>,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
    mut command_rx: broadcast::Receiver<TunnelCommand>,
) {
    let mut running: HashMap<TunnelId, CancellationToken> = HashMap::new();
    // Tasks report their own id here when they end on their own (error/EOF), so the
    // supervisor can drop the stale token and allow a restart.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<TunnelId>();

    loop {
        tokio::select! {
            cmd = command_rx.recv() => match cmd {
                Ok(TunnelCommand::Start(id)) => {
                    if running.contains_key(&id) {
                        continue; // already running
                    }
                    let Some(req) = status.get_request(id) else { continue };
                    let token = CancellationToken::new();
                    running.insert(id, token.clone());

                    let conn = conn.clone();
                    let semaphore = semaphore.clone();
                    let status = status.clone();
                    let done_tx = done_tx.clone();
                    tokio::spawn(async move {
                        let outcome = tokio::select! {
                            r = run_request(conn.clone(), req, semaphore, status.clone(), id) => Some(r),
                            _ = token.cancelled() => None,
                            // Tie the listener's lifetime to the connection so it
                            // never outlives it (which would leak the bound port).
                            _ = conn.closed() => None,
                        };
                        match outcome {
                            Some(Err(e)) => {
                                status.update_tunnel(id, TunnelStatus::Error, e.to_string());
                                log::warn!("Request {} ended: {}", id, e);
                            }
                            // Stopped, connection closed, or the listen loop ended cleanly.
                            Some(Ok(())) | None => {
                                status.update_tunnel(id, TunnelStatus::Idle, String::new());
                            }
                        }
                        let _ = done_tx.send(id);
                    });
                }
                Ok(TunnelCommand::Stop(id)) => {
                    if let Some(token) = running.remove(&id) {
                        token.cancel();
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("Tunnel command channel lagged by {n}");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            Some(id) = done_rx.recv() => {
                running.remove(&id);
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

/// Authenticate as the listener.
async fn auth_as_listener(
    conn: &iroh::endpoint::Connection,
    auth_tokens: &HashSet<String>,
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
        let request = decode_auth_request(&request_bytes).context("Invalid auth request")?;

        if !is_token_valid(request.auth_token.as_str(), auth_tokens) {
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
    allowed_sources: Arc<AllowedSources>,
) -> Result<()> {
    let mut stream_tasks: JoinSet<()> = JoinSet::new();

    loop {
        let (send, recv) = conn
            .accept_bi()
            .await
            .context("accept_bi failed (connection closed)")?;

        let semaphore = semaphore.clone();
        let allowed_sources = allowed_sources.clone();
        stream_tasks.spawn(async move {
            if let Err(e) = handle_incoming_stream(send, recv, semaphore, allowed_sources).await {
                log::warn!("Stream error: {}", e);
            }
        });

        while stream_tasks.try_join_next().is_some() {}
    }
}

async fn handle_incoming_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    semaphore: Arc<Semaphore>,
    allowed_sources: Arc<AllowedSources>,
) -> Result<()> {
    let hello_bytes = tokio::time::timeout(HELLO_TIMEOUT, read_length_prefixed(&mut recv))
        .await
        .context("Timed out reading stream hello")?
        .context("Failed to read stream hello")?;
    let hello = decode_stream_hello(&hello_bytes).context("Invalid stream hello")?;

    match hello {
        StreamHello::LocalForward { source, .. } => {
            // Gate the requested source against our allowlist (fail-closed) before
            // committing a session permit or connecting out.
            let networks = if source.starts_with("udp://") {
                &allowed_sources.udp
            } else {
                &allowed_sources.tcp
            };
            if let Err(e) = check_source_allowed(&source, networks).await {
                log::warn!("Rejecting requested source: {}", e);
                let ack = StreamAck::rejected(e.to_string());
                let _ = send.write_all(&encode_stream_ack(&ack)?).await;
                let _ = send.finish();
                return Ok(());
            }
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

/// Connect out to `dest` and bridge it with the stream (acceptor / connect side).
async fn connect_side(
    mut send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    dest: &str,
) -> Result<()> {
    let is_tcp = dest.starts_with("tcp://");
    let is_udp = dest.starts_with("udp://");
    if !is_tcp && !is_udp {
        let ack = StreamAck::rejected("Invalid destination protocol (must be tcp:// or udp://)");
        send.write_all(&encode_stream_ack(&ack)?).await?;
        let _ = send.finish();
        anyhow::bail!("Invalid destination protocol: {}", dest);
    }

    let addr = extract_addr_from_source(dest)
        .ok_or_else(|| anyhow::anyhow!("Invalid destination URL: {}", dest))?;

    if is_tcp {
        let target_addrs = resolve_all_target_addrs(&addr).await?;
        match try_connect_tcp(&target_addrs).await {
            Ok(tcp_stream) => {
                send.write_all(&encode_stream_ack(&StreamAck::accepted())?)
                    .await?;
                log::info!("-> Connected to TCP {}", addr);
                bridge_streams(recv, send, tcp_stream).await?;
                log::info!("<- TCP connection to {} closed", addr);
            }
            Err(e) => {
                let ack = StreamAck::rejected(format!("connect failed: {}", e));
                send.write_all(&encode_stream_ack(&ack)?).await?;
                let _ = send.finish();
                anyhow::bail!("Failed to connect to TCP {}: {}", addr, e);
            }
        }
    } else {
        let target_addrs = Arc::new(resolve_all_target_addrs(&addr).await?);
        if target_addrs.is_empty() {
            anyhow::bail!("No target addresses resolved for '{}'", addr);
        }
        send.write_all(&encode_stream_ack(&StreamAck::accepted())?)
            .await?;
        log::info!("-> Forwarding UDP to {}", addr);
        forward_stream_to_udp_server(recv, send, target_addrs).await?;
        log::info!("<- UDP forwarding to {} closed", addr);
    }

    Ok(())
}

// ============================================================================
// Tunnel requests: opener / listen side
// ============================================================================

/// Run one tunnel request: bind the local `local_listen` address and, for each
/// incoming connection, open a stream asking the peer to connect out to
/// `remote_source`. Runs until the listener errors or the caller cancels it
/// (freeing the bound port).
async fn run_request(
    conn: Arc<iroh::endpoint::Connection>,
    req: RequestEntry,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
    id: TunnelId,
) -> Result<()> {
    let hello = StreamHello::local_forward(&req.remote_source);
    let listen_addrs = resolve_listen_addrs(&req.local_listen)
        .await
        .with_context(|| format!("Invalid request listen address '{}'", req.local_listen))?;

    if req.remote_source.starts_with("udp://") {
        let listen_addr = *listen_addrs
            .first()
            .context("No listen address resolved for request")?;
        let udp_socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind UDP listener on {}", listen_addr))?,
        );
        log::info!("Listening on UDP {} <- {}", listen_addr, req.remote_source);
        status.update_tunnel(id, TunnelStatus::Listening, listen_addr.to_string());
        udp_listen_side(&conn, hello, udp_socket).await
    } else {
        let listeners = bind_tcp_listeners(&listen_addrs, &req.remote_source).await?;
        status.update_tunnel(id, TunnelStatus::Listening, req.local_listen.clone());
        tcp_accept_and_tunnel(conn, listeners, hello, semaphore).await
    }
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
        accept_tasks.spawn(async move {
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
        });
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
        conn_tasks.spawn(async move {
            let _permit = permit;
            if let Err(e) = open_tcp_data_stream(&conn, hello, tcp_stream).await {
                log::warn!("Tunnel for {} failed: {}", peer, e);
            }
        });
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

/// Run the UDP listen side over a single stream: open it, send the hello, await
/// the ack, then forward packets both ways. `udp_socket` is a bound local socket.
async fn udp_listen_side(
    conn: &iroh::endpoint::Connection,
    hello: StreamHello,
    udp_socket: Arc<UdpSocket>,
) -> Result<()> {
    let (mut send, mut recv) = open_bi_with_retry(conn).await?;
    send.write_all(&encode_stream_hello(&hello)?).await?;
    expect_ack(&mut recv).await?;

    let peer_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    tokio::select! {
        r = forward_udp_to_stream(udp_socket.clone(), send, peer_addr.clone()) => {
            if let Err(e) = r {
                log::warn!("UDP -> stream error: {}", e);
            }
        }
        r = forward_stream_to_udp_client(recv, udp_socket, peer_addr) => {
            if let Err(e) = r {
                log::warn!("stream -> UDP error: {}", e);
            }
        }
    }
    Ok(())
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
        let status = AppState::new(role, false, LogBuffer::new(16), vec![], false, None);
        Arc::new(PeerConfig {
            role,
            peer_node_id: None,
            allowed_sources: AllowedSources::default(),
            autostart_requests: false,
            auth_token: token.to_string(),
            nostr_relays: vec![],
            nostr_discovery: false,
            nostr_identifier: None,
            report_endpoint_id: true,
            relay_urls: vec![],
            relay_only: false,
            dns_server: Some("none".to_string()),
            max_streams: None,
            transport: TransportTuning::default(),
            announce_endpoint: false,
            status,
        })
    }

    /// `split_serve_dial_config` keeps the serving allowlist + own name on an always-on
    /// listen half (which owns the reported node id), gives the dial half no fixed
    /// target, and shares one `AppState`.
    #[test]
    fn split_serve_dial_config_shapes_both_halves() {
        let status = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            vec![],
            true,
            Some("homelab".to_string()),
        );
        let both = PeerConfig {
            role: Role::Both,
            peer_node_id: None,
            allowed_sources: AllowedSources {
                tcp: vec!["10.0.0.0/8".to_string()],
                udp: vec![],
            },
            autostart_requests: true,
            auth_token: "tok".to_string(),
            nostr_relays: vec![],
            nostr_discovery: true,
            nostr_identifier: Some("homelab".to_string()),
            report_endpoint_id: true,
            relay_urls: vec![],
            relay_only: false,
            dns_server: Some("none".to_string()),
            max_streams: None,
            transport: TransportTuning::default(),
            announce_endpoint: false,
            status,
        };

        let (listen, dial) = split_serve_dial_config(&both);

        assert_eq!(listen.role, Role::Listen);
        assert_eq!(dial.role, Role::Dial);

        // Listen publishes under its own name and owns the reported node id.
        assert_eq!(listen.nostr_identifier.as_deref(), Some("homelab"));
        assert!(listen.report_endpoint_id);
        assert!(!listen.autostart_requests);
        assert_eq!(listen.allowed_sources.tcp, vec!["10.0.0.0/8".to_string()]);

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
        let status = AppState::new(Role::Both, false, LogBuffer::new(16), vec![], true, None);
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
            let _ = handle_connection(conn, server_cfg, test_semaphore(), false).await;
        });

        // Dialer side: the system under test.
        let client_conn = client_ep
            .connect(server_addr, ALPN)
            .await
            .expect("dial connect");
        let client_cfg = test_peer_config(Role::Dial, token);
        let client_status = client_cfg.status.clone();
        let client_task =
            tokio::spawn(handle_connection(client_conn, client_cfg, test_semaphore(), true));

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
            auth_as_listener(&conn, &accepted)
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
        let result = handle_connection(client_conn, client_cfg, test_semaphore(), true).await;

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
