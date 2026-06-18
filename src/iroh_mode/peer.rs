//! Symmetric iroh peer: one connection, many tunnels in both directions.
//!
//! A peer either dials another peer (`Role::Dial`) or listens for one
//! (`Role::Listen`). Connection *setup* is asymmetric (QUIC needs a dialer
//! and an acceptor), but once a connection is established either side can open
//! streams, so tunnels flow both ways:
//!
//! - Local forward (`-L`): this peer binds a local listener and forwards each
//!   connection to a destination the *peer* connects out to.
//! - Remote forward (`-R`): this peer asks the *peer* to bind a listener and
//!   forward connections back to a destination *we* connect out to.
//!
//! Every non-auth stream begins with a [`StreamHello`] so the acceptor can route
//! it without positional assumptions. Trust model: once token auth passes, the
//! peer is fully trusted — there are no per-destination allowlists.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::app_state::{AppState, ConnStatus, Role, TunnelDir, TunnelRow, TunnelStatus};
use crate::auth::is_token_valid;
use crate::config::{LocalForward, RemoteForward, TransportTuning};
use crate::error::{ErrorCategory, TunnelError};
use crate::net::{
    bind_udp_for_targets, extract_addr_from_source, resolve_all_target_addrs, resolve_listen_addrs,
    try_connect_tcp, tune_tcp_stream,
};

use crate::iroh_mode::endpoint::{
    connect_to_server, create_client_endpoint, create_server_endpoint, validate_relay_only,
    watch_connection_paths, ALPN,
};
use crate::iroh_mode::helpers::{
    bridge_streams, forward_stream_to_udp_client, forward_stream_to_udp_server,
    forward_udp_to_stream, open_bi_with_retry,
};
use crate::signaling::{
    decode_auth_request, decode_auth_response, decode_remote_forward_request,
    decode_remote_forward_response, decode_stream_ack, decode_stream_hello, encode_auth_request,
    encode_auth_response, encode_remote_forward_request, encode_remote_forward_response,
    encode_stream_ack, encode_stream_hello, read_length_prefixed, AuthRequest, AuthResponse,
    RemoteForwardRequest, RemoteForwardResponse, StreamAck, StreamHello,
};

/// Default maximum concurrent data streams per connection.
const DEFAULT_MAX_SESSIONS: usize = 100;

/// Timeout for the authentication handshake.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading a stream's leading [`StreamHello`] (prevents a stalled
/// opener from holding a session permit indefinitely).
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading a [`StreamAck`] / [`RemoteForwardResponse`].
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection close code for authentication failure (invalid token).
const AUTH_FAILED_CODE: u32 = 1;

/// Connection close code for authentication timeout (no auth within deadline).
const AUTH_TIMEOUT_CODE: u32 = 2;

/// Maximum reconnect backoff for the dialing peer.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// Monotonic allocator for remote-forward tunnel ids (unique per requester).
static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);

/// Map of `tunnel_id -> destination URL` for remote forwards we requested.
type RemoteForwardMap = Arc<Mutex<HashMap<u64, String>>>;

/// Runtime configuration for a symmetric peer.
pub struct PeerConfig {
    /// Connection role (dial out or listen).
    pub role: Role,
    /// EndpointId of the peer to dial (required for `Dial`).
    pub peer_node_id: Option<EndpointId>,
    /// Local forwards (-L) hosted by this peer.
    pub local_forwards: Vec<LocalForward>,
    /// Remote forwards (-R) this peer requests from the other peer.
    pub remote_forwards: Vec<RemoteForward>,
    /// The shared auth token (presented when dialing, required when listening).
    /// **Sensitive - redacted in Debug.**
    pub auth_token: String,
    /// Iroh relay URLs.
    pub relay_urls: Vec<String>,
    /// Whether to force relay-only mode (disables direct P2P).
    pub relay_only: bool,
    /// Custom DNS server, or "none" to disable DNS discovery.
    pub dns_server: Option<String>,
    /// Maximum concurrent data streams (None = default).
    pub max_sessions: Option<usize>,
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
            .field("local_forwards", &self.local_forwards)
            .field("remote_forwards", &self.remote_forwards)
            .field("auth_token", &"[REDACTED]")
            .field("relay_urls", &self.relay_urls)
            .field("relay_only", &self.relay_only)
            .field("dns_server", &self.dns_server)
            .field("max_sessions", &self.max_sessions)
            .field("transport", &self.transport)
            .field("announce_endpoint", &self.announce_endpoint)
            .field("status", &"<present>")
            .finish()
    }
}

/// Run a symmetric peer: dial or listen, then serve tunnels in both directions.
pub async fn run_peer(config: PeerConfig) -> Result<()> {
    validate_relay_only(config.relay_only, &config.relay_urls)?;

    match config.role {
        Role::Listen => run_listen(config).await,
        Role::Dial => run_dial(config).await,
    }
}

// ============================================================================
// Listen role
// ============================================================================

async fn run_listen(config: PeerConfig) -> Result<()> {
    log::info!("Symmetric Peer - Listen Mode");
    log::info!("============================");

    let endpoint = create_server_endpoint(
        &config.relay_urls,
        config.relay_only,
        None,
        config.dns_server.as_deref(),
        ALPN,
        Some(&config.transport),
    )
    .await?;

    let endpoint_id = endpoint.id();
    config.status.set_endpoint_id(endpoint_id.to_string());
    config.status.set_auth_token(config.auth_token.clone());
    if config.announce_endpoint {
        // Non-interactive mode: surface both on stderr for a test harness.
        eprintln!("node_id: {endpoint_id}");
        eprintln!("auth_token: {}", config.auth_token);
    }
    log::info!("EndpointId: {}", endpoint_id);
    log::info!(
        "Connect to this instance with node id {} and the auth token shown above.",
        endpoint_id
    );
    log::info!("Waiting for peers to connect...");

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
        connection_tasks.spawn(async move {
            if let Err(e) = handle_connection(conn, config, false).await {
                log::warn!("Connection error for {}: {}", remote_id, e);
            }
        });
    }

    connection_tasks.shutdown().await;
    endpoint.close().await;
    log::info!("Peer (listen) stopped.");
    Ok(())
}

// ============================================================================
// Dial role
// ============================================================================

async fn run_dial(config: PeerConfig) -> Result<()> {
    let peer_id: EndpointId = config
        .peer_node_id
        .context("dial role requires peer_node_id")?;

    log::info!("Symmetric Peer - Dial Mode");
    log::info!("==========================");

    let endpoint = create_client_endpoint(
        &config.relay_urls,
        config.relay_only,
        config.dns_server.as_deref(),
        None,
        Some(&config.transport),
    )
    .await?;

    config.status.set_endpoint_id(endpoint.id().to_string());

    let shutdown = config.status.shutdown.clone();
    let config = Arc::new(config);
    let mut backoff = Duration::from_secs(1);

    loop {
        config.status.set_conn_status(ConnStatus::Connecting);
        let connect = tokio::select! {
            _ = shutdown.cancelled() => break,
            connect = connect_to_server(
                &endpoint,
                peer_id,
                &config.relay_urls,
                config.relay_only,
                ALPN,
            ) => connect,
        };

        match connect {
            Ok(conn) => {
                backoff = Duration::from_secs(1);
                config.status.set_conn_status(ConnStatus::Connected);
                log::info!("Connected to peer!");
                match handle_connection(conn, config.clone(), true).await {
                    Ok(()) => log::info!("Connection closed; will reconnect"),
                    Err(e) => {
                        // Auth failures are fatal — retrying with the same token is futile.
                        if e
                            .downcast_ref::<TunnelError>()
                            .is_some_and(|te| te.category == ErrorCategory::Auth)
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

        config
            .status
            .set_conn_status(ConnStatus::Reconnecting { backoff_secs: backoff.as_secs() });
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

async fn handle_connection(
    conn: iroh::endpoint::Connection,
    config: Arc<PeerConfig>,
    is_dialer: bool,
) -> Result<()> {
    let remote_id = conn.remote_id();

    // Phase 1: authenticate.
    if is_dialer {
        config.status.set_conn_status(ConnStatus::Authenticating);
        auth_as_dialer(&conn, &config.auth_token).await?;
        config.status.set_conn_status(ConnStatus::Connected);
    } else {
        let accepted: HashSet<String> =
            std::iter::once(config.auth_token.clone()).collect();
        auth_as_listener(&conn, &accepted).await?;
        config.status.add_peer(remote_id.to_string());
        log::info!("Peer {} authenticated successfully", remote_id);
    }

    seed_tunnel_rows(&config);

    let _path_watcher =
        watch_connection_paths(&conn, config.status.clone(), remote_id.to_string());

    let conn = Arc::new(conn);
    let max_sessions = config.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS);
    let semaphore = Arc::new(Semaphore::new(max_sessions));
    config.status.set_semaphore(semaphore.clone(), max_sessions);
    let rf_map: RemoteForwardMap = Arc::new(Mutex::new(HashMap::new()));

    let mut tasks: JoinSet<()> = JoinSet::new();

    // (a) Accept incoming streams (local-forward data from the peer, remote-forward
    //     data for tunnels we requested, and remote-forward control from the peer).
    {
        let conn = conn.clone();
        let semaphore = semaphore.clone();
        let rf_map = rf_map.clone();
        tasks.spawn(async move {
            if let Err(e) = accept_loop(conn, semaphore, rf_map).await {
                log::debug!("Accept loop ended: {}", e);
            }
        });
    }

    // (b) Our local-forward listeners (-L).
    for lf in &config.local_forwards {
        let conn = conn.clone();
        let semaphore = semaphore.clone();
        let lf = lf.clone();
        let status = config.status.clone();
        tasks.spawn(async move {
            if let Err(e) = run_local_forward(conn, lf.clone(), semaphore, status.clone()).await {
                status.update_tunnel(&lf.listen, TunnelStatus::Error, e.to_string());
                log::warn!("Local forward {} ended: {}", lf.listen, e);
            }
        });
    }

    // (c) Request remote forwards (-R) from the peer.
    if !config.remote_forwards.is_empty() {
        let conn = conn.clone();
        let forwards = config.remote_forwards.clone();
        let rf_map = rf_map.clone();
        let status = config.status.clone();
        tasks.spawn(async move {
            if let Err(e) = request_remote_forwards(conn, forwards, rf_map, status).await {
                log::warn!("Remote forward negotiation ended: {}", e);
            }
        });
    }

    // Run until the connection closes, then tear everything down.
    let reason = conn.closed().await;
    log::info!("Connection to {} closed: {}", remote_id, reason);
    if is_dialer {
        config.status.set_conn_status(ConnStatus::Closed);
    } else {
        config.status.remove_peer(&remote_id.to_string());
    }
    tasks.shutdown().await;
    Ok(())
}

/// Seed the TUI tunnel table from this peer's configured forwards.
fn seed_tunnel_rows(config: &PeerConfig) {
    let mut rows = Vec::new();
    for lf in &config.local_forwards {
        rows.push(TunnelRow {
            dir: TunnelDir::Local,
            key: lf.listen.clone(),
            spec: format!("{} -> {}", lf.listen, lf.dest),
            status: TunnelStatus::Pending,
            detail: String::new(),
        });
    }
    for rf in &config.remote_forwards {
        rows.push(TunnelRow {
            dir: TunnelDir::Remote,
            key: rf.bind.clone(),
            spec: format!("{} -> {}", rf.bind, rf.dest),
            status: TunnelStatus::Pending,
            detail: String::new(),
        });
    }
    config.status.set_tunnels(rows);
}

// ============================================================================
// Authentication
// ============================================================================

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
    rf_map: RemoteForwardMap,
) -> Result<()> {
    let mut stream_tasks: JoinSet<()> = JoinSet::new();

    loop {
        let (send, recv) = conn
            .accept_bi()
            .await
            .context("accept_bi failed (connection closed)")?;

        let conn = conn.clone();
        let semaphore = semaphore.clone();
        let rf_map = rf_map.clone();
        stream_tasks.spawn(async move {
            if let Err(e) = handle_incoming_stream(conn, send, recv, semaphore, rf_map).await {
                log::warn!("Stream error: {}", e);
            }
        });

        while stream_tasks.try_join_next().is_some() {}
    }
}

async fn handle_incoming_stream(
    conn: Arc<iroh::endpoint::Connection>,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    semaphore: Arc<Semaphore>,
    rf_map: RemoteForwardMap,
) -> Result<()> {
    let hello_bytes = tokio::time::timeout(HELLO_TIMEOUT, read_length_prefixed(&mut recv))
        .await
        .context("Timed out reading stream hello")?
        .context("Failed to read stream hello")?;
    let hello = decode_stream_hello(&hello_bytes).context("Invalid stream hello")?;

    match hello {
        StreamHello::LocalForward { dest, .. } => {
            let Some(permit) = acquire_or_reject(&semaphore, &mut send).await? else {
                return Ok(());
            };
            let _permit = permit;
            connect_side(send, recv, &dest).await
        }
        StreamHello::RemoteForwardData { tunnel_id, .. } => {
            let dest = rf_map.lock().await.get(&tunnel_id).cloned();
            let Some(dest) = dest else {
                let ack = StreamAck::rejected("Unknown tunnel_id");
                let _ = send.write_all(&encode_stream_ack(&ack)?).await;
                let _ = send.finish();
                anyhow::bail!("RemoteForwardData for unknown tunnel_id {}", tunnel_id);
            };
            let Some(permit) = acquire_or_reject(&semaphore, &mut send).await? else {
                return Ok(());
            };
            let _permit = permit;
            connect_side(send, recv, &dest).await
        }
        StreamHello::RemoteForwardControl { .. } => {
            host_remote_forwards(conn, send, recv, semaphore).await
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
        let udp_socket = Arc::new(
            bind_udp_for_targets(&target_addrs)
                .await
                .context("Failed to bind UDP socket")?,
        );
        send.write_all(&encode_stream_ack(&StreamAck::accepted())?)
            .await?;
        log::info!("-> Forwarding UDP to {}", addr);
        forward_stream_to_udp_server(recv, send, udp_socket, target_addrs).await?;
        log::info!("<- UDP forwarding to {} closed", addr);
    }

    Ok(())
}

// ============================================================================
// Local forwards (-L): opener / listen side
// ============================================================================

async fn run_local_forward(
    conn: Arc<iroh::endpoint::Connection>,
    lf: LocalForward,
    semaphore: Arc<Semaphore>,
    status: Arc<AppState>,
) -> Result<()> {
    let hello = StreamHello::local_forward(&lf.dest);
    let listen_addrs = resolve_listen_addrs(&lf.listen)
        .await
        .with_context(|| format!("Invalid local_forward listen address '{}'", lf.listen))?;

    if lf.dest.starts_with("udp://") {
        let listen_addr = *listen_addrs
            .first()
            .context("No listen address resolved for local forward")?;
        let udp_socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind UDP listener on {}", listen_addr))?,
        );
        log::info!("Listening on UDP {} -> {}", listen_addr, lf.dest);
        status.update_tunnel(&lf.listen, TunnelStatus::Listening, listen_addr.to_string());
        udp_listen_side(&conn, hello, udp_socket).await
    } else {
        let listeners = bind_tcp_listeners(&listen_addrs, &lf.dest).await?;
        status.update_tunnel(&lf.listen, TunnelStatus::Listening, String::new());
        tcp_accept_and_tunnel(conn, listeners, hello, semaphore).await
    }
}

// ============================================================================
// Remote forwards (-R): requester side
// ============================================================================

async fn request_remote_forwards(
    conn: Arc<iroh::endpoint::Connection>,
    forwards: Vec<RemoteForward>,
    rf_map: RemoteForwardMap,
    status: Arc<AppState>,
) -> Result<()> {
    let (mut send, mut recv) = open_bi_with_retry(&conn).await?;
    send.write_all(&encode_stream_hello(&StreamHello::remote_forward_control())?)
        .await?;

    for rf in &forwards {
        let tunnel_id = NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
        let scheme = if rf.bind.starts_with("udp://") {
            "udp"
        } else {
            "tcp"
        };
        let dest_url = format!("{}://{}", scheme, rf.dest);
        rf_map.lock().await.insert(tunnel_id, dest_url);

        let req = RemoteForwardRequest::new(tunnel_id, rf.bind.clone());
        send.write_all(&encode_remote_forward_request(&req)?).await?;

        let resp_bytes = tokio::time::timeout(ACK_TIMEOUT, read_length_prefixed(&mut recv))
            .await
            .context("Timed out waiting for remote forward response")?
            .context("Failed to read remote forward response")?;
        let resp = decode_remote_forward_response(&resp_bytes)
            .context("Invalid remote forward response")?;

        if resp.accepted {
            let bound = resp.bound_addr.as_deref().unwrap_or("?");
            status.update_tunnel(&rf.bind, TunnelStatus::Bound, bound.to_string());
            log::info!(
                "Remote forward established: peer binds {} -> our {} ({})",
                rf.bind,
                rf.dest,
                bound
            );
        } else {
            rf_map.lock().await.remove(&tunnel_id);
            let reason = resp.reason.as_deref().unwrap_or("Unknown");
            status.update_tunnel(&rf.bind, TunnelStatus::Rejected, reason.to_string());
            log::warn!("Remote forward rejected for {}: {}", rf.bind, reason);
        }
    }

    // Signal clean EOF on the control stream; data arrives on separate streams.
    let _ = send.finish();
    Ok(())
}

// ============================================================================
// Remote forwards (-R): host side
// ============================================================================

async fn host_remote_forwards(
    conn: Arc<iroh::endpoint::Connection>,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    loop {
        // Read the next request; a clean EOF ends the control stream.
        let req_bytes = match read_length_prefixed(&mut recv).await {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        let req =
            decode_remote_forward_request(&req_bytes).context("Invalid remote forward request")?;

        let resp = match start_hosted_listener(conn.clone(), req.tunnel_id, &req.bind, &semaphore)
            .await
        {
            Ok(bound) => RemoteForwardResponse::accepted(req.tunnel_id, Some(bound)),
            Err(e) => {
                log::warn!("Refusing remote forward bind {}: {}", req.bind, e);
                RemoteForwardResponse::rejected(req.tunnel_id, e.to_string())
            }
        };
        send.write_all(&encode_remote_forward_response(&resp)?)
            .await?;
    }
    Ok(())
}

/// Bind the listener requested by a remote forward and spawn its accept loop.
/// Returns the bound address. The spawned task self-terminates when the
/// connection closes, freeing the port.
async fn start_hosted_listener(
    conn: Arc<iroh::endpoint::Connection>,
    tunnel_id: u64,
    bind: &str,
    semaphore: &Arc<Semaphore>,
) -> Result<String> {
    let is_udp = bind.starts_with("udp://");
    let addr_str =
        extract_addr_from_source(bind).ok_or_else(|| anyhow::anyhow!("Invalid bind URL: {}", bind))?;
    let listen_addrs = resolve_listen_addrs(&addr_str).await?;
    let hello = StreamHello::remote_forward_data(tunnel_id);

    if is_udp {
        let listen_addr = *listen_addrs
            .first()
            .context("No listen address resolved for remote forward bind")?;
        let udp_socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("Failed to bind UDP listener on {}", listen_addr))?,
        );
        let bound = udp_socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| listen_addr.to_string());

        let conn_for_task = conn.clone();
        tokio::spawn(async move {
            tokio::select! {
                r = udp_listen_side(&conn_for_task, hello, udp_socket) => {
                    if let Err(e) = r {
                        log::warn!("Hosted UDP forward (tunnel {}) ended: {}", tunnel_id, e);
                    }
                }
                _ = conn_for_task.closed() => {}
            }
        });
        log::info!("Hosting remote forward: bound UDP {} (tunnel {})", bound, tunnel_id);
        Ok(bound)
    } else {
        let listeners = bind_tcp_listeners(&listen_addrs, bind).await?;
        let bound = listeners
            .first()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_else(|| addr_str.clone());

        let conn_for_task = conn.clone();
        let semaphore = semaphore.clone();
        tokio::spawn(async move {
            tokio::select! {
                r = tcp_accept_and_tunnel(conn_for_task.clone(), listeners, hello, semaphore) => {
                    if let Err(e) = r {
                        log::warn!("Hosted TCP forward (tunnel {}) ended: {}", tunnel_id, e);
                    }
                }
                _ = conn_for_task.closed() => {}
            }
        });
        log::info!("Hosting remote forward: bound TCP {} (tunnel {})", bound, tunnel_id);
        Ok(bound)
    }
}

// ============================================================================
// Shared listen-side helpers (used by both -L and hosted -R listeners)
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
