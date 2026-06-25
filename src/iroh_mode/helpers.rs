//! Shared helper functions for iroh-based tunnels.
//!
//! This module contains stream and connection helpers used by
//! iroh mode.

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::buffer::uninitialized_vec;
use crate::net::{
    STREAM_OPEN_BASE_DELAY_MS, STREAM_OPEN_MAX_ATTEMPTS, connect_udp_to_target,
    order_udp_addresses, retry_with_backoff, tune_tcp_stream,
};

/// Read exactly enough bytes to fill `read_buf` to its capacity from a QUIC
/// stream — our own `read_exact` over uninitialized memory.
///
/// The stock `RecvStream::read_exact` requires an initialized `&mut [u8]`, which
/// forces zeroing the buffer first. This reads through the `AsyncRead` impl into
/// a `ReadBuf::uninit` instead, skipping the memset. `read_buf`'s capacity bounds
/// the read, so frame boundaries are preserved (no over-read into the next
/// frame). Errors if the stream ends before the buffer is full.
async fn read_exact_uninit(
    stream: &mut iroh::endpoint::RecvStream,
    read_buf: &mut ReadBuf<'_>,
) -> Result<()> {
    while read_buf.remaining() > 0 {
        let before = read_buf.filled().len();
        poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, read_buf))
            .await
            .context("Failed to read frame payload")?;
        if read_buf.filled().len() == before {
            anyhow::bail!("QUIC stream ended mid-frame");
        }
    }
    Ok(())
}

// ============================================================================
// QUIC Stream Helpers
// ============================================================================

/// Open an iroh QUIC bidirectional stream with retry and exponential backoff.
pub(super) async fn open_bi_with_retry(
    conn: &iroh::endpoint::Connection,
) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    retry_with_backoff(
        |_| async {
            conn.open_bi()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to open QUIC stream: {}", e))
        },
        STREAM_OPEN_MAX_ATTEMPTS,
        STREAM_OPEN_BASE_DELAY_MS,
    )
    .await
}

/// Bridge a QUIC stream bidirectionally with a TCP stream.
pub(super) async fn bridge_streams(
    mut quic_recv: iroh::endpoint::RecvStream,
    mut quic_send: iroh::endpoint::SendStream,
    tcp_stream: TcpStream,
) -> Result<()> {
    tune_tcp_stream(&tcp_stream);
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Bridge both directions to completion (not `select!`, which would cancel one
    // direction the instant the other reaches EOF). With a half-close — e.g. a
    // client that sends a request then shuts down its write half — the TCP->QUIC
    // direction finishes first; cancelling QUIC->TCP there would drop the peer's
    // response before it arrives. Each direction independently signals EOF on its
    // output when its input ends, so half-open connections are preserved. The
    // halves are disjoint (tcp_read+quic_send vs quic_recv+tcp_write), so the two
    // futures never alias.
    let tcp_to_quic = async {
        let result = copy_tcp_to_quic(&mut tcp_read, &mut quic_send).await;
        // Tell the peer we're done sending so it can observe EOF and finish its
        // own response.
        let _ = quic_send.finish();
        result
    };
    let quic_to_tcp = async {
        let result = copy_quic_to_tcp(&mut quic_recv, &mut tcp_write).await;
        // Propagate EOF (FIN) to the local TCP peer once the QUIC side is done.
        let _ = tcp_write.shutdown().await;
        result
    };

    let (up, down) = tokio::join!(tcp_to_quic, quic_to_tcp);
    for result in [up, down] {
        if let Err(e) = result
            && !e.to_string().contains("reset")
        {
            log::warn!("bridge error: {}", e);
        }
    }

    Ok(())
}

const TCP_TO_QUIC_CHUNK_SIZE: usize = 256 * 1024;
const QUIC_TO_TCP_CHUNKS: usize = 64;

async fn copy_tcp_to_quic<R>(reader: &mut R, writer: &mut iroh::endpoint::SendStream) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    // Single-write-per-read: coalescing multiple reads into one large QUIC write
    // was measured to increase iperf3 retransmits by making the sender bursty.
    loop {
        let mut buf = BytesMut::with_capacity(TCP_TO_QUIC_CHUNK_SIZE);
        let read_len = reader
            .read_buf(&mut buf)
            .await
            .context("Failed to read from TCP stream")?;
        if read_len == 0 {
            break;
        }

        writer
            .write_chunk(buf.freeze())
            .await
            .context("Failed to write to QUIC stream")?;
    }

    Ok(())
}

async fn copy_quic_to_tcp<W>(reader: &mut iroh::endpoint::RecvStream, writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut chunks: [Bytes; QUIC_TO_TCP_CHUNKS] = std::array::from_fn(|_| Bytes::new());

    while let Some(chunk_count) = reader
        .read_many_chunks(&mut chunks)
        .await
        .context("Failed to read from QUIC stream")?
    {
        write_all_chunks_vectored(writer, &mut chunks[..chunk_count])
            .await
            .context("Failed to write to TCP stream")?;
    }

    writer.flush().await.context("Failed to flush TCP stream")?;
    Ok(())
}

async fn write_all_chunks_vectored<W>(writer: &mut W, chunks: &mut [Bytes]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut first = 0;

    while first < chunks.len() {
        while first < chunks.len() && chunks[first].is_empty() {
            first += 1;
        }
        if first == chunks.len() {
            break;
        }

        let slices: Vec<IoSlice<'_>> = chunks[first..]
            .iter()
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| IoSlice::new(chunk.as_ref()))
            .collect();

        let written = writer.write_vectored(&slices).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }

        let mut remaining = written;
        while remaining > 0 && first < chunks.len() {
            let chunk_len = chunks[first].len();
            if remaining >= chunk_len {
                remaining -= chunk_len;
                chunks[first] = Bytes::new();
                first += 1;
            } else {
                chunks[first].advance(remaining);
                break;
            }
        }
    }

    Ok(())
}

// ============================================================================
// UDP Stream Helpers
// ============================================================================

/// Read UDP packets from local socket and forward to iroh stream.
pub(super) async fn forward_udp_to_stream(
    udp_socket: Arc<UdpSocket>,
    mut send_stream: iroh::endpoint::SendStream,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let mut storage = uninitialized_vec(65535);

    loop {
        let mut read_buf = ReadBuf::uninit(&mut storage);
        let addr = poll_fn(|cx| udp_socket.poll_recv_from(cx, &mut read_buf))
            .await
            .context("Failed to receive UDP packet")?;
        let data = read_buf.filled();
        let len = data.len();

        *peer_addr.lock().await = Some(addr);

        let frame_len = (len as u16).to_be_bytes();
        send_stream
            .write_all(&frame_len)
            .await
            .context("Failed to write frame length")?;
        send_stream
            .write_all(data)
            .await
            .context("Failed to write frame payload")?;

        log::debug!("-> Forwarded {} bytes from {}", len, addr);
    }
}

/// Read from iroh stream, forward to UDP target, and send responses back (server mode).
///
/// Supports multiple target addresses with fallback:
/// - Addresses are tried in Happy Eyeballs order (IPv6 first)
/// - On send error, falls back to the next address
/// - Aggregates errors if all addresses fail
pub(super) async fn forward_stream_to_udp_server(
    mut recv_stream: iroh::endpoint::RecvStream,
    send_stream: iroh::endpoint::SendStream,
    target_addrs: Arc<Vec<SocketAddr>>,
) -> Result<()> {
    if target_addrs.is_empty() {
        anyhow::bail!("No target addresses provided for UDP forwarding");
    }

    // Order addresses for connection attempts
    let ordered_addrs = order_udp_addresses(&target_addrs);
    let (response_tx, response_rx) = mpsc::channel::<Bytes>(32);
    let writer_task = tokio::spawn(crate::logging::inherit_source(
        write_udp_responses_to_stream(send_stream, response_rx),
    ));

    let mut active_session: Option<UdpTargetSession> = None;
    let mut active_addr_idx = 0;
    let mut logged_active = false;
    let mut storage = uninitialized_vec(u16::MAX as usize);

    while let Some(payload) = read_next_udp_frame(&mut recv_stream, &mut storage).await? {
        let len = payload.len();

        // Try to send to current address, falling back on error
        let mut sent = false;
        let mut errors: Vec<(SocketAddr, String)> = Vec::new();
        while active_addr_idx < ordered_addrs.len() {
            let target_addr = ordered_addrs[active_addr_idx];
            if active_session
                .as_ref()
                .is_none_or(|session| session.addr != target_addr)
            {
                active_session = match UdpTargetSession::connect(
                    target_addr,
                    response_tx.clone(),
                )
                .await
                {
                    Ok(session) => Some(session),
                    Err(e) => {
                        log::warn!("UDP connect to {} failed: {}", target_addr, e);
                        errors.push((target_addr, e.to_string()));
                        active_addr_idx += 1;
                        logged_active = false;
                        continue;
                    }
                };
            }

            let session = active_session
                .as_ref()
                .expect("active UDP target session should exist");
            match session.socket.send(&payload).await {
                Ok(_) => {
                    if !logged_active {
                        if active_addr_idx > 0 {
                            log::info!(
                                "UDP fallback: using {} after {} failed address(es)",
                                target_addr,
                                active_addr_idx
                            );
                        }
                        logged_active = true;
                    }
                    log::debug!("<- Forwarded {} bytes to {}", len, target_addr);
                    sent = true;
                    break;
                }
                Err(e) => {
                    log::warn!("UDP send to {} failed: {}", target_addr, e);
                    errors.push((target_addr, e.to_string()));
                    active_session = None;
                    active_addr_idx += 1;
                    logged_active = false;
                }
            }
        }

        if !sent {
            // All addresses failed for this packet; reset so the next packet retries from the start.
            if active_addr_idx >= ordered_addrs.len() {
                active_addr_idx = 0;
                logged_active = false;
            }
            if errors.len() == 1 {
                let (addr, e) = errors.remove(0);
                log::warn!("Failed to send UDP packet to {}: {}", addr, e);
            } else if !errors.is_empty() {
                let error_details: Vec<String> = errors
                    .iter()
                    .map(|(addr, e)| format!("{}: {}", addr, e))
                    .collect();
                log::warn!(
                    "Failed to send UDP packet to any address:\n  {}",
                    error_details.join("\n  ")
                );
            } else {
                log::warn!("Failed to send UDP packet: no target addresses available");
            }
        }
    }

    drop(active_session);
    drop(response_tx);
    match writer_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("UDP response writer error: {}", e),
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("UDP response writer task failed: {}", e),
    }
    Ok(())
}

struct UdpTargetSession {
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    response_task: JoinHandle<()>,
}

impl UdpTargetSession {
    async fn connect(addr: SocketAddr, response_tx: mpsc::Sender<Bytes>) -> Result<Self> {
        let socket = Arc::new(connect_udp_to_target(addr).await?);
        let response_task = spawn_udp_response_task(socket.clone(), addr, response_tx);
        Ok(Self {
            addr,
            socket,
            response_task,
        })
    }
}

impl Drop for UdpTargetSession {
    fn drop(&mut self) {
        self.response_task.abort();
    }
}

async fn read_next_udp_frame(
    recv_stream: &mut iroh::endpoint::RecvStream,
    storage: &mut [MaybeUninit<u8>],
) -> Result<Option<Bytes>> {
    let mut len_buf = [0u8; 2];
    match recv_stream.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(iroh::endpoint::ReadExactError::FinishedEarly(_)) => {
            // Clean EOF - stream finished at frame boundary
            return Ok(None);
        }
        Err(e) => {
            log::warn!("Failed to read frame length: {}", e);
            return Ok(None);
        }
    }
    let len = u16::from_be_bytes(len_buf) as usize;

    let mut read_buf = ReadBuf::uninit(&mut storage[..len]);
    read_exact_uninit(recv_stream, &mut read_buf).await?;
    Ok(Some(Bytes::copy_from_slice(read_buf.filled())))
}

fn spawn_udp_response_task(
    socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
    response_tx: mpsc::Sender<Bytes>,
) -> JoinHandle<()> {
    tokio::spawn(crate::logging::inherit_source(async move {
        let mut storage = uninitialized_vec(65535);
        loop {
            let mut read_buf = ReadBuf::uninit(&mut storage);
            if let Err(e) = poll_fn(|cx| socket.poll_recv(cx, &mut read_buf)).await {
                log::warn!("UDP receive from {} failed: {}", target_addr, e);
                break;
            }
            let data = read_buf.filled();
            if response_tx
                .send(Bytes::copy_from_slice(data))
                .await
                .is_err()
            {
                break;
            }
            log::debug!("-> Sent {} bytes back to client from {}", data.len(), target_addr);
        }
    }))
}

async fn write_udp_responses_to_stream(
    mut send_stream: iroh::endpoint::SendStream,
    mut response_rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    while let Some(data) = response_rx.recv().await {
        let frame_len = (data.len() as u16).to_be_bytes();
        send_stream
            .write_all(&frame_len)
            .await
            .context("Failed to write UDP response frame length")?;
        send_stream
            .write_all(&data)
            .await
            .context("Failed to write UDP response frame payload")?;
        log::debug!("-> Sent {} bytes back to client", data.len());
    }

    Ok(())
}

/// Read from iroh stream and forward to local UDP client (client mode).
pub(super) async fn forward_stream_to_udp_client(
    mut recv_stream: iroh::endpoint::RecvStream,
    udp_socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let mut storage = uninitialized_vec(u16::MAX as usize);
    loop {
        let mut len_buf = [0u8; 2];
        match recv_stream.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(iroh::endpoint::ReadExactError::FinishedEarly(_)) => {
                // Clean EOF - stream finished at frame boundary
                break;
            }
            Err(e) => {
                log::warn!("Failed to read frame length: {}", e);
                break;
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut read_buf = ReadBuf::uninit(&mut storage[..len]);
        read_exact_uninit(&mut recv_stream, &mut read_buf).await?;
        let payload = read_buf.filled();

        if let Some(addr) = *client_addr.lock().await {
            udp_socket
                .send_to(payload, addr)
                .await
                .context("Failed to send UDP packet to client")?;
            log::debug!("<- Forwarded {} bytes to client {}", len, addr);
        } else {
            log::debug!("<- Received {} bytes but no client connected yet", len);
        }
    }

    Ok(())
}
