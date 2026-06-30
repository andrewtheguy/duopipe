//! Shared helper functions for iroh-based tunnels.
//!
//! This module contains stream and connection helpers used by
//! iroh mode.

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use std::io::{self, IoSlice};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::net::{
    STREAM_OPEN_BASE_DELAY_MS, STREAM_OPEN_MAX_ATTEMPTS, retry_with_backoff, tune_tcp_stream,
};

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
