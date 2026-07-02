//! Shared networking utilities for duopipe.

use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Delay between starting connection attempts (Happy Eyeballs style).
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Maximum attempts for opening QUIC streams
pub const STREAM_OPEN_MAX_ATTEMPTS: u32 = 3;

/// Base delay for exponential backoff (doubles each attempt)
pub const STREAM_OPEN_BASE_DELAY_MS: u64 = 100;

/// Maximum multiplier for exponential backoff to keep delays bounded.
/// With base delay of 100ms, this caps max delay at ~102 seconds.
pub const BACKOFF_MAX_MULTIPLIER: u64 = 1024;

/// TCP socket buffer target for local tunnel endpoints (4 MB).
pub const TCP_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;

// ============================================================================
// Address Ordering (Happy Eyeballs)
// ============================================================================

/// Interleave addresses for Happy Eyeballs style connection attempts.
/// Returns addresses with IPv6 preferred first, then alternates IPv4 and IPv6.
/// Preserves original counts and alternates until all addresses are consumed.
///
/// This implements RFC 8305 address sorting for dual-stack connections,
/// giving IPv6 a slight head start while still trying IPv4 quickly.
pub fn interleave_addresses(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let (ipv6, ipv4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().copied().partition(|a| a.is_ipv6());

    let mut ordered = Vec::with_capacity(addrs.len());
    let mut v6_iter = ipv6.into_iter();
    let mut v4_iter = ipv4.into_iter();

    // Interleave addresses: IPv6 first, then alternate
    loop {
        let v6 = v6_iter.next();
        let v4 = v4_iter.next();
        if let Some(addr) = v6 {
            ordered.push(addr);
        }
        if let Some(addr) = v4 {
            ordered.push(addr);
        }
        if v6.is_none() && v4.is_none() {
            break;
        }
    }
    ordered
}

// ============================================================================
// Address Ordering Helpers
// ============================================================================

/// Orders socket addresses by loopback preference.
///
/// If all addresses are loopback (127.x.x.x or ::1), sorts IPv4 before IPv6.
/// This is because most local services bind to 127.0.0.1 only, and macOS
/// resolves "localhost" to ::1 first, causing connection failures or 250ms delays.
///
/// For non-loopback addresses, preserves the original order to allow Happy Eyeballs
/// to work as designed (resolver typically returns IPv6 first per RFC 6724).
pub fn order_by_loopback_preference(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let is_loopback = addrs.iter().all(|a| a.ip().is_loopback());
    if is_loopback {
        let mut sorted = addrs;
        sorted.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        sorted
    } else {
        addrs
    }
}

// ============================================================================
// Address Resolution
// ============================================================================

// ============================================================================
// Happy Eyeballs TCP Connection
// ============================================================================

/// Try to connect to any of the given addresses using Happy Eyeballs algorithm (RFC 8305).
/// - For non-loopback: Prefers IPv6 addresses (tried first), interleaves with IPv4
/// - For loopback: Prefers IPv4 addresses (most local services bind to 127.0.0.1 only)
/// - Staggers connection attempts with a small delay
/// - Returns first successful connection, cancels remaining attempts
///
/// Note: For loopback addresses, IPv4 is preferred because most local services
/// bind to 127.0.0.1 only. This avoids the 250ms Happy Eyeballs delay when IPv6
/// fails on macOS (which returns ::1 before 127.0.0.1 by default).
pub async fn try_connect_tcp(addrs: &[SocketAddr]) -> Result<TcpStream> {
    use tokio::sync::mpsc;

    if addrs.is_empty() {
        anyhow::bail!("No addresses to connect to");
    }

    // Check if all addresses are loopback
    let is_loopback = addrs.iter().all(|a| a.ip().is_loopback());

    let ordered = if is_loopback {
        // For loopback, prefer IPv4 since most local services bind to 127.0.0.1.
        // This is self-contained and does not depend on caller's ordering.
        let mut sorted = addrs.to_vec();
        sorted.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        sorted
    } else {
        // For non-loopback, apply Happy Eyeballs: IPv6 first, interleaved with IPv4
        interleave_addresses(addrs)
    };

    // Channel for connection results
    let (tx, mut rx) =
        mpsc::channel::<(SocketAddr, Result<TcpStream, std::io::Error>)>(ordered.len());

    // Spawn staggered connection attempts
    let mut handles = Vec::with_capacity(ordered.len());
    for (i, addr) in ordered.into_iter().enumerate() {
        let tx = tx.clone();
        let delay = CONNECTION_ATTEMPT_DELAY * i as u32;
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let res = TcpStream::connect(addr).await;
            let _ = tx.send((addr, res)).await;
        }));
    }
    drop(tx);

    // Return the first successful connection
    let mut errors: Vec<String> = Vec::new();
    while let Some((addr, result)) = rx.recv().await {
        match result {
            Ok(stream) => {
                tune_tcp_stream(&stream);
                // Cancel outstanding tasks
                for handle in handles {
                    handle.abort();
                }
                return Ok(stream);
            }
            Err(e) => {
                log::debug!("Connection attempt to {} failed: {}", addr, e);
                errors.push(format!("{}: {}", addr, e));
            }
        }
    }

    anyhow::bail!(
        "Failed to connect to any address:\n  {}",
        errors.join("\n  ")
    );
}

/// Apply best-effort TCP options that help tunnel throughput and latency.
pub fn tune_tcp_stream(stream: &TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        log::debug!("Failed to enable TCP_NODELAY: {}", err);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "fuchsia",
        target_os = "cygwin",
    ))]
    if let Err(err) = stream.set_quickack(true) {
        log::debug!("Failed to enable TCP_QUICKACK: {}", err);
    }

    let socket = socket2::SockRef::from(stream);
    if let Err(err) = socket.set_recv_buffer_size(TCP_SOCKET_BUFFER_SIZE) {
        log::debug!("Failed to set TCP receive buffer: {}", err);
    }
    if let Err(err) = socket.set_send_buffer_size(TCP_SOCKET_BUFFER_SIZE) {
        log::debug!("Failed to set TCP send buffer: {}", err);
    }
}

// ============================================================================
// Exponential backoff helper
// ============================================================================

/// Retry an async operation with exponential backoff.
pub async fn retry_with_backoff<T, E, F, Fut>(
    mut operation: F,
    max_attempts: u32,
    base_delay_ms: u64,
) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempt = 0;
    loop {
        attempt += 1;
        match operation(attempt).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= max_attempts {
                    return Err(err);
                }
                let multiplier = 1_u64
                    .checked_shl(attempt.saturating_sub(1))
                    .unwrap_or(u64::MAX);
                let bounded = multiplier.min(BACKOFF_MAX_MULTIPLIER);
                let delay = Duration::from_millis(base_delay_ms.saturating_mul(bounded));
                tokio::time::sleep(delay).await;
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_loopback_addresses_prefer_ipv4() {
        // Simulate macOS resolver order: IPv6 first
        let addrs = vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080), // ::1
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080), // 127.0.0.1
        ];

        // All loopback, should prefer IPv4
        let is_loopback = addrs.iter().all(|a| a.ip().is_loopback());
        assert!(is_loopback);

        // Use the shared ordering helper
        let result = order_by_loopback_preference(addrs);

        // IPv4 should be first after sorting
        assert!(result[0].is_ipv4(), "IPv4 should be preferred for loopback");
        assert!(result[1].is_ipv6(), "IPv6 should be second for loopback");
    }

    #[test]
    fn test_non_loopback_addresses_preserve_order() {
        // Non-loopback addresses should preserve input order (no sorting)
        let addrs = vec![
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                80,
            ),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        ];

        let is_loopback = addrs.iter().all(|a| a.ip().is_loopback());
        assert!(!is_loopback);

        // Use the shared ordering helper
        let result = order_by_loopback_preference(addrs.clone());

        // Order should be preserved exactly (IPv6 still first, as input)
        assert_eq!(
            result, addrs,
            "Non-loopback addresses should preserve input order"
        );
        assert!(result[0].is_ipv6(), "First address should remain IPv6");
        assert!(result[1].is_ipv4(), "Second address should remain IPv4");
    }

    #[test]
    fn test_mixed_loopback_non_loopback_not_treated_as_loopback() {
        // If there's a mix, it's not pure loopback
        let addrs = [
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
        ];

        let is_loopback = addrs.iter().all(|a| a.ip().is_loopback());
        assert!(!is_loopback);
    }

    // =========================================================================
    // interleave_addresses tests (TCP Happy Eyeballs)
    // =========================================================================

    #[test]
    fn test_interleave_addresses_empty() {
        let result = interleave_addresses(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_interleave_addresses_only_ipv4() {
        let addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        ];
        let result = interleave_addresses(&addrs);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|a| a.is_ipv4()));
    }

    #[test]
    fn test_interleave_addresses_only_ipv6() {
        let addrs = vec![
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                8080,
            ),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                8080,
            ),
        ];
        let result = interleave_addresses(&addrs);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|a| a.is_ipv6()));
    }

    #[test]
    fn test_interleave_addresses_ipv6_first() {
        let v4_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let v4_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let v6_1 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let v6_2 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            8080,
        );

        // Input: v4, v4, v6, v6
        let addrs = vec![v4_1, v4_2, v6_1, v6_2];
        let result = interleave_addresses(&addrs);

        // Expected: v6, v4, v6, v4 (interleaved with IPv6 first)
        assert_eq!(result.len(), 4);
        assert!(result[0].is_ipv6(), "First should be IPv6");
        assert!(result[1].is_ipv4(), "Second should be IPv4");
        assert!(result[2].is_ipv6(), "Third should be IPv6");
        assert!(result[3].is_ipv4(), "Fourth should be IPv4");
    }

    #[test]
    fn test_interleave_addresses_unequal_counts() {
        let v4_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let v6_1 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let v6_2 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            8080,
        );
        let v6_3 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
            8080,
        );

        // Input: 1 IPv4, 3 IPv6
        let addrs = vec![v4_1, v6_1, v6_2, v6_3];
        let result = interleave_addresses(&addrs);

        // Expected: v6, v4, v6, v6 (all addresses consumed)
        assert_eq!(result.len(), 4);
        assert!(result[0].is_ipv6(), "First should be IPv6");
        assert!(result[1].is_ipv4(), "Second should be IPv4");
        assert!(result[2].is_ipv6(), "Third should be IPv6");
        assert!(result[3].is_ipv6(), "Fourth should be IPv6");
    }

    #[test]
    fn test_interleave_addresses_preserves_all() {
        let v4_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let v4_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8081);
        let v6_1 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8082,
        );

        let addrs = vec![v4_1, v4_2, v6_1];
        let result = interleave_addresses(&addrs);

        // All original addresses should be present
        assert_eq!(result.len(), 3);
        assert!(result.contains(&v4_1));
        assert!(result.contains(&v4_2));
        assert!(result.contains(&v6_1));
    }

}
