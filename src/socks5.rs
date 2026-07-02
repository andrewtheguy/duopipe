//! Local-edge SOCKS5 server (RFC 1928): method negotiation, CONNECT request
//! parsing, and reply writing. Only the no-auth method and the CONNECT command
//! are supported (TCP only — no BIND, no UDP ASSOCIATE).
//!
//! Domains are NOT resolved here — they ride the `StreamHello::SocksConnect`
//! to the remote peer and resolve there, so DNS happens on the peer's network.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

// SOCKS5 ATYP values (RFC 1928).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// SOCKS5 reply (REP) codes. The remote peer's connect outcome travels back as
// one of these in `StreamAck.rep` and is relayed verbatim to the local client.
// `REP_SUCCESS` documents the 0x00 code that `StreamAck::accepted()` carries.
#[allow(dead_code)]
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NET_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Parsed CONNECT target. `Domain` is unresolved — resolution happens on the
/// remote peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    /// The host as it should travel in the stream hello: an IP literal or the
    /// unresolved domain name.
    pub fn host(&self) -> String {
        match self {
            Target::Ip(addr) => addr.ip().to_string(),
            Target::Domain(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(addr) => addr.port(),
            Target::Domain(_, port) => *port,
        }
    }
}

/// Map a connect error to the SOCKS5 REP code the opener should relay.
pub fn rep_for_io_error(e: &io::Error) -> u8 {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => REP_CONN_REFUSED,
        NetworkUnreachable => REP_NET_UNREACHABLE,
        HostUnreachable => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    }
}

/// Perform the SOCKS5 greeting/method negotiation, selecting no-auth.
///
/// Reads `[VER, NMETHODS, METHODS..]`; if the client offers the no-auth method
/// replies `[0x05, 0x00]`, otherwise replies `[0x05, 0xFF]` and errors.
pub async fn negotiate_method<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<()> {
    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "unsupported SOCKS version: 0x{ver:02x}"
        )));
    }
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        Err(io::Error::other("client offered no acceptable SOCKS5 method"))
    }
}

/// Read and parse a SOCKS5 CONNECT request, returning the [`Target`].
///
/// On a non-CONNECT command or an unsupported address type, writes the matching
/// SOCKS5 reply to the client before returning an error.
pub async fn read_connect_request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> io::Result<Target> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [ver, cmd, rsv, atyp] = head;

    if ver != SOCKS_VERSION {
        return Err(io::Error::other(format!(
            "unsupported SOCKS version in request: 0x{ver:02x}"
        )));
    }
    if cmd != CMD_CONNECT {
        write_reply(stream, REP_CMD_NOT_SUPPORTED).await?;
        return Err(io::Error::other(format!(
            "unsupported SOCKS5 command: 0x{cmd:02x} (only CONNECT)"
        )));
    }
    // RSV is reserved and MUST be 0x00 (RFC 1928); reject a malformed request
    // before parsing the address.
    if rsv != 0x00 {
        write_reply(stream, REP_GENERAL_FAILURE).await?;
        return Err(io::Error::other(format!(
            "invalid SOCKS5 reserved byte: 0x{rsv:02x} (must be 0x00)"
        )));
    }

    let target = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Target::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            )))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Target::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            // A zero-length domain is malformed: reject it with a local failure reply before
            // constructing an empty `Target::Domain` or forwarding it to the remote resolver.
            if len == 0 {
                write_reply(stream, REP_GENERAL_FAILURE).await?;
                return Err(io::Error::other("SOCKS5 domain length is zero"));
            }
            let mut host = vec![0u8; len];
            stream.read_exact(&mut host).await?;
            let port = stream.read_u16().await?;
            match String::from_utf8(host) {
                Ok(host) => Target::Domain(host, port),
                Err(_) => {
                    write_reply(stream, REP_GENERAL_FAILURE).await?;
                    return Err(io::Error::other("SOCKS5 domain is not valid UTF-8"));
                }
            }
        }
        other => {
            write_reply(stream, REP_ATYP_NOT_SUPPORTED).await?;
            return Err(io::Error::other(format!(
                "unsupported SOCKS5 address type: 0x{other:02x}"
            )));
        }
    };

    // A domain (ATYP_DOMAIN) resolves on the remote peer; an IP means the
    // client pre-resolved locally. Destination logged only at debug so default
    // logs don't leak user destinations.
    match &target {
        Target::Domain(host, port) => {
            log::debug!("SOCKS5 CONNECT target {host}:{port} (remote DNS)");
        }
        Target::Ip(addr) => {
            log::debug!("SOCKS5 CONNECT target {addr} (client pre-resolved)");
        }
    }
    Ok(target)
}

/// Write a SOCKS5 reply to the local app: `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`.
///
/// We always report `BND = 0.0.0.0:0` (ATYP IPv4) — apps ignore the bound
/// address for CONNECT. `rep` is the code received from the remote peer.
pub async fn write_reply<S: AsyncWriteExt + Unpin>(stream: &mut S, rep: u8) -> io::Result<()> {
    // VER, REP, RSV, ATYP=IPv4, 0.0.0.0, port 0
    let reply = [SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn read_n(client: &mut (impl AsyncReadExt + Unpin), n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        client.read_exact(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn greeting_selects_no_auth() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        negotiate_method(&mut server).await.unwrap();
        assert_eq!(read_n(&mut client, 2).await, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn greeting_rejects_when_no_auth_not_offered() {
        let (mut client, mut server) = duplex(64);
        // Only username/password (0x02) offered.
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        assert!(negotiate_method(&mut server).await.is_err());
        assert_eq!(read_n(&mut client, 2).await, [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn greeting_rejects_bad_version() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        assert!(negotiate_method(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn connect_parses_ipv4() {
        let (mut client, mut server) = duplex(64);
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        let target = read_connect_request(&mut server).await.unwrap();
        assert_eq!(target, Target::Ip("127.0.0.1:80".parse().unwrap()));
        assert_eq!(target.host(), "127.0.0.1");
        assert_eq!(target.port(), 80);
    }

    #[tokio::test]
    async fn connect_parses_ipv6() {
        let (mut client, mut server) = duplex(64);
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let target = read_connect_request(&mut server).await.unwrap();
        assert_eq!(target, Target::Ip("[::1]:443".parse().unwrap()));
        assert_eq!(target.host(), "::1");
    }

    #[tokio::test]
    async fn connect_parses_domain() {
        let (mut client, mut server) = duplex(64);
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&8080u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let target = read_connect_request(&mut server).await.unwrap();
        assert_eq!(target, Target::Domain("localhost".into(), 8080));
    }

    #[tokio::test]
    async fn connect_rejects_zero_length_domain() {
        let (mut client, mut server) = duplex(64);
        // ATYP_DOMAIN with a zero length byte, then a port.
        client
            .write_all(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50])
            .await
            .unwrap();
        assert!(read_connect_request(&mut server).await.is_err());
        let reply = read_n(&mut client, 10).await;
        assert_eq!(reply[1], REP_GENERAL_FAILURE);
    }

    #[tokio::test]
    async fn connect_rejects_non_connect_command() {
        let (mut client, mut server) = duplex(64);
        // BIND (0x02)
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        assert!(read_connect_request(&mut server).await.is_err());
        let reply = read_n(&mut client, 10).await;
        assert_eq!(reply[1], REP_CMD_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn connect_rejects_bad_rsv() {
        let (mut client, mut server) = duplex(64);
        client
            .write_all(&[0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        assert!(read_connect_request(&mut server).await.is_err());
        let reply = read_n(&mut client, 10).await;
        assert_eq!(reply[1], REP_GENERAL_FAILURE);
    }

    #[tokio::test]
    async fn connect_rejects_unknown_atyp() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x05, 0x01, 0x00, 0x09]).await.unwrap();
        assert!(read_connect_request(&mut server).await.is_err());
        let reply = read_n(&mut client, 10).await;
        assert_eq!(reply[1], REP_ATYP_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn reply_layout() {
        let mut buf = Vec::new();
        write_reply(&mut buf, REP_HOST_UNREACHABLE).await.unwrap();
        assert_eq!(buf, [0x05, REP_HOST_UNREACHABLE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn io_error_mapping() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            rep_for_io_error(&Error::from(ErrorKind::ConnectionRefused)),
            REP_CONN_REFUSED
        );
        assert_eq!(
            rep_for_io_error(&Error::from(ErrorKind::HostUnreachable)),
            REP_HOST_UNREACHABLE
        );
        assert_eq!(
            rep_for_io_error(&Error::from(ErrorKind::NetworkUnreachable)),
            REP_NET_UNREACHABLE
        );
        assert_eq!(
            rep_for_io_error(&Error::from(ErrorKind::TimedOut)),
            REP_GENERAL_FAILURE
        );
    }
}
