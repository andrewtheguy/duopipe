//! Configuration file support for duopipe.
//!
//! A single symmetric peer config with all keys at the top level.
//!
//! Interactive runs always serve inbound peers, and the outbound dial target is
//! chosen later from the dashboard, not in the config. The optional `[tunnel]`
//! table is the single TCP forward this node can open over its outbound dial
//! session: it names a remote `host:port` source on the connected peer and a
//! local listener address where traffic is delivered. The seed is activated
//! interactively (nothing starts automatically). Once a connected peer passes
//! token auth it is trusted to request any `host:port` source from us (there is
//! no source allowlist). `validate()` checks address formats at parse time. The
//! single `auth_token` is the shared secret used by both sides.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

// ============================================================================
// Configuration Structures
// ============================================================================

/// Unified peer configuration. All keys live at the top level.
#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// The single TCP tunnel this node can open over its outbound dial session.
    /// Asks the connected peer to connect out to a remote `remote_source`
    /// (`host:port`); traffic is delivered to a local `local_listen` address.
    /// Activated interactively — nothing starts automatically. Optional: in
    /// configless (`quick`) mode it is set from the TUI instead.
    #[serde(default)]
    pub tunnel: Option<TunnelEntry>,
    pub relay_urls: Option<Vec<String>>,
    /// Force all traffic through the relay server (disables direct P2P).
    /// Requires at least one entry in `relay_urls`.
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,
    /// Maximum concurrent forwarded streams across all tunnels (default: 100).
    pub max_streams: Option<usize>,
    /// Path to a file containing the shared authentication token. This (or the
    /// `DUOPIPE_AUTH_TOKEN` env var) is the only way to supply a token; a fresh
    /// listening instance generates one if neither is set.
    pub auth_token_file: Option<PathBuf>,
    /// Expected fingerprint of the shared auth token (the first 8 hex digits of its
    /// SHA-256, as shown in the dashboard header and by `duopipe generate-auth-token`).
    /// REQUIRED in nostr
    /// mode. Whatever token is finally resolved — from `auth_token_file`, the
    /// `DUOPIPE_AUTH_TOKEN` env var, or pasted at the setup screen — must match this
    /// fingerprint, so a config written for one pairing cannot be accidentally run with
    /// another pairing's token. Case-insensitive.
    pub auth_token_fingerprint: Option<String>,
    /// This peer's short, memorable identifier for nostr discovery. Required in
    /// connect mode: a listener publishes its node id under this name, and a dialer
    /// types it to look the peer up — so several peers can share one auth token and
    /// still be reached individually. Must be ASCII letters, digits, and underscores
    /// only (see [`validate_name`]); it is used verbatim in the local state-file path.
    pub name: Option<String>,
    /// Nostr relay URLs used for node-id discovery (connect mode only). Absent ⇒ a
    /// built-in set of public relays (see `nostr_discovery::DEFAULT_NOSTR_RELAYS`).
    pub nostr_relay_urls: Option<Vec<String>>,
    /// Transport layer tuning (congestion control, buffer sizes).
    #[serde(default)]
    pub transport: TransportTuning,
}

/// The single TCP tunnel: ask the peer to connect out to `remote_source` and
/// deliver the traffic to a local listener bound at `local_listen`.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TunnelEntry {
    /// Remote origin on the peer to connect out to (`host:port`, TCP).
    pub remote_source: String,
    /// Local address to listen on (`host:port`) where traffic is delivered.
    pub local_listen: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// TOML config file on disk (connect mode).
    File,
    /// No config, defaults only
    None,
}

/// Congestion controller algorithm selection.
///
/// Controls how the QUIC connection manages congestion and adjusts sending rates.
/// Default is Cubic, which is the most widely tested algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionController {
    /// CUBIC - Default. Loss-based congestion control, widely deployed.
    /// Best for general internet conditions.
    #[default]
    Cubic,
    /// BBR (Bottleneck Bandwidth and RTT) - Model-based congestion control.
    /// May perform better on high-bandwidth, high-latency links.
    /// Experimental - may not be fair to Cubic/NewReno flows.
    Bbr,
    /// NewReno - Classic TCP-like congestion control.
    /// Most conservative, good for compatibility.
    #[serde(alias = "new_reno")]
    NewReno,
}

/// Default QUIC stream receive window size (64 MB).
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Default QUIC send window size (64 MB).
pub const DEFAULT_SEND_WINDOW: u32 = 64 * 1024 * 1024;

/// Transport tuning configuration for QUIC connections.
///
/// These settings affect performance and memory usage of the QUIC transport layer.
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransportTuning {
    /// Congestion controller algorithm (default: cubic).
    /// Options: cubic, bbr, newreno
    #[serde(default)]
    pub congestion_controller: CongestionController,

    /// QUIC stream receive window size in bytes (default: 67108864 = 64MB).
    /// Controls per-stream flow control. The connection receive window uses iroh's default.
    /// Valid range: 1024 to 67108864 (64MB).
    pub receive_window: Option<u32>,

    /// QUIC send window size in bytes (default: 67108864 = 64MB).
    /// Controls how much data can be sent before acknowledgment.
    /// Valid range: 1024 to 67108864 (64MB).
    pub send_window: Option<u32>,

    /// QUIC ACK-eliciting threshold: the number of ack-eliciting packets the
    /// peer may receive before it must send an ACK to us.
    ///
    /// This requests the peer to delay acknowledgements of the data *we* send,
    /// so it directly affects our own sender-side ACK clock. A larger value
    /// reduces ACK overhead but starves congestion control of feedback, which
    /// hurts bulk-sending endpoints. A value of 0 makes the peer ACK every
    /// packet.
    ///
    /// When unset, the ACK_FREQUENCY extension is left at iroh/quinn defaults
    /// (peer ACKs every other packet). Only set this if you have measured a
    /// benefit. Valid range: 0 to 65535.
    pub ack_eliciting_threshold: Option<u32>,
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate that a string is a strict bare `host:port` address. Accepts exactly one of:
/// an IPv4 literal (`127.0.0.1:8000`), a bracketed IPv6 literal (`[::1]:8000`), or a
/// DNS hostname (`host.example:8000`), each followed by a port in `1..=65535`.
///
/// Rejects URL-shaped values — a scheme like `tcp://`, a path, userinfo (`@`), a
/// query/fragment, or any whitespace — and bare (unbracketed) IPv6. A lenient
/// right-split used to wave these through (e.g. `tcp://127.0.0.1:8000` parsed as host
/// `tcp://127.0.0.1`), so the typo only surfaced as a connection reset at dial time;
/// catch it here instead.
fn validate_host_port(value: &str, field_name: &str) -> Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let invalid = |reason: &str| {
        anyhow::anyhow!(
            "{field_name} '{value}' is not a valid host:port ({reason}). Use a bare \
             address like 127.0.0.1:8000, [::1]:8000, or host.example:8000 — no scheme, \
             path, or spaces."
        )
    };

    if value.is_empty() {
        return Err(invalid("empty"));
    }
    // Reject URL syntax outright: scheme separators, paths, userinfo, query/fragment,
    // and any whitespace.
    if value.contains('/')
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.contains(char::is_whitespace)
    {
        return Err(invalid("contains scheme, path, userinfo, or whitespace"));
    }

    // Split host from port, then validate each.
    let (host, port_str, bracketed) = if let Some(rest) = value.strip_prefix('[') {
        // Bracketed IPv6: [addr]:port
        let close = rest
            .find(']')
            .ok_or_else(|| invalid("unterminated '[' in IPv6 address"))?;
        let host = &rest[..close];
        let port = rest[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| invalid("expected ':port' after ']'"))?;
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(invalid("invalid IPv6 address inside brackets"));
        }
        (host, port, true)
    } else {
        // Unbracketed: exactly one ':' separating host and port.
        let mut it = value.rsplitn(2, ':');
        let port = it.next().expect("rsplitn yields at least one element");
        let host = it.next().ok_or_else(|| invalid("missing port"))?;
        if host.contains(':') {
            return Err(invalid("bracket IPv6 addresses as [addr]:port"));
        }
        (host, port, false)
    };

    // Port: 1..=65535 (u16 rejects out-of-range and non-numeric; 0 is meaningless here).
    let port: u16 = port_str
        .parse()
        .map_err(|_| invalid("port must be a number in 1..=65535"))?;
    if port == 0 {
        return Err(invalid("port must be in 1..=65535"));
    }

    // Host: the bracketed branch already validated the IPv6 literal; otherwise it must
    // be an IPv4 literal or a DNS hostname.
    if bracketed {
        return Ok(());
    }
    if host.is_empty() {
        return Err(invalid("missing host"));
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    validate_hostname(host).map_err(|reason| invalid(&reason))?;
    Ok(())
}

/// Validate a DNS hostname: dot-separated labels, each 1–63 chars of ASCII letters,
/// digits, or `-` (not at a label edge), total length ≤ 253. Returns a short reason
/// string on failure so the caller can wrap it in the field-specific message.
fn validate_hostname(host: &str) -> std::result::Result<(), String> {
    if host.len() > 253 {
        return Err("hostname is longer than 253 characters".into());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("hostname has an empty label".into());
        }
        if label.len() > 63 {
            return Err("hostname label is longer than 63 characters".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("hostname label must not start or end with '-'".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("hostname may contain only letters, digits, '-', and '.'".into());
        }
    }
    Ok(())
}

/// Validate that a string is a well-formed URL whose scheme is in `allowed_schemes`
/// and that has a non-empty host. Used for the relay / DNS URL config fields, where a
/// bare hostname or a wrong/missing scheme is a common mistake — `relay_urls` fails
/// late at endpoint build, and a bad `nostr_relay_urls` entry is silently skipped, so
/// catch both here at parse time. `example` is shown in the error to demonstrate the
/// expected form.
fn validate_url(
    value: &str,
    field_name: &str,
    allowed_schemes: &[&str],
    example: &str,
) -> Result<()> {
    let invalid = |reason: &str| {
        anyhow::anyhow!(
            "{field_name} '{value}' is not a valid URL ({reason}). Expected a {} URL like {example}.",
            allowed_schemes.join("/")
        )
    };

    if value.is_empty() {
        return Err(invalid("empty"));
    }
    if value.contains(char::is_whitespace) {
        return Err(invalid("contains whitespace"));
    }
    let url = url::Url::parse(value).map_err(|e| invalid(&e.to_string()))?;
    if !allowed_schemes.contains(&url.scheme()) {
        return Err(invalid(&format!(
            "scheme must be one of {}",
            allowed_schemes.join("/")
        )));
    }
    match url.host_str() {
        Some(h) if !h.is_empty() => Ok(()),
        _ => Err(invalid("missing host")),
    }
}

/// Validate the single tunnel's address formats: both `remote_source` and
/// `local_listen` are bare `host:port`.
pub fn validate_tunnel_spec(tunnel: &TunnelEntry) -> Result<()> {
    validate_host_port(&tunnel.remote_source, "tunnel.remote_source")?;
    validate_host_port(&tunnel.local_listen, "tunnel.local_listen")?;
    Ok(())
}

/// Max length of a peer `name` (keeps the verbatim state-file path well under
/// filesystem limits).
const MAX_NAME_LEN: usize = 64;

/// Validate a nostr peer `name`: a non-empty identifier of ASCII letters, digits, and
/// underscores only. The charset makes it safe to use verbatim in the state-file path
/// and stable as a nostr lookup key.
pub fn validate_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() {
        anyhow::bail!("Peer `name` must not be empty");
    }
    if n.chars().count() > MAX_NAME_LEN {
        anyhow::bail!(
            "Peer `name` must be at most {MAX_NAME_LEN} characters, got {}",
            n.chars().count()
        );
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!(
            "Peer `name` may contain only ASCII letters, digits, and underscores (got {n:?})"
        );
    }
    Ok(())
}

/// Minimum QUIC window size (1 KB).
const MIN_WINDOW_SIZE: u32 = 1024;

/// Maximum QUIC window size (64 MB).
const MAX_WINDOW_SIZE: u32 = 64 * 1024 * 1024;

/// Maximum QUIC ACK-eliciting threshold (fits in a QUIC VarInt and stays sane).
const MAX_ACK_ELICITING_THRESHOLD: u32 = 65535;

/// Validate QUIC window size is within acceptable range (1024-67108864 bytes).
fn validate_window_size(size: u32, field_name: &str, section: &str) -> Result<()> {
    if size < MIN_WINDOW_SIZE {
        anyhow::bail!(
            "[{}] {} value {} is below minimum of {} bytes (1KB)",
            section,
            field_name,
            size,
            MIN_WINDOW_SIZE
        );
    }
    if size > MAX_WINDOW_SIZE {
        anyhow::bail!(
            "[{}] {} value {} exceeds maximum of {} bytes (64MB)",
            section,
            field_name,
            size,
            MAX_WINDOW_SIZE
        );
    }
    Ok(())
}

/// Validate TransportTuning window sizes if specified.
pub fn validate_transport_tuning(tuning: &TransportTuning, section: &str) -> Result<()> {
    if let Some(recv) = tuning.receive_window {
        validate_window_size(recv, "receive_window", section)?;
    }
    if let Some(send) = tuning.send_window {
        validate_window_size(send, "send_window", section)?;
    }
    if let Some(threshold) = tuning.ack_eliciting_threshold
        && threshold > MAX_ACK_ELICITING_THRESHOLD
    {
        anyhow::bail!(
            "[{}] ack_eliciting_threshold value {} exceeds maximum of {}",
            section,
            threshold,
            MAX_ACK_ELICITING_THRESHOLD
        );
    }
    Ok(())
}

// ============================================================================
// Config Accessor Methods
// ============================================================================

impl PeerConfig {
    /// Validate config structure and address formats.
    ///
    /// Note: the interactive dial target is entered from the dashboard, and the
    /// headless test role is resolved from env vars, so neither is part of the
    /// config or checked here.
    pub fn validate(&self) -> Result<()> {
        if let Some(tunnel) = &self.tunnel {
            validate_tunnel_spec(tunnel)?;
        }
        validate_transport_tuning(&self.transport, "transport")?;
        // A name is only required in connect mode (checked at startup), but if one is
        // set it must be a valid identifier — it is used verbatim in the state path.
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        // DNS server: the `"none"` sentinel disables discovery; otherwise it is an
        // HTTP(S) pkarr URL.
        if let Some(dns) = &self.dns_server
            && dns != "none"
        {
            validate_url(dns, "dns_server", &["http", "https"], "https://dns.example.com")?;
        }
        // iroh relay URLs are HTTP(S); nostr relay URLs are WebSocket (ws/wss).
        for relay in self.relay_urls.iter().flatten() {
            validate_url(relay, "relay_urls", &["http", "https"], "https://relay.example.com")?;
        }
        for relay in self.nostr_relay_urls.iter().flatten() {
            validate_url(relay, "nostr_relay_urls", &["ws", "wss"], "wss://relay.example.com")?;
        }

        Ok(())
    }
}

// ============================================================================
// Path Expansion
// ============================================================================

/// Expand tilde (~) in paths to the user's home directory.
///
/// - `~/...` expands to the user's home directory
/// - `~` alone expands to the home directory
/// - Other paths are returned unchanged
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    } else if path_str == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    path.to_path_buf()
}

// ============================================================================
// Config Loading
// ============================================================================

/// Load configuration from a TOML file.
fn load_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// The duopipe config/state directory (`~/.config/duopipe/`). Used for the peer
/// config file and for local state such as name-conflict flag files. `None` only if
/// the home directory cannot be determined.
pub fn duopipe_config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("duopipe"))
}

/// Resolve the default peer config path (~/.config/duopipe/peer.toml).
fn default_peer_config_path() -> Option<PathBuf> {
    duopipe_config_dir().map(|dir| dir.join("peer.toml"))
}

/// Resolve the path `load_peer_config` would read from: the tilde-expanded explicit
/// path, or the default location. Returned so the rename flow can persist a new
/// `name` back to the same file. `None` only when no path is given and the default
/// cannot be determined.
pub fn resolve_peer_config_path(path: Option<&Path>) -> Option<PathBuf> {
    match path {
        Some(p) => Some(expand_tilde(p)),
        None => default_peer_config_path(),
    }
}

/// Marker prefix for the nudge comment, so we only append it once.
const NAME_CONFLICT_COMMENT_MARKER: &str = "# duopipe-name-conflict:";

/// Best-effort, non-destructive nudge: append a comment to the peer config file
/// telling the user that `name` collided with another device and should be changed,
/// without ever altering the `name` value itself. Idempotent (skips if the marker is
/// already present). Used when the user resolves a name conflict by choosing
/// "rename". Returns an error only if the file cannot be read or written.
pub fn append_name_conflict_comment(path: &Path, name: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading config to add rename nudge: {}", path.display()))?;
    if content.contains(NAME_CONFLICT_COMMENT_MARKER) {
        return Ok(());
    }
    let mut text = content;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!(
        "\n{NAME_CONFLICT_COMMENT_MARKER} the name {name:?} was in use by another device.\n\
         # Change the `name` value to a unique identifier and restart to avoid the conflict.\n"
    ));
    std::fs::write(path, text)
        .with_context(|| format!("writing config to add rename nudge: {}", path.display()))
}

/// Load peer configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path (tilde-expanded)
/// - `path`: None loads from the default path (~/.config/duopipe/peer.toml)
pub fn load_peer_config(path: Option<&Path>) -> Result<PeerConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_peer_config_path().ok_or_else(|| {
            anyhow::anyhow!("Could not find default config path. Use -c to specify a config file.")
        })?,
    };
    load_config(&config_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_config(cfg: PeerConfig) -> PeerConfig {
        cfg
    }

    #[test]
    fn validate_name_accepts_alphanumeric_and_underscore() {
        for n in ["web1", "home_lab", "A1_b2", "  web1  ", "_", "X"] {
            assert!(validate_name(n).is_ok(), "should accept {n:?}");
        }
    }

    #[test]
    fn validate_name_rejects_other_chars_empty_and_too_long() {
        let too_long = "a".repeat(MAX_NAME_LEN + 1);
        for n in [
            "",
            "   ",
            "home-lab",
            "web 1",
            "web.1",
            "naïve",
            too_long.as_str(),
        ] {
            assert!(validate_name(n).is_err(), "should reject {n:?}");
        }
    }

    #[test]
    fn config_validate_rejects_malformed_name() {
        let cfg = PeerConfig {
            name: Some("home-lab".to_string()),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("underscores"), "was: {err}");
    }

    #[test]
    fn name_conflict_comment_is_appended_once_and_preserves_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer.toml");
        let original = "name = \"homelab\"\nmax_streams = 50\n";
        std::fs::write(&path, original).unwrap();

        append_name_conflict_comment(&path, "homelab").unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        // Original settings are untouched; the `name` value is not rewritten.
        assert!(after.starts_with(original), "original content preserved: {after}");
        assert!(after.contains(NAME_CONFLICT_COMMENT_MARKER));
        assert!(after.contains("\"homelab\""));

        // Idempotent: a second call does not append a duplicate comment.
        append_name_conflict_comment(&path, "homelab").unwrap();
        let after2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, after2, "second nudge is a no-op");
        assert_eq!(after2.matches(NAME_CONFLICT_COMMENT_MARKER).count(), 1);
    }

    #[test]
    fn parses_toml_config() {
        let toml = r#"
max_streams = 100

[tunnel]
remote_source = "127.0.0.1:5678"
local_listen = "127.0.0.1:15678"

[transport]
congestion_controller = "bbr"
receive_window = 67108864
"#;
        let cfg: PeerConfig = toml::from_str(toml).expect("config TOML should parse");
        assert_eq!(cfg.max_streams, Some(100));
        let tunnel = cfg.tunnel.as_ref().expect("a single tunnel");
        assert_eq!(tunnel.remote_source, "127.0.0.1:5678");
        assert_eq!(tunnel.local_listen, "127.0.0.1:15678");
        assert_eq!(
            cfg.transport.congestion_controller,
            CongestionController::Bbr
        );
        assert_eq!(cfg.transport.receive_window, Some(67108864));
        cfg.validate()
            .expect("config should validate");
    }

    #[test]
    fn rejects_tunnel_array() {
        // The multi-tunnel `[[tunnel]]` array no longer parses; only a single
        // `[tunnel]` table is accepted.
        let toml = r#"
[[tunnel]]
remote_source = "127.0.0.1:5678"
local_listen = "127.0.0.1:15678"
"#;
        assert!(
            toml::from_str::<PeerConfig>(toml).is_err(),
            "a [[tunnel]] array should fail to parse"
        );
    }

    #[test]
    fn rejects_remote_source_missing_port() {
        // Sources are bare host:port now; a value with no port is rejected.
        let cfg = peer_config(PeerConfig {
            tunnel: Some(TunnelEntry {
                remote_source: "127.0.0.1".into(),
                local_listen: "127.0.0.1:15678".into(),
            }),
            ..Default::default()
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_allowed_sources_key() {
        // The allowlist was removed; `[allowed_sources]` is now an unknown field.
        let toml = r#"
[allowed_sources]
tcp = ["127.0.0.0/8"]
"#;
        assert!(
            toml::from_str::<PeerConfig>(toml).is_err(),
            "[allowed_sources] should no longer parse"
        );
    }

    #[test]
    fn rejects_unknown_field() {
        // Any unknown top-level key (e.g. a removed `connect`) must now error.
        // Avoid unwrap_err so PeerConfig need not derive Debug (it holds secrets).
        let toml = "connect = \"dial\"\n";
        let err = match toml::from_str::<PeerConfig>(toml) {
            Ok(_) => panic!("expected unknown-field error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("connect"), "error was: {err}");
    }

    #[test]
    fn rejects_unknown_transport_field() {
        let toml = "[transport]\nrecieve_window = 1024\n"; // typo
        let err = match toml::from_str::<PeerConfig>(toml) {
            Ok(_) => panic!("expected unknown-field error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("recieve_window"), "error was: {err}");
    }

    #[test]
    fn validates_tunnel_address_formats() {
        let cfg = peer_config(PeerConfig {
            tunnel: Some(TunnelEntry {
                remote_source: "127.0.0.1:5678".into(),
                local_listen: "127.0.0.1:15678".into(),
            }),
            ..Default::default()
        });
        assert!(cfg.validate().is_ok());

        let bad_listen = peer_config(PeerConfig {
            tunnel: Some(TunnelEntry {
                remote_source: "127.0.0.1:5678".into(),
                local_listen: "127.0.0.1".into(), // missing port
            }),
            ..Default::default()
        });
        assert!(bad_listen.validate().is_err());
    }

    #[test]
    fn host_port_accepts_valid_forms() {
        for ok in [
            "127.0.0.1:8000",
            "0.0.0.0:1",
            "1.2.3.4:65535",
            "[::1]:8080",
            "[::]:443",
            "[2001:db8::1]:22",
            "localhost:8000",
            "host.example.com:443",
            "a-b.c:53",
        ] {
            assert!(
                validate_host_port(ok, "field").is_ok(),
                "expected '{ok}' to be accepted"
            );
        }
    }

    #[test]
    fn host_port_rejects_scheme_path_and_malformed() {
        for bad in [
            "tcp://127.0.0.1:8000", // scheme — the original bug
            "http://x/y:80",        // scheme + path
            "127.0.0.1:8000/path",  // trailing path
            "user@127.0.0.1:8000",  // userinfo
            "127.0.0.1:8000?x=1",   // query
            "127.0.0.1",            // missing port
            "127.0.0.1:",           // empty port
            "127.0.0.1:0",          // port 0
            "127.0.0.1:70000",      // port out of range
            "127.0.0.1:abc",        // non-numeric port
            "::1:8080",             // bare (unbracketed) IPv6
            "[::1]8080",            // missing ':' after ']'
            "[zzzz]:80",            // invalid IPv6 literal
            "host .example:80",     // whitespace
            "-bad.example:80",      // label starts with '-'
            ":8000",                // missing host
            "",                     // empty
        ] {
            assert!(
                validate_host_port(bad, "field").is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn url_validation_accepts_and_rejects() {
        // relay-style http(s)
        assert!(validate_url("https://relay.example.com", "f", &["http", "https"], "ex").is_ok());
        assert!(validate_url("http://127.0.0.1:8443", "f", &["http", "https"], "ex").is_ok());
        // nostr-style ws(s)
        assert!(validate_url("wss://nos.lol", "f", &["ws", "wss"], "ex").is_ok());

        for bad in [
            "relay.example.com",           // no scheme
            "wss://nos.lol",               // wrong scheme for an http field (below)
            "https://",                    // missing host
            "ftp://example.com",           // disallowed scheme
            "https://exa mple.com",        // whitespace
            "",                            // empty
            "not a url",                   // garbage
        ] {
            // Validate against the http/https allowlist; "wss://nos.lol" is rejected here.
            assert!(
                validate_url(bad, "f", &["http", "https"], "ex").is_err(),
                "expected '{bad}' to be rejected for http/https"
            );
        }
    }

    #[test]
    fn default_nostr_relays_validate() {
        // Guard against a typo in the built-in default relay set.
        let cfg = peer_config(PeerConfig {
            nostr_relay_urls: Some(
                crate::nostr_discovery::DEFAULT_NOSTR_RELAYS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            ..Default::default()
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_checks_relay_dns_fields() {
        // dns_server "none" sentinel is accepted; a bare host is rejected.
        let none_dns = peer_config(PeerConfig {
            dns_server: Some("none".into()),
            ..Default::default()
        });
        assert!(none_dns.validate().is_ok());

        let bad_dns = peer_config(PeerConfig {
            dns_server: Some("dns.example.com".into()), // no scheme
            ..Default::default()
        });
        assert!(bad_dns.validate().is_err());

        // A relay URL with the wrong scheme (ws:// where http(s) is expected) fails.
        let bad_relay = peer_config(PeerConfig {
            relay_urls: Some(vec!["wss://relay.example.com".into()]),
            ..Default::default()
        });
        assert!(bad_relay.validate().is_err());

        // A nostr relay with the wrong scheme (https:// where ws(s) is expected) fails.
        let bad_nostr = peer_config(PeerConfig {
            nostr_relay_urls: Some(vec!["https://relay.example.com".into()]),
            ..Default::default()
        });
        assert!(bad_nostr.validate().is_err());

        // Valid combination passes.
        let good = peer_config(PeerConfig {
            dns_server: Some("https://dns.example.com".into()),
            relay_urls: Some(vec!["https://relay.example.com".into()]),
            nostr_relay_urls: Some(vec!["wss://relay.example.com".into()]),
            ..Default::default()
        });
        assert!(good.validate().is_ok());
    }
}
