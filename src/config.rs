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
    /// nostr mode: a listener publishes its node id under this name, and a dialer
    /// types it to look the peer up — so several peers can share one auth token and
    /// still be reached individually. Must be ASCII letters, digits, and underscores
    /// only (see [`validate_name`]); it is used verbatim in the local state-file path.
    pub name: Option<String>,
    /// Nostr relay URLs used for node-id discovery (nostr mode only). Absent ⇒ a
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
    /// TOML config file on disk (nostr mode).
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

/// Validate that a string is a valid host:port address.
fn validate_host_port(value: &str, field_name: &str) -> Result<()> {
    if !value.contains(':') {
        anyhow::bail!(
            "{} '{}' missing port. Expected format: host:port",
            field_name,
            value
        );
    }

    // Use rsplitn to split from the right (handles IPv6 addresses like [::1]:8080)
    let parts: Vec<&str> = value.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "{} '{}' has invalid format. Expected format: host:port",
            field_name,
            value
        );
    }

    let port_str = parts[0];
    let host = parts[1];

    if host.is_empty() {
        anyhow::bail!("{} '{}' missing host", field_name, value);
    }

    port_str
        .parse::<u16>()
        .with_context(|| format!("{} '{}' has invalid port number", field_name, value))?;

    Ok(())
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
        // A name is only required in nostr mode (checked at startup), but if one is
        // set it must be a valid identifier — it is used verbatim in the state path.
        if let Some(name) = &self.name {
            validate_name(name)?;
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

}
