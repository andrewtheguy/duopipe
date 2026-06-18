//! Configuration file support for duopipe.
//!
//! A single symmetric peer config with all keys at the top level.
//!
//! The connection role is chosen interactively at startup (or via env vars for
//! tests), not in the config. Over one established connection a peer can run
//! many tunnels in both directions: local forwards (`-L`, `[[local_forward]]`)
//! and remote forwards (`-R`, `[[remote_forward]]`). `validate()` checks
//! address formats at parse time. The single `auth_token` is the shared secret
//! used by both sides.

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
    /// Local forwards (-L): this peer listens locally and forwards to the peer's `dest`.
    #[serde(default)]
    pub local_forward: Vec<LocalForward>,
    /// Remote forwards (-R): ask the peer to bind `bind` and forward back to our `dest`.
    #[serde(default)]
    pub remote_forward: Vec<RemoteForward>,
    pub relay_urls: Option<Vec<String>>,
    /// Force all traffic through the relay server (disables direct P2P).
    /// Requires at least one entry in `relay_urls`.
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,
    /// Maximum concurrent data streams per connection (default: 100).
    pub max_sessions: Option<usize>,
    /// The shared authentication token, used by both sides of the connection.
    /// Optional: when starting a fresh (listening) instance without one, a token
    /// is generated and shown in the TUI. Prefer `auth_token_file` or an
    /// age-encrypted value in production to avoid exposing it in config files.
    pub auth_token: Option<String>,
    /// Path to file containing the authentication token.
    pub auth_token_file: Option<PathBuf>,
    /// Path to age identity (private key) file for decrypting age-encrypted values.
    pub encryption_key_file: Option<PathBuf>,
    /// Age public key (recipient) for encrypting values in this config.
    /// Used by `encrypt-value --config`, not required for decryption.
    /// Accessed via separate minimal TOML parsing in the encrypt-value command.
    #[allow(dead_code)]
    pub encryption_recipient: Option<String>,
    /// Transport layer tuning (congestion control, buffer sizes).
    #[serde(default)]
    pub transport: TransportTuning,
}

impl PeerConfig {
    /// Reject a plaintext `auth_token` when config is loaded from a file.
    ///
    /// Age-encrypted values (detected by `ageenc:` prefix) are allowed through;
    /// they will be decrypted later via `decrypt_secrets()`.
    fn reject_plaintext_secrets(&self) -> Result<()> {
        use crate::encryption::is_age_encrypted;
        if self.auth_token.as_ref().is_some_and(|v| !is_age_encrypted(v)) {
            anyhow::bail!(
                "Plaintext 'auth_token' is not allowed in config files. \
                 Use 'auth_token_file', set DUOPIPE_AUTH_TOKEN env var, \
                 or use an age-encrypted value. See: duopipe config-encryption encrypt-value --help"
            );
        }
        Ok(())
    }

    /// Decrypt any age-encrypted fields in place.
    ///
    /// If no fields contain age-encrypted values, returns immediately.
    /// If encrypted fields are found but no key file is provided, returns an error.
    pub fn decrypt_secrets(&mut self, encryption_key_file: Option<&Path>) -> Result<()> {
        use crate::encryption::{decrypt_value, is_age_encrypted};

        let has_encrypted = self
            .auth_token
            .as_ref()
            .is_some_and(|v| is_age_encrypted(v));

        if !has_encrypted {
            return Ok(());
        }

        let key_path = encryption_key_file.ok_or_else(|| {
            anyhow::anyhow!(
                "Age-encrypted values found but no encryption key file specified.\n\
                 Set encryption_key_file in config \
                 or set DUOPIPE_ENCRYPTION_KEY_FILE env var."
            )
        })?;

        if let Some(ref v) = self.auth_token
            && is_age_encrypted(v) {
                self.auth_token =
                    Some(decrypt_value(v, key_path).context("Failed to decrypt auth_token")?);
            }

        Ok(())
    }
}

/// Local forward (-L): this peer binds `listen` locally and the peer connects to `dest`.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct LocalForward {
    /// Local address to listen on (host:port).
    pub listen: String,
    /// Destination the peer connects to (tcp://host:port or udp://host:port).
    /// The scheme selects the protocol of the local listener.
    pub dest: String,
}

/// Remote forward (-R): ask the peer to bind `bind`, forwarding back to our local `dest`.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RemoteForward {
    /// Address the peer should bind (tcp://host:port or udp://host:port).
    /// The scheme selects the protocol.
    pub bind: String,
    /// Our local destination to connect to (host:port).
    pub dest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// TOML file on disk — plaintext secrets rejected
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

/// Validate that a string is a valid tcp:// or udp:// URL with host and port.
fn validate_tcp_udp_url(value: &str, field_name: &str) -> Result<()> {
    let url = url::Url::parse(value).with_context(|| {
        format!(
            "Invalid {} '{}'. Expected format: tcp://host:port or udp://host:port",
            field_name, value
        )
    })?;

    let scheme = url.scheme();
    if scheme != "tcp" && scheme != "udp" {
        anyhow::bail!(
            "Invalid {} scheme '{}'. Must be 'tcp' or 'udp'",
            field_name,
            scheme
        );
    }

    if url.host_str().is_none() {
        anyhow::bail!("{} '{}' missing host", field_name, value);
    }

    if url.port().is_none() {
        anyhow::bail!("{} '{}' missing port", field_name, value);
    }

    Ok(())
}

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

/// Validate local- and remote-forward address formats.
/// Used for both config-file forwards and CLI `-L`/`-R` specs.
pub fn validate_forward_specs(
    local: &[LocalForward],
    remote: &[RemoteForward],
) -> Result<()> {
    for lf in local {
        validate_host_port(&lf.listen, "local_forward.listen")?;
        validate_tcp_udp_url(&lf.dest, "local_forward.dest")?;
    }
    for rf in remote {
        validate_tcp_udp_url(&rf.bind, "remote_forward.bind")?;
        validate_host_port(&rf.dest, "remote_forward.dest")?;
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
    /// Note: the connection role (dial/listen) and the target node id are
    /// resolved interactively at startup (or via env vars for tests), so they
    /// are not part of the config and not checked here.
    pub fn validate(&self, source: ConfigSource) -> Result<()> {
        let iroh = self;
        if source == ConfigSource::File {
            iroh.reject_plaintext_secrets()?;
        }
        if iroh.auth_token.is_some() && iroh.auth_token_file.is_some() {
            anyhow::bail!("Use only one of 'auth_token' or 'auth_token_file'.");
        }
        validate_forward_specs(&iroh.local_forward, &iroh.remote_forward)?;
        validate_transport_tuning(&iroh.transport, "transport")?;

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
        && let Some(home) = dirs::home_dir() {
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

/// Resolve the default peer config path (~/.config/duopipe/peer.toml).
fn default_peer_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("duopipe").join("peer.toml"))
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
    fn parses_toml_config() {
        let toml = r#"
max_sessions = 100

[[local_forward]]
listen = "127.0.0.1:15678"
dest = "tcp://127.0.0.1:5678"

[[remote_forward]]
bind = "tcp://0.0.0.0:6574"
dest = "127.0.0.1:6574"

[transport]
congestion_controller = "bbr"
receive_window = 67108864
"#;
        let cfg: PeerConfig = toml::from_str(toml).expect("config TOML should parse");
        assert_eq!(cfg.max_sessions, Some(100));
        assert_eq!(cfg.local_forward.len(), 1);
        assert_eq!(cfg.remote_forward.len(), 1);
        assert_eq!(
            cfg.transport.congestion_controller,
            CongestionController::Bbr
        );
        assert_eq!(cfg.transport.receive_window, Some(67108864));
        cfg.validate(ConfigSource::File).expect("config should validate");
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
    fn rejects_plaintext_auth_token_from_file() {
        let cfg = peer_config(PeerConfig {
            auth_token: Some("secret123".into()),
            ..Default::default()
        });
        let err = cfg.validate(ConfigSource::File).unwrap_err();
        assert!(err.to_string().contains("Plaintext 'auth_token'"));
    }

    const FAKE_AGE_ENCRYPTED: &str = "ageenc:YWdlLWVuY3J5cHRpb24=";

    #[test]
    fn allows_age_encrypted_secrets_from_file() {
        let cfg = peer_config(PeerConfig {
            auth_token: Some(FAKE_AGE_ENCRYPTED.into()),
            ..Default::default()
        });
        assert!(cfg.validate(ConfigSource::File).is_ok());
    }

    #[test]
    fn validates_forward_address_formats() {
        let cfg = peer_config(PeerConfig {
            local_forward: vec![LocalForward {
                listen: "127.0.0.1:15678".into(),
                dest: "tcp://127.0.0.1:5678".into(),
            }],
            remote_forward: vec![RemoteForward {
                bind: "tcp://0.0.0.0:6574".into(),
                dest: "127.0.0.1:6574".into(),
            }],
            ..Default::default()
        });
        assert!(cfg.validate(ConfigSource::File).is_ok());

        let bad_listen = peer_config(PeerConfig {
            local_forward: vec![LocalForward {
                listen: "127.0.0.1".into(), // missing port
                dest: "tcp://127.0.0.1:5678".into(),
            }],
            ..Default::default()
        });
        assert!(bad_listen.validate(ConfigSource::File).is_err());

        let bad_dest = peer_config(PeerConfig {
            local_forward: vec![LocalForward {
                listen: "127.0.0.1:15678".into(),
                dest: "127.0.0.1:5678".into(), // missing scheme
            }],
            ..Default::default()
        });
        assert!(bad_dest.validate(ConfigSource::File).is_err());
    }

    #[test]
    fn decrypt_secrets_missing_key_returns_error() {
        let mut iroh = PeerConfig {
            auth_token: Some(FAKE_AGE_ENCRYPTED.into()),
            ..Default::default()
        };
        let err = iroh.decrypt_secrets(None).unwrap_err();
        assert!(err.to_string().contains("no encryption key file"));
    }
}
