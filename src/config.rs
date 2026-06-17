//! Configuration file support for duopipe.
//!
//! A single symmetric peer config:
//! - `mode` field for validation (mode only accepts "iroh")
//! - Mode-specific section: [iroh]
//!
//! `[iroh].connect` selects the connection role ("dial" or "listen"). Over one
//! established connection a peer can run many tunnels in both directions:
//! local forwards (`-L`, `[[iroh.local_forward]]`) and remote forwards
//! (`-R`, `[[iroh.remote_forward]]`). `validate()` checks required fields and
//! address formats at parse time.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

// ============================================================================
// Configuration Structures
// ============================================================================

/// iroh mode configuration for a symmetric peer.
#[derive(Deserialize, Default, Clone)]
pub struct IrohConfig {
    /// Connection role: "dial" (connect out to `peer_node_id`) or "listen" (accept).
    pub connect: Option<ConnectRole>,
    /// EndpointId of the peer to dial (required when `connect = "dial"`).
    pub peer_node_id: Option<String>,
    /// Local forwards (-L): this peer listens locally and forwards to the peer's `dest`.
    #[serde(default)]
    pub local_forward: Vec<LocalForward>,
    /// Remote forwards (-R): ask the peer to bind `bind` and forward back to our `dest`.
    #[serde(default)]
    pub remote_forward: Vec<RemoteForward>,
    /// Path to secret key file for persistent identity (required when listening).
    pub secret_file: Option<PathBuf>,
    /// Base64-encoded secret key for persistent identity.
    /// Prefer `secret_file` in production; inline secrets are best kept to testing or
    /// special cases due to VCS/log exposure risk. Secret files should be 0600 on Unix.
    pub secret: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub dns_server: Option<String>,
    /// Maximum concurrent data streams per connection (default: 100).
    pub max_sessions: Option<usize>,
    /// Authentication tokens accepted from dialing peers (used when listening).
    /// Prefer `auth_tokens_file` in production; inline tokens are best kept to testing or
    /// special cases due to VCS/log exposure risk.
    pub auth_tokens: Option<Vec<String>>,
    /// Path to file containing accepted authentication tokens (used when listening).
    /// One token per line, # comments allowed.
    pub auth_tokens_file: Option<PathBuf>,
    /// Authentication token presented to the peer (used when dialing).
    /// Prefer `auth_token_file` in production to avoid exposing tokens in config files.
    pub auth_token: Option<String>,
    /// Path to file containing the authentication token (used when dialing).
    pub auth_token_file: Option<PathBuf>,
    /// ALPN token for QUIC handshake-level filtering.
    /// Both peers must use the same token.
    pub alpn_token: Option<String>,
    /// Path to file containing the ALPN token.
    pub alpn_token_file: Option<PathBuf>,
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

impl IrohConfig {
    /// Reject plaintext sensitive fields when config is loaded from a file.
    ///
    /// Checked fields: `auth_token`, `auth_tokens`, `alpn_token`, `secret`.
    ///
    /// Age-encrypted values (detected by `ageenc:` prefix) are allowed through;
    /// they will be decrypted later via `decrypt_secrets()`.
    fn reject_plaintext_secrets(&self) -> Result<()> {
        use crate::encryption::is_age_encrypted;
        if self.auth_token.as_ref().is_some_and(|v| !is_age_encrypted(v)) {
            anyhow::bail!(
                "[iroh] Plaintext 'auth_token' is not allowed in config files. \
                 Use 'auth_token_file', set DUOPIPE_AUTH_TOKEN env var, \
                 or use an age-encrypted value. See: duopipe config-encryption encrypt-value --help"
            );
        }
        if self
            .auth_tokens
            .as_ref()
            .is_some_and(|vs| vs.iter().any(|v| !is_age_encrypted(v)))
        {
            anyhow::bail!(
                "[iroh] Plaintext 'auth_tokens' is not allowed in config files. \
                 Use 'auth_tokens_file', set DUOPIPE_AUTH_TOKENS env var, \
                 or use age-encrypted values. See: duopipe config-encryption encrypt-value --help"
            );
        }
        if self.alpn_token.as_ref().is_some_and(|v| !is_age_encrypted(v)) {
            anyhow::bail!(
                "[iroh] Plaintext 'alpn_token' is not allowed in config files. \
                 Use 'alpn_token_file', set DUOPIPE_ALPN_TOKEN env var, \
                 or use an age-encrypted value. See: duopipe config-encryption encrypt-value --help"
            );
        }
        if self.secret.as_ref().is_some_and(|v| !is_age_encrypted(v)) {
            anyhow::bail!(
                "[iroh] Plaintext 'secret' is not allowed in config files. \
                 Use 'secret_file', set DUOPIPE_SECRET env var, \
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
            .is_some_and(|v| is_age_encrypted(v))
            || self
                .alpn_token
                .as_ref()
                .is_some_and(|v| is_age_encrypted(v))
            || self.secret.as_ref().is_some_and(|v| is_age_encrypted(v))
            || self
                .auth_tokens
                .as_ref()
                .is_some_and(|vs| vs.iter().any(|v| is_age_encrypted(v)));

        if !has_encrypted {
            return Ok(());
        }

        let key_path = encryption_key_file.ok_or_else(|| {
            anyhow::anyhow!(
                "Age-encrypted values found but no encryption key file specified.\n\
                 Set [iroh].encryption_key_file in config, use --encryption-key-file, \
                 or set DUOPIPE_ENCRYPTION_KEY_FILE env var."
            )
        })?;

        if let Some(ref v) = self.auth_token
            && is_age_encrypted(v) {
                self.auth_token =
                    Some(decrypt_value(v, key_path).context("Failed to decrypt auth_token")?);
            }
        if let Some(ref v) = self.alpn_token
            && is_age_encrypted(v) {
                self.alpn_token =
                    Some(decrypt_value(v, key_path).context("Failed to decrypt alpn_token")?);
            }
        if let Some(ref v) = self.secret
            && is_age_encrypted(v) {
                self.secret =
                    Some(decrypt_value(v, key_path).context("Failed to decrypt secret")?);
            }
        if let Some(ref vs) = self.auth_tokens {
            let mut decrypted = Vec::with_capacity(vs.len());
            for (i, v) in vs.iter().enumerate() {
                if is_age_encrypted(v) {
                    decrypted.push(
                        decrypt_value(v, key_path)
                            .with_context(|| format!("Failed to decrypt auth_tokens[{}]", i))?,
                    );
                } else {
                    decrypted.push(v.clone());
                }
            }
            self.auth_tokens = Some(decrypted);
        }

        Ok(())
    }
}

/// Connection role: who establishes the QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectRole {
    /// Dial out to `peer_node_id`. Identity may be ephemeral.
    Dial,
    /// Accept incoming connections. Requires a stable secret.
    Listen,
}

/// Local forward (-L): this peer binds `listen` locally and the peer connects to `dest`.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct LocalForward {
    /// Local address to listen on (host:port).
    pub listen: String,
    /// Destination the peer connects to (tcp://host:port or udp://host:port).
    /// The scheme selects the protocol of the local listener.
    pub dest: String,
}

/// Remote forward (-R): ask the peer to bind `bind`, forwarding back to our local `dest`.
#[derive(Debug, Deserialize, Default, Clone)]
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
    /// JSON from stdin — all values allowed
    Stdin,
    /// No config, defaults only
    None,
}

/// Connection mode. Only iroh is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Iroh,
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

/// Unified peer configuration.
#[derive(Deserialize, Default)]
pub struct PeerConfig {
    // Validation field
    pub mode: Option<Mode>,

    // Mode-specific section
    pub iroh: Option<IrohConfig>,
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
    /// Get iroh config section.
    pub fn iroh(&self) -> Option<&IrohConfig> {
        self.iroh.as_ref()
    }

    /// Validate config structure and address formats.
    ///
    /// Note: the connection role (dial/listen) and its required fields
    /// (`peer_node_id` for dial, secret for listen) are resolved and enforced in
    /// `main.rs` after merging CLI/env overrides, since those can supply the values.
    pub fn validate(&self, source: ConfigSource) -> Result<()> {
        self.mode.context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\"",
        )?;

        if let Some(ref iroh) = self.iroh {
            if source == ConfigSource::File {
                iroh.reject_plaintext_secrets()?;
            }
            if iroh.secret.is_some() && iroh.secret_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'secret' or 'secret_file'.");
            }
            if iroh.auth_tokens.is_some() && iroh.auth_tokens_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'auth_tokens' or 'auth_tokens_file'.");
            }
            if iroh.auth_token.is_some() && iroh.auth_token_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'auth_token' or 'auth_token_file'.");
            }
            if iroh.alpn_token.is_some() && iroh.alpn_token_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'alpn_token' or 'alpn_token_file'.");
            }
            validate_forward_specs(&iroh.local_forward, &iroh.remote_forward)?;
            validate_transport_tuning(&iroh.transport, "iroh")?;
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

/// Parse configuration as JSON from a reader (e.g. stdin).
///
/// Uses `serde_json::Deserializer::from_reader` to parse exactly one JSON value
/// without calling `end()`, so it returns immediately after the closing `}`
/// without waiting for EOF. This leaves the rest of the stream unconsumed.
/// Times out after 30 seconds since this is intended for automation/IPC.
pub async fn parse_config_from_reader<T: for<'de> Deserialize<'de> + Send + 'static, R: std::io::Read + Send + 'static>(reader: R) -> Result<T> {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            let mut de = serde_json::Deserializer::from_reader(reader);
            T::deserialize(&mut de).context("Failed to parse JSON config from stdin")
        }),
    )
    .await
    .context("Timed out waiting for JSON config from stdin (30s)")? // timeout
    .context("Failed to read config from stdin")? // join error
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

    fn peer_config_with_iroh(iroh: IrohConfig) -> PeerConfig {
        PeerConfig {
            mode: Some(Mode::Iroh),
            iroh: Some(iroh),
        }
    }

    #[test]
    fn rejects_plaintext_auth_token_from_file() {
        let cfg = peer_config_with_iroh(IrohConfig {
            auth_token: Some("secret123".into()),
            ..Default::default()
        });
        let err = cfg.validate(ConfigSource::File).unwrap_err();
        assert!(err.to_string().contains("Plaintext 'auth_token'"));
    }

    #[test]
    fn allows_plaintext_auth_token_from_stdin() {
        let cfg = peer_config_with_iroh(IrohConfig {
            auth_token: Some("secret123".into()),
            ..Default::default()
        });
        assert!(cfg.validate(ConfigSource::Stdin).is_ok());
    }

    #[test]
    fn rejects_plaintext_auth_tokens_from_file() {
        let cfg = peer_config_with_iroh(IrohConfig {
            auth_tokens: Some(vec!["tok1".into()]),
            ..Default::default()
        });
        let err = cfg.validate(ConfigSource::File).unwrap_err();
        assert!(err.to_string().contains("Plaintext 'auth_tokens'"));
    }

    #[test]
    fn rejects_plaintext_alpn_token_from_file() {
        let cfg = peer_config_with_iroh(IrohConfig {
            alpn_token: Some("alpn123".into()),
            ..Default::default()
        });
        let err = cfg.validate(ConfigSource::File).unwrap_err();
        assert!(err.to_string().contains("Plaintext 'alpn_token'"));
    }

    #[test]
    fn rejects_plaintext_secret_from_file() {
        let cfg = peer_config_with_iroh(IrohConfig {
            secret: Some("base64secret".into()),
            ..Default::default()
        });
        let err = cfg.validate(ConfigSource::File).unwrap_err();
        assert!(err.to_string().contains("Plaintext 'secret'"));
    }

    #[test]
    fn allows_plaintext_secrets_from_stdin() {
        let cfg = peer_config_with_iroh(IrohConfig {
            auth_tokens: Some(vec!["tok1".into()]),
            alpn_token: Some("alpn123".into()),
            secret: Some("base64secret".into()),
            ..Default::default()
        });
        assert!(cfg.validate(ConfigSource::Stdin).is_ok());
    }

    const FAKE_AGE_ENCRYPTED: &str = "ageenc:YWdlLWVuY3J5cHRpb24=";

    #[test]
    fn allows_age_encrypted_secrets_from_file() {
        let cfg = peer_config_with_iroh(IrohConfig {
            auth_token: Some(FAKE_AGE_ENCRYPTED.into()),
            auth_tokens: Some(vec![FAKE_AGE_ENCRYPTED.into()]),
            alpn_token: Some(FAKE_AGE_ENCRYPTED.into()),
            secret: Some(FAKE_AGE_ENCRYPTED.into()),
            ..Default::default()
        });
        assert!(cfg.validate(ConfigSource::File).is_ok());
    }

    #[test]
    fn rejects_mixed_plaintext_age_auth_tokens_from_file() {
        let cfg = peer_config_with_iroh(IrohConfig {
            auth_tokens: Some(vec![FAKE_AGE_ENCRYPTED.into(), "plaintext".into()]),
            ..Default::default()
        });
        let err = cfg.validate(ConfigSource::File).unwrap_err();
        assert!(err.to_string().contains("Plaintext 'auth_tokens'"));
    }

    #[test]
    fn validates_forward_address_formats() {
        let cfg = peer_config_with_iroh(IrohConfig {
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
        assert!(cfg.validate(ConfigSource::Stdin).is_ok());

        let bad_listen = peer_config_with_iroh(IrohConfig {
            local_forward: vec![LocalForward {
                listen: "127.0.0.1".into(), // missing port
                dest: "tcp://127.0.0.1:5678".into(),
            }],
            ..Default::default()
        });
        assert!(bad_listen.validate(ConfigSource::Stdin).is_err());

        let bad_dest = peer_config_with_iroh(IrohConfig {
            local_forward: vec![LocalForward {
                listen: "127.0.0.1:15678".into(),
                dest: "127.0.0.1:5678".into(), // missing scheme
            }],
            ..Default::default()
        });
        assert!(bad_dest.validate(ConfigSource::Stdin).is_err());
    }

    #[test]
    fn decrypt_secrets_missing_key_returns_error() {
        let mut iroh = IrohConfig {
            auth_token: Some(FAKE_AGE_ENCRYPTED.into()),
            ..Default::default()
        };
        let err = iroh.decrypt_secrets(None).unwrap_err();
        assert!(err.to_string().contains("no encryption key file"));
    }
}
