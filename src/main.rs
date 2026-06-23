//! duopipe
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.

mod app_state;
mod auth;
mod buffer;
mod config;
mod encryption;
mod error;
mod identity;
mod iroh_mode;
mod logging;
mod net;
mod peer_params;
mod signaling;
mod tui;

use crate::app_state::{AppState, Role};
use crate::error::{ErrorCategory, TunnelError};
use crate::peer_params::ResolvedPeer;
use crate::tui::TuiLaunch;
use ::iroh::EndpointId;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;

/// Capacity of the in-memory log ring buffer shown in the TUI.
const LOG_CAPACITY: usize = 2000;

use crate::config::{
    AllowedSources, ConfigSource, PeerConfig, expand_tilde, load_peer_config,
    validate_allowed_sources, validate_request_specs, validate_transport_tuning,
};
use crate::iroh_mode::endpoint::validate_relay_only;

#[derive(Parser)]
#[command(name = "duopipe")]
#[command(version)]
#[command(about = "Forward TCP/UDP traffic through iroh P2P connections")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a peer (interactive TUI): one connection, many tunnels both ways.
    ///
    /// On startup the TUI offers a choice between starting a new (listening)
    /// instance and connecting to an existing one. Listening generates an auth
    /// token if none is configured; connecting prompts for the existing
    /// instance's node id and, if not configured, its auth token. Forwards,
    /// relays, and other options come from the config file.
    Start {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/duopipe/peer.toml)
        #[arg(long)]
        default_config: bool,
    },
    /// Generate an authentication token
    ///
    /// The auth token is the shared secret presented by both sides. Store it with
    /// `auth_token_file`, an age-encrypted config `auth_token`, or
    /// DUOPIPE_AUTH_TOKEN. A fresh listening instance generates one automatically
    /// if none is provided.
    GenerateAuthToken {
        /// Number of tokens to generate (default: 1)
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
    /// Age encryption commands for config file secrets
    ConfigEncryption {
        #[command(subcommand)]
        action: ConfigEncryptionCommand,
    },
}

#[derive(Subcommand)]
enum ConfigEncryptionCommand {
    /// Generate an age encryption keypair
    ///
    /// Without --output, prints both keys to stdout. With --output, saves the
    /// private key to a file and prints the public key (recipient) to stdout.
    GenerateKey {
        /// Path where to save the age identity (private key) file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Overwrite existing file if it exists (requires --output)
        #[arg(long, requires = "output")]
        force: bool,
    },
    /// Encrypt a value for use in config files (reads plaintext from stdin)
    ///
    /// Outputs an `ageenc:` prefixed single-line string that can be used directly
    /// as a TOML config value.
    EncryptValue {
        /// Age recipient (public key, starts with "age1...")
        #[arg(short, long)]
        recipient: Option<String>,

        /// Config file to read encryption_recipient from (alternative to --recipient)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

fn env_var_opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn env_truthy(name: &str) -> bool {
    env_var_opt(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Resolve the shared auth token from env (`DUOPIPE_AUTH_TOKEN`), then config
/// `auth_token`, then `auth_token_file`. Validates the token's CRC when present.
/// Returns `None` when none is configured (a fresh listening instance will
/// generate one).
fn resolve_config_auth_token(cfg: &PeerConfig) -> Result<Option<String>> {
    let token = if let Some(t) = env_var_opt("DUOPIPE_AUTH_TOKEN") {
        Some(t)
    } else if let Some(t) = &cfg.auth_token {
        Some(t.clone())
    } else if let Some(file) = &cfg.auth_token_file {
        let expanded = expand_tilde(file);
        Some(auth::load_auth_token_from_file(&expanded)?)
    } else {
        None
    };

    if let Some(t) = &token {
        auth::validate_token(t).context(
            "Invalid auth token format. Generate a valid token with: duopipe generate-auth-token",
        )?;
    }
    Ok(token)
}

/// All test-only environment variables, read once behind the single
/// `DUOPIPE_TEST_MODE` gate. `None` ⇒ test mode is off and no other `DUOPIPE_*`
/// test var has any effect. This is the only place test-only env vars are read.
struct TestEnv {
    /// `DUOPIPE_PEER_NODE_ID`: present ⇒ Dial that id; absent ⇒ Listen.
    peer_node_id: Option<String>,
    /// `DUOPIPE_AUTOSTART_REQUESTS`: auto-start all requests once connected.
    autostart_requests: bool,
    /// `DUOPIPE_SECRET_KEY`: base64 iroh secret key to force a *stable* node id.
    /// Lets a test spawn two peers sharing one node id to exercise duplicate
    /// detection. Absent ⇒ ephemeral identity (the usual test behavior).
    secret_key: Option<String>,
}

impl TestEnv {
    /// Read the gate and, if set, every gated var.
    fn from_env() -> Option<Self> {
        if !env_truthy("DUOPIPE_TEST_MODE") {
            return None;
        }
        Some(TestEnv {
            peer_node_id: env_var_opt("DUOPIPE_PEER_NODE_ID"),
            autostart_requests: env_truthy("DUOPIPE_AUTOSTART_REQUESTS"),
            secret_key: env_var_opt("DUOPIPE_SECRET_KEY"),
        })
    }

    /// Resolve the role-dependent peer for this test run. Role is inferred from
    /// `peer_node_id`: present ⇒ Dial (parse the id), absent ⇒ Listen. The auth
    /// token comes from `config_auth_token` (already resolved/validated), or is
    /// generated for Listen. Evaluated before the peer starts so failures print
    /// plainly and exit.
    fn resolve_preset(
        &self,
        config_auth_token: Option<String>,
        allowed_sources: AllowedSources,
    ) -> Result<ResolvedPeer> {
        match &self.peer_node_id {
            Some(node) => {
                let id: EndpointId = node
                    .parse()
                    .map_err(|_| anyhow::anyhow!("DUOPIPE_PEER_NODE_ID is not a valid node id."))?;
                let auth_token = config_auth_token.context(
                    "Non-interactive dial requires an auth token. Set DUOPIPE_AUTH_TOKEN, auth_token_file, or an age-encrypted auth_token in the config.",
                )?;
                Ok(ResolvedPeer {
                    role: Role::Dial,
                    peer_node_id: Some(id),
                    auth_token,
                    token_generated: false,
                    allowed_sources,
                })
            }
            None => {
                let (auth_token, token_generated) = match config_auth_token {
                    Some(t) => (t, false),
                    None => {
                        let t = auth::generate_token();
                        // Printed before TUI init so non-interactive tests can capture it.
                        eprintln!("auth_token: {t}");
                        (t, true)
                    }
                };
                Ok(ResolvedPeer {
                    role: Role::Listen,
                    peer_node_id: None,
                    auth_token,
                    token_generated,
                    allowed_sources,
                })
            }
        }
    }
}

/// Resolve the optional *stable* iroh identity key. Precedence: the
/// `DUOPIPE_SECRET_KEY` test var wins (so tests can force a shared node id);
/// otherwise, only when a config file is in use, an `identity_file` is loaded
/// (or generated on first run). Configless/interactive runs get `None` ⇒
/// ephemeral identity (a fresh node id every run).
fn resolve_identity_key(
    cfg: &PeerConfig,
    source: ConfigSource,
    test_env: Option<&TestEnv>,
) -> Result<Option<::iroh::SecretKey>> {
    if let Some(s) = test_env.and_then(|t| t.secret_key.as_ref()) {
        return identity::parse_secret_key(s)
            .map(Some)
            .context("DUOPIPE_SECRET_KEY is not a valid base64 secret key");
    }
    if source == ConfigSource::File
        && let Some(path) = &cfg.identity_file
    {
        let expanded = expand_tilde(path);
        return identity::load_or_create_identity(&expanded).map(Some);
    }
    Ok(None)
}

/// Load peer config based on flags. Returns (config, source).
fn resolve_peer_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(PeerConfig, ConfigSource)> {
    if config.is_some() && default_config {
        anyhow::bail!("Only one of -c/--config or --default-config may be used");
    }

    if let Some(path) = config {
        Ok((load_peer_config(Some(&path))?, ConfigSource::File))
    } else if default_config {
        Ok((load_peer_config(None)?, ConfigSource::File))
    } else {
        Ok((PeerConfig::default(), ConfigSource::None))
    }
}

/// Run a peer headless (no TUI) for non-interactive test mode. Logs go to stderr
/// via the env logger; the in-memory `AppState` is still created (the runtime
/// writes status into it) but nothing renders it. Ctrl-C triggers a clean shutdown.
async fn run_peer_headless(
    resolved: ResolvedPeer,
    cfg: &PeerConfig,
    relay_urls: Vec<String>,
    relay_only: bool,
    autostart_requests: bool,
    secret_key: Option<::iroh::SecretKey>,
) -> Result<()> {
    let logs = logging::LogBuffer::new(LOG_CAPACITY);
    let state = AppState::new(
        resolved.role,
        resolved.token_generated,
        logs,
        cfg.request.clone(),
    );
    let peer_cfg = iroh_mode::PeerConfig {
        role: resolved.role,
        peer_node_id: resolved.peer_node_id,
        allowed_sources: resolved.allowed_sources.clone(),
        autostart_requests,
        auth_token: resolved.auth_token,
        secret_key,
        relay_urls,
        relay_only,
        dns_server: cfg.dns_server.clone(),
        max_streams: cfg.max_streams,
        transport: cfg.transport.clone(),
        announce_endpoint: true,
        status: state.clone(),
    };

    let mut runtime = tokio::spawn(iroh_mode::run_peer(peer_cfg));
    tokio::select! {
        r = &mut runtime => r.map_err(|e| anyhow::anyhow!("peer task failed: {e}"))?,
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down (Ctrl-C)…");
            state.shutdown.cancel();
            let _ = runtime.await;
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() {
    std::process::exit(run().await);
}

async fn run() -> i32 {
    match run_inner().await {
        Ok(()) => 0,
        Err(err) => {
            let code = err
                .downcast_ref::<TunnelError>()
                .map(|e| match e.category {
                    ErrorCategory::Config => 2,
                    ErrorCategory::Auth => 3,
                    ErrorCategory::Rejected => 4,
                    ErrorCategory::Duplicate => 5,
                    ErrorCategory::Connection => 10,
                    ErrorCategory::ConnectionLost => 11,
                })
                .unwrap_or(1);
            eprintln!("Error: {:#}", err);
            code
        }
    }
}

async fn run_inner() -> Result<()> {
    let args = Args::parse();
    let command = args.command;

    // The interactive `start` command renders a TUI and captures logs into a ring
    // buffer. In test mode — `DUOPIPE_TEST_MODE=1` — the peer runs headless with
    // no TUI, logging to stderr, so it needs no terminal. `DUOPIPE_TEST_MODE` is
    // the single gate for all test-only env vars. Every other command logs to the
    // console as usual.
    let test_env = TestEnv::from_env();
    let log_buffer = if matches!(&command, Command::Start { .. }) && test_env.is_none() {
        if !std::io::stdout().is_terminal() {
            return Err(TunnelError::config(anyhow::anyhow!(
                "duopipe start requires an interactive terminal (set DUOPIPE_TEST_MODE=1 for headless test mode)."
            ))
            .into());
        }
        Some(logging::init_tui_logger(LOG_CAPACITY).expect("logger not yet initialized"))
    } else {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .filter_module("duopipe", log::LevelFilter::Info)
            .try_init();
        None
    };

    match &command {
        Command::Start {
            config,
            default_config,
        } => {
            let (mut cfg, source) = resolve_peer_config(config.clone(), *default_config)?;

            if source != ConfigSource::None {
                cfg.validate(source).map_err(TunnelError::config)?;
            }

            // Decrypt age-encrypted values if present.
            let enc_key = env_var_opt("DUOPIPE_ENCRYPTION_KEY_FILE")
                .map(PathBuf::from)
                .or_else(|| cfg.encryption_key_file.clone())
                .map(|p| expand_tilde(&p));
            cfg.decrypt_secrets(enc_key.as_deref())?;

            // Requests, allowlist, relays, and transport now come from config only.
            validate_request_specs(&cfg.request).map_err(TunnelError::config)?;
            validate_allowed_sources(&cfg.allowed_sources).map_err(TunnelError::config)?;
            validate_transport_tuning(&cfg.transport, "transport").map_err(TunnelError::config)?;

            let relay_urls = cfg.relay_urls.clone().unwrap_or_default();
            let relay_only = cfg.relay_only.unwrap_or(false);
            validate_relay_only(relay_only, &relay_urls).map_err(TunnelError::config)?;

            // Resolve the shared auth token (env > config) before startup so
            // failures print plainly.
            let config_auth_token = resolve_config_auth_token(&cfg).map_err(TunnelError::config)?;

            // Resolve the optional stable identity key (config identity_file, or
            // the DUOPIPE_SECRET_KEY test var). None ⇒ ephemeral node id.
            let secret_key =
                resolve_identity_key(&cfg, source, test_env.as_ref()).map_err(TunnelError::config)?;

            // Test mode: resolve the preset and run headless, no TUI.
            // Interactive mode: hand off to the TUI lifecycle.
            if let Some(test_env) = &test_env {
                let resolved = test_env
                    .resolve_preset(config_auth_token, cfg.allowed_sources.clone())
                    .map_err(TunnelError::config)?;
                return run_peer_headless(
                    resolved,
                    &cfg,
                    relay_urls,
                    relay_only,
                    test_env.autostart_requests,
                    secret_key,
                )
                .await;
            }

            let log_buffer = log_buffer.expect("start command initializes the TUI log buffer");
            let launch = TuiLaunch {
                logs: log_buffer,
                requests: cfg.request.clone(),
                allowed_sources: cfg.allowed_sources.clone(),
                relay_urls,
                relay_only,
                dns_server: cfg.dns_server.clone(),
                max_streams: cfg.max_streams,
                transport: cfg.transport.clone(),
                config_auth_token,
                secret_key,
            };

            tui::run_tui(launch).await
        }
        Command::GenerateAuthToken { count } => {
            for _ in 0..*count {
                println!("{}", auth::generate_token());
            }
            Ok(())
        }
        Command::ConfigEncryption { action } => match action {
            ConfigEncryptionCommand::GenerateKey { output, force } => {
                let (secret_key, public_key) = encryption::generate_keypair();
                if let Some(path) = output {
                    let path = expand_tilde(path);
                    encryption::write_identity_file(&path, &secret_key, &public_key, *force)?;
                    log::info!("Encryption key saved to: {}", path.display());
                    println!("{}", public_key);
                } else {
                    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z");
                    println!("# created: {}", now);
                    println!("# public key: {}", public_key);
                    println!("{}", secret_key);
                }
                Ok(())
            }
            ConfigEncryptionCommand::EncryptValue { recipient, config } => {
                let recipient_str = match (recipient, config) {
                    (Some(_), Some(_)) => {
                        anyhow::bail!("Cannot combine --recipient and --config. Use only one.");
                    }
                    (Some(r), None) => r.clone(),
                    (None, Some(config_path)) => {
                        let expanded = expand_tilde(config_path);
                        let content = std::fs::read_to_string(&expanded).with_context(|| {
                            format!("Failed to read config: {}", expanded.display())
                        })?;

                        #[derive(serde::Deserialize)]
                        struct MinimalConfig {
                            encryption_recipient: Option<String>,
                        }

                        let cfg: MinimalConfig = toml::from_str(&content).with_context(|| {
                            format!("Failed to parse config: {}", expanded.display())
                        })?;
                        cfg.encryption_recipient.ok_or_else(|| {
                            anyhow::anyhow!(
                                "No encryption_recipient found in {}",
                                expanded.display()
                            )
                        })?
                    }
                    (None, None) => {
                        anyhow::bail!(
                            "Provide --recipient or --config to specify the age public key"
                        );
                    }
                };

                let mut plaintext = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut plaintext)
                    .context("Failed to read plaintext from stdin")?;
                let plaintext = plaintext.trim_end();
                if plaintext.is_empty() {
                    anyhow::bail!("No input provided on stdin");
                }

                let encrypted = encryption::encrypt_value(plaintext, &recipient_str)?;
                println!("{}", encrypted);
                Ok(())
            }
        },
    }
}
