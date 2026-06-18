//! duopipe
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.

mod app_state;
mod auth;
mod buffer;
mod config;
mod encryption;
mod error;
mod iroh_mode;
mod logging;
mod net;
mod peer_params;
mod signaling;
mod tui;

use ::iroh::EndpointId;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;
use crate::app_state::Role;
use crate::error::{ErrorCategory, TunnelError};
use crate::peer_params::ResolvedPeer;
use crate::tui::TuiLaunch;

/// Capacity of the in-memory log ring buffer shown in the TUI.
const LOG_CAPACITY: usize = 2000;

use crate::config::{
    expand_tilde, load_peer_config, validate_forward_specs, validate_transport_tuning,
    ConfigSource, PeerConfig,
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
    /// Run a peer (interactive TUI): one connection, many tunnels both ways.
    ///
    /// On startup the TUI asks whether to connect to an existing instance.
    /// Choosing "no" starts a listening instance (generating an auth token if
    /// none is configured); choosing "yes" prompts for the existing instance's
    /// node id and, if not configured, its auth token. Forwards, relays, and
    /// other options come from the config file.
    Peer {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/duopipe/peer.toml)
        #[arg(long)]
        default_config: bool,
    },
    /// Generate an authentication token
    ///
    /// The auth token is the shared secret presented by both sides. Put it in a
    /// config `auth_token`/`auth_token_file`, or set DUOPIPE_AUTH_TOKEN. A fresh
    /// listening instance generates one automatically if none is provided.
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

/// Detect a non-interactive (test) preset from environment variables.
///
/// Requires `DUOPIPE_NONINTERACTIVE` to be truthy. Role is inferred from
/// `DUOPIPE_PEER_NODE_ID`: present ⇒ Dial (parse the id), absent ⇒ Listen. The
/// auth token comes from `config_auth_token` (already resolved/validated), or is
/// generated for Listen. Evaluated before the TUI starts so failures print
/// plainly and exit.
fn detect_env_preset(config_auth_token: Option<String>) -> Result<Option<ResolvedPeer>> {
    if !env_truthy("DUOPIPE_NONINTERACTIVE") {
        return Ok(None);
    }

    match env_var_opt("DUOPIPE_PEER_NODE_ID") {
        Some(node) => {
            let id: EndpointId = node.parse().map_err(|_| {
                anyhow::anyhow!("DUOPIPE_PEER_NODE_ID is not a valid node id.")
            })?;
            let auth_token = config_auth_token.context(
                "Non-interactive dial requires an auth token. Set DUOPIPE_AUTH_TOKEN or auth_token in the config.",
            )?;
            Ok(Some(ResolvedPeer {
                role: Role::Dial,
                peer_node_id: Some(id),
                auth_token,
            }))
        }
        None => {
            let auth_token = match config_auth_token {
                Some(t) => t,
                None => {
                    let t = auth::generate_token();
                    // Printed before TUI init so non-interactive tests can capture it.
                    eprintln!("auth_token: {t}");
                    t
                }
            };
            Ok(Some(ResolvedPeer {
                role: Role::Listen,
                peer_node_id: None,
                auth_token,
            }))
        }
    }
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

    // The `peer` command renders a TUI and captures logs into a ring buffer;
    // every other command logs to the console as usual.
    let log_buffer = if matches!(&command, Command::Peer { .. }) {
        if !std::io::stdout().is_terminal() {
            return Err(TunnelError::config(anyhow::anyhow!(
                "duopipe peer requires an interactive terminal."
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
        Command::Peer {
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

            // Forwards, relays, and transport now come from config only.
            validate_forward_specs(&cfg.local_forward, &cfg.remote_forward)
                .map_err(TunnelError::config)?;
            validate_transport_tuning(&cfg.transport, "transport")
                .map_err(TunnelError::config)?;

            let relay_urls = cfg.relay_urls.clone().unwrap_or_default();
            let relay_only = cfg.relay_only.unwrap_or(false);
            validate_relay_only(relay_only, &relay_urls).map_err(TunnelError::config)?;

            // Resolve the shared auth token (env > config) and any non-interactive
            // preset, both before the TUI starts so failures print plainly.
            let config_auth_token =
                resolve_config_auth_token(&cfg).map_err(TunnelError::config)?;
            let preset =
                detect_env_preset(config_auth_token.clone()).map_err(TunnelError::config)?;

            let log_buffer = log_buffer.expect("peer command initializes the TUI log buffer");
            let launch = TuiLaunch {
                logs: log_buffer,
                local_forwards: cfg.local_forward.clone(),
                remote_forwards: cfg.remote_forward.clone(),
                relay_urls,
                relay_only,
                dns_server: cfg.dns_server.clone(),
                max_sessions: cfg.max_sessions,
                transport: cfg.transport.clone(),
                announce_endpoint: preset.is_some(),
                config_auth_token,
                preset,
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
                        anyhow::bail!(
                            "Cannot combine --recipient and --config. Use only one."
                        );
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

                        let cfg: MinimalConfig =
                            toml::from_str(&content).with_context(|| {
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
