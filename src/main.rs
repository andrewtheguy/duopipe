//! duopipe
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.

mod auth;
mod buffer;
mod config;
mod encryption;
mod error;
mod iroh_mode;
mod net;
mod secret;
mod signaling;

use ::iroh::SecretKey;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::error::{ErrorCategory, TunnelError};

use crate::config::{
    expand_tilde, load_peer_config, parse_config_from_reader, validate_forward_specs,
    validate_transport_tuning, ConfigSource, ConnectRole, LocalForward, PeerConfig, RemoteForward,
    TransportTuning,
};
use crate::iroh_mode::endpoint::{
    load_secret, load_secret_from_string, secret_to_endpoint_id,
};

#[derive(Parser)]
#[command(name = "duopipe")]
#[command(version)]
#[command(about = "Forward TCP/UDP traffic through iroh P2P connections")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// The `Peer` variant carries many CLI flags; boxing individual clap fields would
// hurt readability for no real benefit on a short-lived, single-instance enum.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run a peer: one connection, many tunnels in both directions.
    ///
    /// One peer dials (`--connect dial --peer-node-id <ID>`), the other listens
    /// (`--connect listen --secret-file <KEY>`). Over the single connection, each
    /// side can declare local forwards (-L) and remote forwards (-R).
    Peer {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/duopipe/peer.toml)
        #[arg(long)]
        default_config: bool,

        /// Read JSON config from stdin for automation/IPC (use -c for normal usage)
        #[arg(long)]
        config_stdin: bool,

        /// Connection role: "dial" (connect out) or "listen" (accept).
        #[arg(long)]
        connect: Option<String>,

        /// EndpointId of the peer to dial (required when --connect dial)
        #[arg(short = 'n', long)]
        peer_node_id: Option<String>,

        /// Local forward (-L), repeatable: LISTEN=DEST
        /// E.g. -L 127.0.0.1:15678=tcp://127.0.0.1:5678
        #[arg(short = 'L', value_name = "LISTEN=DEST")]
        local_forward: Vec<String>,

        /// Remote forward (-R), repeatable: BIND=DEST
        /// E.g. -R tcp://0.0.0.0:6574=127.0.0.1:6574
        #[arg(short = 'R', value_name = "BIND=DEST")]
        remote_forward: Vec<String>,

        /// Maximum concurrent data streams per connection (default: 100)
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Path to secret key file for persistent identity (required when listening)
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P).
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery, or "none" to disable DNS discovery.
        /// mDNS for local network discovery is unaffected.
        #[arg(long)]
        dns_server: Option<String>,

        /// Path to file containing the authentication token presented when dialing
        #[arg(long)]
        auth_token_file: Option<PathBuf>,

        /// Path to file containing accepted authentication tokens when listening
        /// (one per line, # comments allowed).
        #[arg(long, value_name = "FILE")]
        auth_tokens_file: Option<PathBuf>,

        /// Path to file containing ALPN token
        #[arg(long)]
        alpn_token_file: Option<PathBuf>,

        /// Path to age identity file for decrypting age-encrypted config values
        #[arg(long)]
        encryption_key_file: Option<PathBuf>,
    },
    /// Generate a private key for a peer's persistent identity
    ///
    /// The private key gives the listening peer a stable EndpointId that the
    /// dialing peer connects to. Use show-id to display the public EndpointId.
    GenerateKey {
        /// Path where to save the private key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Show the public EndpointId derived from a private key
    ///
    /// The dialing peer uses this EndpointId with --peer-node-id to connect.
    ShowId {
        /// Path to the private key file
        #[arg(short, long)]
        secret_file: PathBuf,
    },
    /// Generate an authentication token
    ///
    /// Tokens authenticate the dialing peer (like API keys). The listening peer
    /// configures accepted tokens via DUOPIPE_AUTH_TOKENS env var or --auth-tokens-file.
    GenerateAuthToken {
        /// Number of tokens to generate (default: 1)
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
    /// Generate an ALPN token (14-char Base64URL)
    ///
    /// Shared between both peers for pre-handshake QUIC ALPN filtering.
    /// Configure via DUOPIPE_ALPN_TOKEN env var or --alpn-token-file.
    GenerateAlpnToken {
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

fn normalize_optional_endpoint(value: Option<String>) -> Option<String> {
    value.and_then(|v| if v.trim().is_empty() { None } else { Some(v) })
}

/// Resolved iroh parameters for a peer, after merging CLI, env, and config.
/// CLI values take precedence over config file values.
struct PeerIrohParams {
    connect: Option<ConnectRole>,
    peer_node_id: Option<String>,
    local_forwards: Vec<LocalForward>,
    remote_forwards: Vec<RemoteForward>,
    max_sessions: Option<usize>,
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    dns_server: Option<String>,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    auth_tokens: Vec<String>,
    auth_tokens_file: Option<PathBuf>,
    alpn_token: Option<String>,
    alpn_token_file: Option<PathBuf>,
    transport: TransportTuning,
}

fn parse_connect_role(value: &str) -> Result<ConnectRole> {
    match value.trim().to_lowercase().as_str() {
        "dial" => Ok(ConnectRole::Dial),
        "listen" => Ok(ConnectRole::Listen),
        other => anyhow::bail!("Invalid --connect '{}'. Use 'dial' or 'listen'.", other),
    }
}

fn parse_local_forward(spec: &str) -> Result<LocalForward> {
    let (listen, dest) = spec.split_once('=').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid -L '{}'. Expected LISTEN=DEST, e.g. 127.0.0.1:15678=tcp://127.0.0.1:5678",
            spec
        )
    })?;
    Ok(LocalForward {
        listen: listen.trim().to_string(),
        dest: dest.trim().to_string(),
    })
}

fn parse_remote_forward(spec: &str) -> Result<RemoteForward> {
    let (bind, dest) = spec.split_once('=').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid -R '{}'. Expected BIND=DEST, e.g. tcp://0.0.0.0:6574=127.0.0.1:6574",
            spec
        )
    })?;
    Ok(RemoteForward {
        bind: bind.trim().to_string(),
        dest: dest.trim().to_string(),
    })
}

/// Resolve iroh peer parameters from CLI and config.
/// Env vars take precedence over config for sensitive fields.
fn resolve_peer_iroh_params(
    cli: &Command,
    iroh_cfg: Option<&crate::config::IrohConfig>,
) -> Result<PeerIrohParams> {
    let cfg = iroh_cfg.cloned().unwrap_or_default();

    let Command::Peer {
        connect,
        peer_node_id,
        local_forward,
        remote_forward,
        max_sessions,
        secret_file,
        relay_urls,
        dns_server,
        auth_token_file,
        auth_tokens_file,
        alpn_token_file,
        encryption_key_file: _,
        ..
    } = cli
    else {
        unreachable!("resolve_peer_iroh_params called with non-peer command");
    };

    let connect = match connect {
        Some(s) => Some(parse_connect_role(s)?),
        None => cfg.connect,
    };

    let local_forwards = if local_forward.is_empty() {
        cfg.local_forward.clone()
    } else {
        local_forward
            .iter()
            .map(|s| parse_local_forward(s))
            .collect::<Result<Vec<_>>>()?
    };
    let remote_forwards = if remote_forward.is_empty() {
        cfg.remote_forward.clone()
    } else {
        remote_forward
            .iter()
            .map(|s| parse_remote_forward(s))
            .collect::<Result<Vec<_>>>()?
    };

    let env_secret = env_var_opt("DUOPIPE_SECRET");
    let (secret, secret_file) = if env_secret.is_some() || secret_file.is_some() {
        (env_secret, secret_file.clone())
    } else {
        (cfg.secret.clone(), cfg.secret_file.clone())
    };

    let env_auth_token = env_var_opt("DUOPIPE_AUTH_TOKEN");
    let (auth_token, auth_token_file) = if env_auth_token.is_some() || auth_token_file.is_some() {
        (env_auth_token, auth_token_file.clone())
    } else {
        (cfg.auth_token.clone(), cfg.auth_token_file.clone())
    };

    let env_auth_tokens: Vec<String> = env_var_opt("DUOPIPE_AUTH_TOKENS")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let env_alpn_token = env_var_opt("DUOPIPE_ALPN_TOKEN");

    Ok(PeerIrohParams {
        connect,
        peer_node_id: normalize_optional_endpoint(peer_node_id.clone())
            .or_else(|| normalize_optional_endpoint(cfg.peer_node_id.clone())),
        local_forwards,
        remote_forwards,
        max_sessions: max_sessions.or(cfg.max_sessions),
        secret,
        secret_file,
        relay_urls: if relay_urls.is_empty() {
            cfg.relay_urls.clone().unwrap_or_default()
        } else {
            relay_urls.clone()
        },
        dns_server: dns_server.clone().or(cfg.dns_server.clone()),
        auth_token,
        auth_token_file,
        auth_tokens: if !env_auth_tokens.is_empty() {
            env_auth_tokens
        } else {
            cfg.auth_tokens.clone().unwrap_or_default()
        },
        auth_tokens_file: auth_tokens_file.clone().or(cfg.auth_tokens_file.clone()),
        alpn_token: if env_alpn_token.is_some() {
            env_alpn_token
        } else if alpn_token_file.is_some() {
            None
        } else {
            cfg.alpn_token.clone()
        },
        alpn_token_file: if alpn_token_file.is_some() {
            alpn_token_file.clone()
        } else {
            cfg.alpn_token_file.clone()
        },
        transport: cfg.transport.clone(),
    })
}

/// Resolve an optional iroh secret. Returns None when neither inline nor file is given
/// (the dialing peer may use an ephemeral identity).
fn resolve_optional_secret(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
) -> Result<Option<SecretKey>> {
    match (secret, secret_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "Cannot combine DUOPIPE_SECRET with --secret-file (or secret and secret_file in config)."
            );
        }
        (Some(secret), None) => {
            let trimmed = secret.trim();
            if trimmed.is_empty() {
                anyhow::bail!("Inline secret is empty. Provide a base64-encoded secret key.");
            }
            let secret = load_secret_from_string(trimmed)
                .context("Invalid inline secret key (expected base64)")?;
            log::info!("Loaded identity from inline secret");
            log::info!("EndpointId: {}", secret_to_endpoint_id(&secret));
            Ok(Some(secret))
        }
        (None, Some(path)) => {
            let expanded = expand_tilde(&path);
            let secret = load_secret(&expanded)?;
            log::info!("Loaded identity from: {}", expanded.display());
            log::info!("EndpointId: {}", secret_to_endpoint_id(&secret));
            Ok(Some(secret))
        }
        (None, None) => Ok(None),
    }
}

/// Load peer config based on flags. Returns (config, source).
async fn resolve_peer_config(
    config: Option<PathBuf>,
    default_config: bool,
    config_stdin: bool,
) -> Result<(PeerConfig, ConfigSource)> {
    let source_count = config.is_some() as u8 + default_config as u8 + config_stdin as u8;
    if source_count > 1 {
        anyhow::bail!("Only one of -c/--config, --default-config, or --config-stdin may be used");
    }

    if config_stdin {
        Ok((
            parse_config_from_reader(std::io::stdin()).await?,
            ConfigSource::Stdin,
        ))
    } else if let Some(path) = config {
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
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .filter_module("duopipe", log::LevelFilter::Info)
        .try_init();

    let args = Args::parse();
    let command = args.command;

    match &command {
        Command::Peer {
            config,
            default_config,
            config_stdin,
            relay_only,
            encryption_key_file,
            ..
        } => {
            let (mut cfg, source) =
                resolve_peer_config(config.clone(), *default_config, *config_stdin).await?;

            if source != ConfigSource::None {
                cfg.validate(source).map_err(TunnelError::config)?;
            }

            // Decrypt age-encrypted values if present
            let enc_key = encryption_key_file
                .clone()
                .or_else(|| env_var_opt("DUOPIPE_ENCRYPTION_KEY_FILE").map(PathBuf::from))
                .or_else(|| {
                    cfg.iroh
                        .as_ref()
                        .and_then(|i| i.encryption_key_file.clone())
                })
                .map(|p| expand_tilde(&p));
            if let Some(ref mut iroh) = cfg.iroh {
                iroh.decrypt_secrets(enc_key.as_deref())?;
            }

            let params = resolve_peer_iroh_params(&command, cfg.iroh())
                .map_err(TunnelError::config)?;

            // Validate forward address formats (covers CLI-supplied -L/-R too).
            validate_forward_specs(&params.local_forwards, &params.remote_forwards)
                .map_err(TunnelError::config)?;

            let connect = params.connect.ok_or_else(|| {
                TunnelError::config(anyhow::anyhow!(
                    "Connection role is required. Pass --connect dial|listen or set [iroh].connect."
                ))
            })?;

            let relay_only = *relay_only;

            let secret = resolve_optional_secret(params.secret, params.secret_file)?;

            // Resolve the auth token presented when dialing (optional for listen).
            let auth_token = match (params.auth_token, params.auth_token_file) {
                (Some(_), Some(_)) => {
                    return Err(TunnelError::config(anyhow::anyhow!(
                        "Cannot combine DUOPIPE_AUTH_TOKEN with --auth-token-file (or auth_token and auth_token_file in config)."
                    )).into());
                }
                (Some(token), None) => Some(token),
                (None, Some(file)) => {
                    let expanded = expand_tilde(&file);
                    Some(auth::load_auth_token_from_file(&expanded).map_err(TunnelError::config)?)
                }
                (None, None) => None,
            };
            if let Some(ref token) = auth_token {
                auth::validate_token(token)
                    .context("Invalid auth token format. Generate a valid token with: duopipe generate-auth-token")
                    .map_err(TunnelError::config)?;
            }

            // Resolve the auth tokens accepted when listening (optional for dial).
            let auth_tokens_file_expanded =
                params.auth_tokens_file.as_ref().map(|p| expand_tilde(p));
            let auth_tokens = auth::load_auth_tokens(
                &params.auth_tokens,
                auth_tokens_file_expanded.as_deref(),
            )
            .map_err(TunnelError::config)?;

            // Resolve ALPN token from env var or file (required for both roles).
            let alpn_token = match (params.alpn_token, params.alpn_token_file) {
                (Some(_), Some(_)) => {
                    return Err(TunnelError::config(anyhow::anyhow!(
                        "Cannot combine DUOPIPE_ALPN_TOKEN with --alpn-token-file (or alpn_token and alpn_token_file in config)."
                    )).into());
                }
                (Some(token), None) => token,
                (None, Some(file)) => {
                    let expanded = expand_tilde(&file);
                    auth::load_alpn_token_from_file(&expanded).map_err(TunnelError::config)?
                }
                (None, None) => {
                    return Err(TunnelError::config(anyhow::anyhow!(
                        "ALPN token is required. Set DUOPIPE_ALPN_TOKEN environment variable or use --alpn-token-file.\n\
                        Generate one with: duopipe generate-alpn-token"
                    )).into());
                }
            };
            auth::validate_alpn_token(&alpn_token)
                .context("Invalid ALPN token format. Generate a valid token with: duopipe generate-alpn-token")
                .map_err(TunnelError::config)?;

            // Enforce role-specific requirements.
            match connect {
                ConnectRole::Dial => {
                    if params.peer_node_id.is_none() {
                        return Err(TunnelError::config(anyhow::anyhow!(
                            "--connect dial requires --peer-node-id (or [iroh].peer_node_id)."
                        )).into());
                    }
                    if auth_token.is_none() {
                        return Err(TunnelError::config(anyhow::anyhow!(
                            "--connect dial requires an auth token. Set DUOPIPE_AUTH_TOKEN or use --auth-token-file."
                        )).into());
                    }
                }
                ConnectRole::Listen => {
                    if secret.is_none() {
                        return Err(TunnelError::config(anyhow::anyhow!(
                            "--connect listen requires a secret identity. Generate one with:\n  \
                             duopipe generate-key --output ./peer.key\n\
                             then pass --secret-file ./peer.key or set [iroh].secret_file."
                        )).into());
                    }
                    if auth_tokens.is_empty() {
                        return Err(TunnelError::config(anyhow::anyhow!(
                            "--connect listen requires at least one accepted auth token. Set DUOPIPE_AUTH_TOKENS or use --auth-tokens-file."
                        )).into());
                    }
                    log::info!("Auth tokens: {} token(s) configured", auth_tokens.len());
                }
            }

            // Validate transport tuning window sizes
            validate_transport_tuning(&params.transport, "iroh.transport")
                .map_err(TunnelError::config)?;

            iroh_mode::run_peer(iroh_mode::PeerConfig {
                connect,
                peer_node_id: params.peer_node_id,
                secret,
                local_forwards: params.local_forwards,
                remote_forwards: params.remote_forwards,
                auth_token,
                auth_tokens,
                alpn_token,
                relay_urls: params.relay_urls,
                relay_only,
                dns_server: params.dns_server,
                max_sessions: params.max_sessions,
                transport: params.transport,
            })
            .await
        }
        Command::GenerateKey { output, force } => {
            secret::generate_secret(expand_tilde(output), *force)
        }
        Command::ShowId { secret_file } => secret::show_id(expand_tilde(secret_file)),
        Command::GenerateAuthToken { count } => {
            for _ in 0..*count {
                println!("{}", auth::generate_token());
            }
            Ok(())
        }
        Command::GenerateAlpnToken { count } => {
            for _ in 0..*count {
                println!("{}", auth::generate_alpn_token());
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
                            iroh: Option<MinimalIroh>,
                        }
                        #[derive(serde::Deserialize)]
                        struct MinimalIroh {
                            encryption_recipient: Option<String>,
                        }

                        let cfg: MinimalConfig =
                            toml::from_str(&content).with_context(|| {
                                format!("Failed to parse config: {}", expanded.display())
                            })?;
                        cfg.iroh
                            .and_then(|i| i.encryption_recipient)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "No [iroh].encryption_recipient found in {}",
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
