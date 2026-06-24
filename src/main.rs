//! duopipe
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.

mod app_state;
mod auth;
mod buffer;
mod config;
mod error;
mod iroh_mode;
mod logging;
mod net;
mod nostr_discovery;
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
use std::path::{Path, PathBuf};

/// Capacity of the in-memory log ring buffer shown in the TUI.
const LOG_CAPACITY: usize = 2000;

use crate::config::{
    AllowedSources, ConfigSource, PeerConfig, expand_tilde, load_peer_config,
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
    /// Start a peer in configless mode (interactive TUI): one connection, many
    /// tunnels both ways.
    ///
    /// Everything is ephemeral and nostr is off: the node id changes every run and
    /// a dialer enters the peer's node id manually. The auth token is generated
    /// fresh each run (shown in the TUI), or loaded from --auth-token-file /
    /// DUOPIPE_AUTH_TOKEN. No config file is read.
    ///
    /// On startup the TUI offers a choice between starting a new (listening)
    /// instance and connecting to an existing one.
    Quick {
        /// Path to a file containing the shared auth token. Takes precedence over
        /// DUOPIPE_AUTH_TOKEN. Without it (or the env var) a fresh ephemeral token
        /// is generated each run.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
    },
    /// Start a peer in nostr mode (interactive TUI): one connection, many tunnels
    /// both ways.
    ///
    /// Requires a config file and a provided auth token (it is the nostr rendezvous
    /// secret — supply it via config `auth_token_file` or DUOPIPE_AUTH_TOKEN). The
    /// listener publishes its current ephemeral node id to nostr and a dialer looks
    /// it up, so the node id need not be exchanged by hand.
    ///
    /// On startup the TUI offers a choice between starting a new (listening)
    /// instance and connecting to an existing one.
    Nostr {
        /// Path to config file. Defaults to ~/.config/duopipe/peer.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Generate an authentication token
    ///
    /// The auth token is the shared secret presented by both sides. Supply it with
    /// `auth_token_file` or the DUOPIPE_AUTH_TOKEN env var. A fresh listening
    /// instance generates one automatically if none is provided.
    GenerateAuthToken {
        /// Number of tokens to generate (default: 1)
        #[arg(short, long, default_value = "1")]
        count: usize,
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

/// Resolve the shared auth token, in precedence order: the `--auth-token-file`
/// CLI flag, then the `DUOPIPE_AUTH_TOKEN` env var, then a config `auth_token_file`.
/// Validates the token's CRC when present. Returns `None` when none is supplied (a
/// fresh listening instance in configless mode will generate one).
fn resolve_config_auth_token(
    cli_file: Option<&Path>,
    cfg: &PeerConfig,
) -> Result<Option<String>> {
    let token = if let Some(file) = cli_file {
        let expanded = expand_tilde(file);
        Some(auth::load_auth_token_from_file(&expanded)?)
    } else if let Some(t) = env_var_opt("DUOPIPE_AUTH_TOKEN") {
        Some(t)
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
                    "Non-interactive dial requires an auth token. Set DUOPIPE_AUTH_TOKEN or auth_token_file.",
                )?;
                Ok(ResolvedPeer {
                    role: Role::Dial,
                    peer_node_id: Some(id),
                    peer_identifier: None,
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
                    peer_identifier: None,
                    auth_token,
                    token_generated,
                    allowed_sources,
                })
            }
        }
    }
}

/// Load the nostr-mode peer config: from `config` if given, else the default
/// location (~/.config/duopipe/peer.toml).
fn load_nostr_config(config: Option<&Path>) -> Result<PeerConfig> {
    load_peer_config(config)
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
        // Headless test mode never uses nostr: the node id is wired directly via
        // DUOPIPE_PEER_NODE_ID, so tests stay hermetic (no live relays).
        nostr_relays: vec![],
        nostr_discovery: false,
        nostr_identifier: None,
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

    // The interactive `quick`/`nostr` commands render a TUI and capture logs into a
    // ring buffer. In test mode — `DUOPIPE_TEST_MODE=1` — the peer runs headless
    // with no TUI, logging to stderr, so it needs no terminal. `DUOPIPE_TEST_MODE`
    // is the single gate for all test-only env vars. Every other command logs to
    // the console as usual.
    let test_env = TestEnv::from_env();
    let is_tui_command = matches!(&command, Command::Quick { .. } | Command::Nostr { .. });
    let log_buffer = if is_tui_command && test_env.is_none() {
        if !std::io::stdout().is_terminal() {
            return Err(TunnelError::config(anyhow::anyhow!(
                "duopipe requires an interactive terminal (set DUOPIPE_TEST_MODE=1 for headless test mode)."
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

    match command {
        // Configless mode: ephemeral id + token, no nostr. The token comes from the
        // `--auth-token-file` flag, then `DUOPIPE_AUTH_TOKEN`, else one is generated.
        Command::Quick { auth_token_file } => {
            run_start_peer(
                PeerConfig::default(),
                ConfigSource::None,
                auth_token_file.as_deref(),
                &test_env,
                log_buffer,
            )
            .await
        }
        // Nostr mode: load the config (from `-c` or the default path) and use nostr
        // for node-id discovery. The token is required, from config/env only.
        Command::Nostr { config } => {
            let cfg = load_nostr_config(config.as_deref()).map_err(TunnelError::config)?;
            run_start_peer(cfg, ConfigSource::File, None, &test_env, log_buffer).await
        }
        Command::GenerateAuthToken { count } => {
            for _ in 0..count {
                println!("{}", auth::generate_token());
            }
            Ok(())
        }
    }
}

/// Shared startup for both interactive modes (`quick` / `nostr`). `source`
/// distinguishes them: `ConfigSource::None` is configless mode (no nostr;
/// `cli_auth_token_file` carries the `--auth-token-file` flag), `ConfigSource::File`
/// is nostr mode (discovery on; auth token required, from config/env). Test mode is
/// handled here too — it runs headless and never touches nostr.
async fn run_start_peer(
    cfg: PeerConfig,
    source: ConfigSource,
    cli_auth_token_file: Option<&Path>,
    test_env: &Option<TestEnv>,
    log_buffer: Option<std::sync::Arc<logging::LogBuffer>>,
) -> Result<()> {
    // Validate config structure and address formats (requests, allowlist,
    // transport). In configless mode this runs on defaults, which are trivially valid.
    cfg.validate().map_err(TunnelError::config)?;

    let relay_urls = cfg.relay_urls.clone().unwrap_or_default();
    let relay_only = cfg.relay_only.unwrap_or(false);
    validate_relay_only(relay_only, &relay_urls).map_err(TunnelError::config)?;

    // Resolve the shared auth token (CLI flag > env > config) before startup so
    // failures print plainly.
    let config_auth_token =
        resolve_config_auth_token(cli_auth_token_file, &cfg).map_err(TunnelError::config)?;

    // Nostr discovery is on exactly in nostr mode. The iroh identity is always
    // ephemeral; nostr is the side channel that publishes/looks up the current node
    // id, keyed off the shared auth token. Relays default to the public set.
    let nostr_discovery_enabled = source == ConfigSource::File;
    let nostr_relays = cfg.nostr_relay_urls.clone().unwrap_or_else(|| {
        nostr_discovery::DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    // Test mode: resolve the preset and run headless, no TUI. Test mode never uses
    // nostr (the node id is wired directly via DUOPIPE_PEER_NODE_ID), so the
    // nostr-mode token requirement below does not apply here.
    if let Some(test_env) = test_env {
        let resolved = test_env
            .resolve_preset(config_auth_token, cfg.allowed_sources.clone())
            .map_err(TunnelError::config)?;
        return run_peer_headless(
            resolved,
            &cfg,
            relay_urls,
            relay_only,
            test_env.autostart_requests,
        )
        .await;
    }

    // Nostr mode requires a provided auth token: it is the rendezvous secret both
    // peers derive their nostr key from, so a generated one could not be discovered
    // by the other side.
    if nostr_discovery_enabled && config_auth_token.is_none() {
        return Err(TunnelError::config(anyhow::anyhow!(
            "Nostr mode requires an auth token. Supply it via the config `auth_token_file` or the DUOPIPE_AUTH_TOKEN env var."
        ))
        .into());
    }

    // Nostr mode requires a `name`: each peer publishes its node id under this short
    // identifier, and a dialer types it to look the peer up.
    let peer_name = cfg.name.as_ref().map(|n| n.trim()).filter(|n| !n.is_empty());
    if nostr_discovery_enabled && peer_name.is_none() {
        return Err(TunnelError::config(anyhow::anyhow!(
            "Nostr mode requires a `name` (short identifier) in the config; a dialer uses it to find this peer."
        ))
        .into());
    }
    let peer_name = peer_name.map(|n| n.to_string());

    let log_buffer = log_buffer.expect("a TUI command initializes the log buffer");
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
        nostr_relays,
        nostr_discovery: nostr_discovery_enabled,
        peer_name,
    };

    tui::run_tui(launch).await
}
