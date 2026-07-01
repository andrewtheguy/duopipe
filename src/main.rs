//! duopipe
//!
//! Forwards a single TCP stream through iroh P2P connections.

mod app_state;
mod auth;
mod config;
mod error;
mod iroh_mode;
mod logging;
mod net;
mod nostr_discovery;
mod peer_params;
mod peer_state;
mod pin;
mod pin_auth;
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

use crate::config::{ConfigSource, PeerConfig, expand_tilde, load_peer_config};
use crate::iroh_mode::endpoint::validate_relay_only;

#[derive(Parser)]
#[command(name = "duopipe")]
#[command(version)]
#[command(about = "Forward a single TCP stream through iroh P2P connections")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a peer in configless mode (interactive TUI): on-demand listening, with
    /// one on-demand outbound dial session.
    ///
    /// Everything is ephemeral and no config file is read: the node id changes every run
    /// and a fresh auth token is always generated (there is no way to supply an existing
    /// one). At setup you pick how to share this device with the dialer:
    ///
    /// - **PIN** — the dashboard shows a short code that refreshes every 60s; it carries
    ///   this peer's node id and token over nostr, so the dialer just types the PIN
    ///   (Shift-C). Needs internet (public relays).
    /// - **Manual** — no nostr/internet: the node id and token are shown to copy by hand,
    ///   and the dialer enters the node id (Shift-C). The token moves out of band.
    ///
    /// On startup the TUI confirms setup, then opens the dashboard idle. Press
    /// Shift-L to listen and Shift-C to connect to a peer by PIN or node id.
    Quick {},
    /// Run a peer from config (interactive TUI): on-demand listening, with one
    /// on-demand outbound dial session.
    ///
    /// Requires a config file. The auth token (the nostr rendezvous secret) is shared
    /// and pre-generated: supply it via config `auth_token_file` or DUOPIPE_AUTH_TOKEN,
    /// or paste it at the setup screen (generate one first with
    /// `duopipe generate-auth-token`). The listener publishes its current ephemeral
    /// node id to nostr and a dialer looks it up, so the node id need not be exchanged
    /// by hand.
    ///
    /// On startup the TUI confirms setup, then opens the dashboard idle. Press
    /// Shift-L to listen and Shift-C to connect to a peer by name.
    Run {
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
        /// Emit JSON (a `[{"token","fingerprint"}]` array) for scripting/automation
        /// instead of the human-readable `<token>  # fp: <fp>` lines.
        #[arg(long)]
        json: bool,
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

/// Resolve the shared auth token, in precedence order: the `DUOPIPE_AUTH_TOKEN` env
/// var, then a config `auth_token_file`. Validates the token's CRC when present.
/// Returns `None` when none is supplied (interactive setup then resolves it).
fn resolve_config_auth_token(cfg: &PeerConfig) -> Result<Option<String>> {
    let token = if let Some(t) = env_var_opt("DUOPIPE_AUTH_TOKEN") {
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

/// Resolve the expected auth-token fingerprint for config mode. Config-mode configs
/// must declare `auth_token_fingerprint` (the 8-hex-digit fingerprint of the shared token):
/// it disambiguates configs meant for different pairings, so a config can't be run with
/// the wrong pairing's token. Returns the validated fingerprint so a token pasted at the
/// setup screen can also be checked against it; a token already resolved from file/env is
/// checked here. Quick mode declares no fingerprint and returns `None`.
fn resolve_expected_fingerprint(
    cfg: &PeerConfig,
    config_mode: bool,
    config_auth_token: Option<&str>,
) -> Result<Option<String>> {
    if !config_mode {
        return Ok(None);
    }
    let expected = cfg
        .auth_token_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Config mode requires `auth_token_fingerprint` in the config: the 8-hex-digit \
                 fingerprint of your shared token (shown by `duopipe generate-auth-token` and in \
                 the dashboard header). It guards against running this config with a token meant \
                 for a different pairing."
            )
        })?;
    auth::validate_fingerprint(expected)?;
    if let Some(token) = config_auth_token
        && !auth::fingerprint_matches(token, expected)
    {
        anyhow::bail!(
            "Auth token fingerprint mismatch: the config declares \
             `auth_token_fingerprint = \"{}\"`, but the resolved token's fingerprint is {}. \
             This token belongs to a different pairing — fix the token source or the fingerprint.",
            expected,
            auth::token_fingerprint(token)
        );
    }
    Ok(Some(expected.to_string()))
}

/// All test-only environment variables, read once behind the single
/// `DUOPIPE_TEST_MODE` gate. `None` ⇒ test mode is off and no other `DUOPIPE_*`
/// test var has any effect. This is the only place test-only env vars are read.
struct TestEnv {
    /// `DUOPIPE_PEER_NODE_ID`: present ⇒ Dial that id; absent ⇒ Listen.
    peer_node_id: Option<String>,
    /// `DUOPIPE_AUTOSTART_TUNNELS`: auto-start all tunnels once connected.
    autostart_tunnels: bool,
}

impl TestEnv {
    /// Read the gate and, if set, every gated var.
    fn from_env() -> Option<Self> {
        if !env_truthy("DUOPIPE_TEST_MODE") {
            return None;
        }
        Some(TestEnv {
            peer_node_id: env_var_opt("DUOPIPE_PEER_NODE_ID"),
            autostart_tunnels: env_truthy("DUOPIPE_AUTOSTART_TUNNELS"),
        })
    }

    /// Resolve the role-dependent peer for this test run. Role is inferred from
    /// `peer_node_id`: present ⇒ Dial (parse the id), absent ⇒ Listen. The auth
    /// token comes from `config_auth_token` (already resolved/validated), or is
    /// generated for Listen. Evaluated before the peer starts so failures print
    /// plainly and exit.
    fn resolve_preset(&self, config_auth_token: Option<String>) -> Result<ResolvedPeer> {
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
                    quick_pin: false,
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
                    quick_pin: false,
                })
            }
        }
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
    autostart_tunnels: bool,
) -> Result<()> {
    let logs = logging::LogBuffer::new(LOG_CAPACITY);
    // Headless test mode is single-role and never uses nostr, so the dial-prompt
    // fields are inert.
    let state = AppState::new(
        resolved.role,
        resolved.token_generated,
        logs,
        cfg.tunnel.clone(),
        false,
        None,
        false,
    );
    let peer_cfg = iroh_mode::PeerConfig {
        role: resolved.role,
        peer_node_id: resolved.peer_node_id,
        autostart_tunnels,
        auth_token: resolved.auth_token,
        // Headless test mode never uses nostr: the node id is wired directly via
        // DUOPIPE_PEER_NODE_ID, so tests stay hermetic (no live relays).
        nostr_relays: vec![],
        nostr_discovery: false,
        nostr_identifier: None,
        // Headless test mode never uses nostr (and never the PIN side channel).
        pin_rendezvous: false,
        // Headless test mode is single-role (listen or dial); this endpoint reports its
        // own id.
        report_endpoint_id: true,
        relay_urls,
        relay_only,
        dns_server: cfg.dns_server.clone(),
        max_streams: cfg.max_streams,
        transport: cfg.transport.clone(),
        announce_endpoint: true,
        // Headless test mode never uses nostr, so there is no name to rename.
        config_path: None,
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

    // The interactive `quick`/`run` commands render a TUI and capture logs into a
    // ring buffer. In test mode — `DUOPIPE_TEST_MODE=1` — the peer runs headless
    // with no TUI, logging to stderr, so it needs no terminal. `DUOPIPE_TEST_MODE`
    // is the single gate for all test-only env vars. Every other command logs to
    // the console as usual.
    let test_env = TestEnv::from_env();
    let is_tui_command = matches!(&command, Command::Quick { .. } | Command::Run { .. });
    let log_buffer = if is_tui_command && test_env.is_none() {
        // The TUI both renders to stdout and reads keyboard input from stdin, so both
        // must be terminals — a piped stdin would otherwise pass and then starve the
        // event loop of input.
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
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
        // Configless mode: ephemeral id + token, no nostr. The token is always
        // generated by setup (interactive). DUOPIPE_AUTH_TOKEN is honored only in
        // test mode, where the headless dial side needs it.
        Command::Quick {} => {
            run_start_peer(
                PeerConfig::default(),
                ConfigSource::None,
                None,
                &test_env,
                log_buffer,
            )
            .await
        }
        // Config mode: load the config (from `-c` or the default path) and use nostr
        // for node-id discovery. The token is required, from config/env only.
        Command::Run { config } => {
            let cfg = load_peer_config(config.as_deref()).map_err(TunnelError::config)?;
            // Resolve the actual file path so a name-conflict rename can annotate it.
            let config_path = crate::config::resolve_peer_config_path(config.as_deref());
            run_start_peer(cfg, ConfigSource::File, config_path, &test_env, log_buffer).await
        }
        Command::GenerateAuthToken { count, json } => {
            let tokens: Vec<String> = (0..count).map(|_| auth::generate_token()).collect();
            if json {
                // Structured output for scripting/automation: an array of
                // {token, fingerprint} objects so callers don't have to parse the
                // human-readable line format.
                let entries: Vec<_> = tokens
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "token": t,
                            "fingerprint": auth::token_fingerprint(t),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                // The fingerprint is appended as an inline `#` comment so the output is
                // still a valid token file (the parser strips inline comments), while
                // surfacing the value to put in a config-mode config's `auth_token_fingerprint`.
                for token in &tokens {
                    println!("{}  # fp: {}", token, auth::token_fingerprint(token));
                }
            }
            Ok(())
        }
    }
}

/// Shared startup for both interactive modes (`quick` / `run`). `source`
/// distinguishes them: `ConfigSource::None` is configless mode (no nostr; the token
/// is always generated by interactive setup), `ConfigSource::File` is config mode
/// (discovery on; auth token required, from config/env/paste). Test mode is handled
/// here too — it runs headless and never touches nostr.
async fn run_start_peer(
    cfg: PeerConfig,
    source: ConfigSource,
    config_path: Option<PathBuf>,
    test_env: &Option<TestEnv>,
    log_buffer: Option<std::sync::Arc<logging::LogBuffer>>,
) -> Result<()> {
    // Validate config structure and address formats (tunnel addresses, transport).
    // In configless mode this runs on defaults, which are trivially valid.
    cfg.validate().map_err(TunnelError::config)?;

    let relay_urls = cfg.relay_urls.clone().unwrap_or_default();
    let relay_only = cfg.relay_only.unwrap_or(false);
    validate_relay_only(relay_only, &relay_urls).map_err(TunnelError::config)?;

    // Resolve the shared auth token (env > config) before startup so failures print
    // plainly. Interactive quick mode always generates its own ephemeral token, so it
    // ignores any supplied token; DUOPIPE_AUTH_TOKEN stays a test-mode-only override
    // (the headless dial side needs it to receive the listener's token).
    let config_auth_token = if source == ConfigSource::None && test_env.is_none() {
        None
    } else {
        resolve_config_auth_token(&cfg).map_err(TunnelError::config)?
    };

    // Nostr discovery is on exactly in config mode. The iroh identity is always
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
    // config-mode token requirement below does not apply here.
    if let Some(test_env) = test_env {
        let resolved = test_env
            .resolve_preset(config_auth_token)
            .map_err(TunnelError::config)?;
        return run_peer_headless(
            resolved,
            &cfg,
            relay_urls,
            relay_only,
            test_env.autostart_tunnels,
        )
        .await;
    }

    // Config mode must declare the shared token's fingerprint. A token already resolved
    // from file/env is checked against it now (plain error, exit); a token pasted at the
    // setup screen is checked there, so carry the expected fingerprint into the TUI.
    let expected_token_fingerprint =
        resolve_expected_fingerprint(&cfg, nostr_discovery_enabled, config_auth_token.as_deref())
            .map_err(TunnelError::config)?;

    // The interactive setup screen resolves the token when none is supplied. Quick mode
    // always generates a fresh ephemeral token (no existing-token input). Config mode
    // lets you paste a token (or supply it via config/env): it is the pre-shared
    // rendezvous secret both peers derive their key from, so it must be generated ahead
    // of time (`duopipe generate-auth-token`) and entered on each device — so
    // `auth_token_file` is optional there.

    // Config mode requires a `name`: each peer publishes its node id under this short
    // identifier, and a dialer types it to look the peer up.
    let peer_name = cfg.name.as_ref().map(|n| n.trim()).filter(|n| !n.is_empty());
    if nostr_discovery_enabled && peer_name.is_none() {
        return Err(TunnelError::config(anyhow::anyhow!(
            "Config mode requires a `name` (short identifier) in the config; a dialer uses it to find this peer."
        ))
        .into());
    }
    let peer_name = peer_name.map(|n| n.to_string());

    // Hold a process-lifetime exclusive lock on this name's local state file so two
    // duopipe instances on the same machine can't claim the same nostr name. This is
    // the same-machine counterpart to the cross-device nostr conflict resolution: it
    // fails fast at startup (the lock is held for the whole process, so there is no
    // mid-session local conflict). `_name_lock` must outlive `run_tui`; dropping it on
    // exit releases the lock. Quick mode (no name) takes no lock.
    // State/lock files are namespaced by the token fingerprint as well as the name.
    // The lock path runs only in config mode, where `expected_token_fingerprint` is
    // required and present; the eventual token is validated to match it, so this is the
    // same value the publisher derives from the resolved token below.
    let lock_fingerprint = expected_token_fingerprint
        .as_deref()
        .map(|fp| fp.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let _name_lock = match peer_name.as_deref() {
        Some(name) => match peer_state::acquire_name_lock(name, &lock_fingerprint) {
            Ok(lock) => Some(lock),
            Err(peer_state::NameLockError::Held) => {
                return Err(TunnelError::config(anyhow::anyhow!(
                    "Another duopipe process on this machine is already using the name '{name}'. \
                     Stop it first, or use a different `name` in the config."
                ))
                .into());
            }
            Err(peer_state::NameLockError::Io(e)) => {
                return Err(TunnelError::config(anyhow::anyhow!(
                    "Could not acquire the local name lock for '{name}': {e}"
                ))
                .into());
            }
        },
        None => None,
    };

    let log_buffer = log_buffer.expect("a TUI command initializes the log buffer");
    let launch = TuiLaunch {
        logs: log_buffer,
        tunnel: cfg.tunnel.clone(),
        relay_urls,
        relay_only,
        dns_server: cfg.dns_server.clone(),
        max_streams: cfg.max_streams,
        transport: cfg.transport.clone(),
        config_auth_token,
        expected_token_fingerprint,
        nostr_relays,
        nostr_discovery: nostr_discovery_enabled,
        peer_name,
        config_path,
    };

    tui::run_tui(launch).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_fp(fp: Option<&str>) -> PeerConfig {
        PeerConfig {
            auth_token_fingerprint: fp.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn quick_mode_ignores_fingerprint() {
        // Quick mode declares no fingerprint and never checks one.
        let cfg = cfg_with_fp(None);
        assert!(
            resolve_expected_fingerprint(&cfg, false, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn config_mode_requires_fingerprint() {
        let cfg = cfg_with_fp(None);
        let err = resolve_expected_fingerprint(&cfg, true, None).unwrap_err();
        assert!(err.to_string().contains("auth_token_fingerprint"));
    }

    #[test]
    fn config_mode_rejects_malformed_fingerprint() {
        let cfg = cfg_with_fp(Some("nothex"));
        assert!(resolve_expected_fingerprint(&cfg, true, None).is_err());
    }

    #[test]
    fn config_mode_returns_fingerprint_when_no_token_yet() {
        // No file/env token: the fingerprint is returned so setup can check a pasted one.
        let cfg = cfg_with_fp(Some("a1b2c3d4"));
        assert_eq!(
            resolve_expected_fingerprint(&cfg, true, None).unwrap(),
            Some("a1b2c3d4".to_string())
        );
    }

    #[test]
    fn config_mode_accepts_matching_token() {
        let token = auth::generate_token();
        let cfg = cfg_with_fp(Some(&auth::token_fingerprint(&token)));
        assert!(resolve_expected_fingerprint(&cfg, true, Some(&token)).is_ok());
    }

    #[test]
    fn config_mode_rejects_token_for_different_pairing() {
        let token = auth::generate_token();
        let other = auth::generate_token();
        let cfg = cfg_with_fp(Some(&auth::token_fingerprint(&other)));
        let err = resolve_expected_fingerprint(&cfg, true, Some(&token)).unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }
}
