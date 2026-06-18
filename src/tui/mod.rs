//! Terminal UI for a running peer.
//!
//! The TUI owns the whole lifecycle: it first runs an interactive setup screen
//! (unless a non-interactive preset is supplied), then spawns the peer runtime
//! and renders the live dashboard. A fatal runtime error tears the TUI down and
//! propagates out; `q`/`Ctrl-C` cancels the shared shutdown token, which both
//! ends this loop and stops the runtime.

mod setup;
mod ui;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use ratatui::crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::app_state::{AppSnapshot, AppState, Role};
use crate::config::{AllowedSources, RequestEntry, TransportTuning};
use crate::logging::LogBuffer;
use crate::peer_params::ResolvedPeer;
use setup::{SetupOutcome, SetupState, Step};
use ui::UiState;

/// Refresh interval for the render tick (also bounds key-input latency).
const TICK: Duration = Duration::from_millis(200);

/// Everything the TUI needs to run setup and build the runtime `PeerConfig`.
pub struct TuiLaunch {
    pub logs: Arc<LogBuffer>,
    pub requests: Vec<RequestEntry>,
    pub allowed_sources: AllowedSources,
    /// Autostart all requests once connected (from `DUOPIPE_AUTOSTART_REQUESTS`).
    pub autostart_requests: bool,
    pub relay_urls: Vec<String>,
    pub relay_only: bool,
    pub dns_server: Option<String>,
    pub max_sessions: Option<usize>,
    pub transport: TransportTuning,
    /// Print the bound node id + token to stderr (non-interactive/test mode).
    pub announce_endpoint: bool,
    /// A valid auth token from config/env (pre-seeds the dial flow; used directly
    /// for listen). Pre-validated in main.
    pub config_auth_token: Option<String>,
    /// Pre-resolved role/target/token (env/non-interactive). When `Some`, the
    /// interactive setup screen is skipped.
    pub preset: Option<ResolvedPeer>,
}

/// Run the interactive setup, then the live dashboard, until the user quits or
/// the runtime stops. Initializes and restores the terminal on every exit path.
pub async fn run_tui(launch: TuiLaunch) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut events = EventStream::new();

    // Phase 1: resolve role/target/token (skip when a preset is supplied).
    let resolved = match launch.preset.clone() {
        Some(preset) => preset,
        None => match run_setup(&mut terminal, &mut events, launch.config_auth_token.clone()).await
        {
            SetupOutcome::Resolved(r) => r,
            SetupOutcome::Quit => {
                ratatui::restore();
                return Ok(());
            }
        },
    };

    // Phase 2: build state + spawn the runtime.
    let state = AppState::new(resolved.role, resolved.token_generated, launch.logs.clone());
    let cfg = build_peer_config(&resolved, &launch, state.clone());
    let mut runtime = tokio::spawn(crate::iroh_mode::run_peer(cfg));

    // Phase 3: dashboard loop.
    let mut tick = tokio::time::interval(TICK);
    let mut ui_state = UiState::default();
    // Listen + freshly generated token: show it once in a modal (with the node
    // id) before the dashboard. For security the token is shown nowhere else.
    let mut token_dialog = resolved.role == Role::Listen && resolved.token_generated;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = state.snapshot();
                let logs = state.logs.snapshot();
                let _ = terminal.draw(|f| {
                    if token_dialog {
                        ui::render_token_dialog(f, &snap);
                    } else {
                        ui::render(f, &snap, &logs, &ui_state);
                    }
                });
            }
            maybe = events.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        if token_dialog {
                            // Any key dismisses the one-time token dialog; Ctrl-C quits.
                            if key.code == KeyCode::Char('c')
                                && key.modifiers.contains(KeyModifiers::CONTROL)
                            {
                                state.shutdown.cancel();
                                break;
                            }
                            token_dialog = false;
                        } else if handle_key(key, &mut ui_state, &state) {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            _ = state.shutdown.cancelled() => break,
            r = &mut runtime => {
                // The runtime stopped on its own (fatal error or clean end).
                state.shutdown.cancel();
                ratatui::restore();
                return match r {
                    Ok(inner) => inner,
                    Err(e) => Err(anyhow::anyhow!("peer task failed: {e}")),
                };
            }
        }
    }

    // Reached on `q`/Ctrl-C or external shutdown: let the runtime close cleanly.
    state.shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), runtime).await;
    ratatui::restore();
    Ok(())
}

fn build_peer_config(
    resolved: &ResolvedPeer,
    launch: &TuiLaunch,
    state: Arc<AppState>,
) -> crate::iroh_mode::PeerConfig {
    crate::iroh_mode::PeerConfig {
        role: resolved.role,
        peer_node_id: resolved.peer_node_id,
        requests: launch.requests.clone(),
        allowed_sources: launch.allowed_sources.clone(),
        autostart_requests: launch.autostart_requests,
        auth_token: resolved.auth_token.clone(),
        relay_urls: launch.relay_urls.clone(),
        relay_only: launch.relay_only,
        dns_server: launch.dns_server.clone(),
        max_sessions: launch.max_sessions,
        transport: launch.transport.clone(),
        announce_endpoint: launch.announce_endpoint,
        status: state,
    }
}

/// Run the interactive setup screen until it resolves or the user quits.
async fn run_setup(
    terminal: &mut DefaultTerminal,
    events: &mut EventStream,
    config_auth_token: Option<String>,
) -> SetupOutcome {
    let mut state = SetupState::new(config_auth_token);
    let mut tick = tokio::time::interval(TICK);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let _ = terminal.draw(|f| setup::render(f, &state));
            }
            maybe = events.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        match setup::handle_key(key, &mut state) {
                            Step::Continue => {}
                            Step::Done(resolved) => return SetupOutcome::Resolved(resolved),
                            Step::Quit => return SetupOutcome::Quit,
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return SetupOutcome::Quit,
                }
            }
        }
    }
}

/// Handle a dashboard key press. Returns `true` when the UI should exit.
///
/// Arrows / `j`/`k` move the tunnel selection cursor; `Enter`/`Space` start or
/// stop the selected tunnel. Logs scroll with `PageUp`/`PageDown` and `[`/`]`.
fn handle_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) -> bool {
    let total = state.logs.len();
    let tunnels = state.tunnel_count();
    match key.code {
        KeyCode::Char('q') => {
            state.shutdown.cancel();
            return true;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.shutdown.cancel();
            return true;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            ui.selected = ui.selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if tunnels > 0 {
                ui.selected = (ui.selected + 1).min(tunnels - 1);
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if ui.selected < tunnels {
                state.toggle_tunnel(ui.selected);
            }
        }
        KeyCode::Char(']') => {
            ui.log_scroll = ui.log_scroll.saturating_add(1).min(total);
        }
        KeyCode::Char('[') => {
            ui.log_scroll = ui.log_scroll.saturating_sub(1);
        }
        KeyCode::PageUp => {
            ui.log_scroll = ui.log_scroll.saturating_add(10).min(total);
        }
        KeyCode::PageDown => {
            ui.log_scroll = ui.log_scroll.saturating_sub(10);
        }
        KeyCode::Char('g') => ui.log_scroll = total,
        KeyCode::Char('G') => ui.log_scroll = 0,
        KeyCode::Char('d') => match dump_connection_info(&state.snapshot()) {
            Ok(path) => log::info!("Wrote connection info (no auth token) to {path}"),
            Err(e) => log::warn!("Failed to write connection info: {e}"),
        },
        _ => {}
    }
    false
}

/// Write the current connection info to a timestamped file in the system temp
/// directory (`/tmp` on Linux) and return its path. The auth token is
/// deliberately excluded so the dump is safe to share. Used by the `d` shortcut.
fn dump_connection_info(snap: &AppSnapshot) -> std::io::Result<String> {
    use std::fmt::Write as _;

    let now = jiff::Zoned::now();
    let path =
        std::env::temp_dir().join(format!("duopipe-conn-{}.txt", now.strftime("%Y%m%d-%H%M%S")));

    let mut out = String::new();
    let _ = writeln!(out, "duopipe connection info");
    let _ = writeln!(out, "generated: {}", now.strftime("%Y-%m-%d %H:%M:%S"));
    let _ = writeln!(out, "host:      {}", snap.hostname);
    let _ = writeln!(out, "role:      {}", snap.role.label());
    let _ = writeln!(
        out,
        "node id:   {}",
        snap.endpoint_id.as_deref().unwrap_or("(pending)")
    );
    if snap.role == Role::Dial {
        let _ = writeln!(out, "status:    {}", snap.conn_status.label());
        let _ = writeln!(out, "path:      {}", snap.path.describe());
    }
    let _ = writeln!(
        out,
        "sessions:  {}/{}",
        snap.sessions_used, snap.sessions_max
    );

    let _ = writeln!(out, "\nTunnels:");
    if snap.tunnels.is_empty() {
        let _ = writeln!(out, "  (none configured)");
    } else {
        for t in &snap.tunnels {
            let _ = writeln!(
                out,
                "  {:<16} {:<40} {:<10} {}",
                t.name,
                t.spec,
                t.status.label(),
                t.detail
            );
        }
    }

    let _ = writeln!(out, "\nConnected peers:");
    if snap.peers.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        for p in &snap.peers {
            let _ = writeln!(
                out,
                "  {}  up {}s  {}",
                p.remote_id,
                p.connected_since.elapsed().as_secs(),
                p.path.describe()
            );
        }
    }

    let _ = writeln!(out, "\n(auth token intentionally omitted)");

    std::fs::write(&path, out)?;
    Ok(path.display().to_string())
}
