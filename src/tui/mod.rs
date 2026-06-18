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

use crate::app_state::{AppSnapshot, AppState, Role, TunnelCommand};
use crate::config::{
    validate_request_specs, AllowedSources, RequestEntry, TransportTuning,
};
use crate::logging::LogBuffer;
use crate::peer_params::ResolvedPeer;
use setup::{SetupOutcome, SetupState, Step};
use ui::{AddField, AddRequestForm, UiState};

/// Refresh interval for the render tick (also bounds key-input latency).
const TICK: Duration = Duration::from_millis(200);

/// Everything the TUI needs to run setup and build the runtime `PeerConfig`.
pub struct TuiLaunch {
    pub logs: Arc<LogBuffer>,
    pub requests: Vec<RequestEntry>,
    pub allowed_sources: AllowedSources,
    /// Autostart all requests once connected (test mode only; see `DUOPIPE_TEST_MODE`).
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
        None => match run_setup(
            &mut terminal,
            &mut events,
            launch.config_auth_token.clone(),
            launch.allowed_sources.clone(),
        )
        .await
        {
            SetupOutcome::Resolved(r) => r,
            SetupOutcome::Quit => {
                ratatui::restore();
                return Ok(());
            }
        },
    };

    // Phase 2: build state + spawn the runtime.
    let state = AppState::new(
        resolved.role,
        resolved.token_generated,
        launch.logs.clone(),
        launch.requests.clone(),
    );
    let cfg = build_peer_config(&resolved, &launch, state.clone());
    let mut runtime = tokio::spawn(crate::iroh_mode::run_peer(cfg));

    // Phase 3: dashboard loop.
    let mut tick = tokio::time::interval(TICK);
    let mut ui_state = UiState::default();

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = state.snapshot();
                let logs = state.logs.snapshot();
                // Once a peer has connected, the generated-token banner is no longer
                // needed (the dialer already has it); hide it for the rest of the run.
                if !snap.peers.is_empty() {
                    ui_state.token_banner_hidden = true;
                }
                let _ = terminal.draw(|f| {
                    ui::render(f, &snap, &logs, &ui_state);
                    if let Some(form) = &ui_state.add_form {
                        ui::render_add_request_dialog(f, form);
                    }
                });
            }
            maybe = events.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        if handle_key(key, &mut ui_state, &state) {
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
        allowed_sources: resolved.allowed_sources.clone(),
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
    config_allowed_sources: AllowedSources,
) -> SetupOutcome {
    let mut state = SetupState::new(config_auth_token, config_allowed_sources);
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
/// stop the selected tunnel; `a` opens the add-request modal; `h` hides the
/// generated-token banner. Logs scroll with `PageUp`/`PageDown` and `[`/`]`.
fn handle_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) -> bool {
    // Ctrl-C always quits, even with the add-request modal open.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        state.shutdown.cancel();
        return true;
    }
    // While the modal is open it captures all other keys (so `q`/`j`/`k` are text).
    if ui.add_form.is_some() {
        handle_add_form(key, ui, state);
        return false;
    }

    let total = state.logs.len();
    let tunnels = state.tunnel_count();
    match key.code {
        KeyCode::Char('q') => {
            state.shutdown.cancel();
            return true;
        }
        KeyCode::Char('a') => {
            ui.add_form = Some(AddRequestForm::default());
        }
        KeyCode::Char('h') => {
            ui.token_banner_hidden = true;
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

/// Accept printable ASCII for the address fields (no spaces); `name` also allows
/// spaces as a free-form label.
fn is_field_char(c: char, field: AddField) -> bool {
    c.is_ascii_graphic() || (c == ' ' && field == AddField::Name)
}

/// Handle a key while the add-request modal is open. Tab/Enter advance the field;
/// Enter on the last field validates and (on success) adds + auto-starts the
/// request. Esc cancels.
fn handle_add_form(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    form.error = None;
    match key.code {
        KeyCode::Esc => {
            ui.add_form = None;
        }
        KeyCode::Tab => {
            form.field = match form.field {
                AddField::Name => AddField::RemoteSource,
                AddField::RemoteSource => AddField::LocalListen,
                AddField::LocalListen => AddField::Name,
            };
        }
        KeyCode::Enter => match form.field {
            AddField::Name => form.field = AddField::RemoteSource,
            AddField::RemoteSource => form.field = AddField::LocalListen,
            AddField::LocalListen => submit_add_form(ui, state),
        },
        KeyCode::Backspace => match form.field {
            AddField::Name => {
                form.name.pop();
            }
            AddField::RemoteSource => {
                form.remote_source.pop();
            }
            AddField::LocalListen => {
                form.local_listen.pop();
            }
        },
        KeyCode::Char(c) if is_field_char(c, form.field) => match form.field {
            AddField::Name => form.name.push(c),
            AddField::RemoteSource => form.remote_source.push(c),
            AddField::LocalListen => form.local_listen.push(c),
        },
        _ => {}
    }
}

/// Validate the modal's fields and, on success, append the request to `AppState`
/// and dispatch a `Start` so it auto-starts. A blank `name` falls back to the
/// `remote_source` string as the row label.
///
/// `Start` is broadcast: if currently disconnected there's no supervisor to
/// receive it, so the row stays Idle until started (consistent with config
/// requests after a reconnect).
fn submit_add_form(ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    let remote_source = form.remote_source.trim().to_string();
    let name = if form.name.trim().is_empty() {
        remote_source.clone()
    } else {
        form.name.trim().to_string()
    };
    let req = RequestEntry {
        name,
        remote_source,
        local_listen: form.local_listen.trim().to_string(),
    };
    match validate_request_specs(std::slice::from_ref(&req)) {
        Ok(()) => {
            let idx = state.add_request(req);
            state.send_command(TunnelCommand::Start(idx));
            ui.selected = idx;
            ui.add_form = None;
        }
        Err(e) => {
            form.error = Some(e.to_string());
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyCode;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn state() -> Arc<AppState> {
        AppState::new(Role::Dial, false, LogBuffer::new(16), Vec::new())
    }

    fn type_str(ui: &mut UiState, st: &Arc<AppState>, s: &str) {
        for c in s.chars() {
            handle_add_form(key(KeyCode::Char(c)), ui, st);
        }
    }

    #[test]
    fn add_form_valid_submit_appends_and_closes() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "ssh");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> RemoteSource
        type_str(&mut ui, &st, "tcp://127.0.0.1:22");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:2222");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit

        assert!(ui.add_form.is_none(), "form closes on successful submit");
        assert_eq!(st.request_count(), 1);
        assert_eq!(ui.selected, 0);
        let req = st.get_request(0).unwrap();
        assert_eq!(req.name, "ssh");
        assert_eq!(req.remote_source, "tcp://127.0.0.1:22");
        assert_eq!(req.local_listen, "127.0.0.1:2222");
    }

    #[test]
    fn add_form_invalid_source_keeps_form_open_with_error() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
            ..Default::default()
        };
        // Skip name; bad remote_source (missing scheme); any local_listen.
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // Name -> RemoteSource
        type_str(&mut ui, &st, "127.0.0.1:22"); // no tcp:// scheme
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:2222");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit -> error

        let form = ui.add_form.as_ref().expect("form stays open on error");
        assert!(form.error.is_some());
        assert_eq!(st.request_count(), 0, "no request added on invalid input");
    }

    #[test]
    fn add_form_esc_cancels() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "x");
        handle_add_form(key(KeyCode::Esc), &mut ui, &st);
        assert!(ui.add_form.is_none());
        assert_eq!(st.request_count(), 0);
    }
}
