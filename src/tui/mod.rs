//! Terminal UI for a running peer.
//!
//! The TUI owns the whole lifecycle: it first runs an interactive setup screen
//! (unless a non-interactive preset is supplied), then spawns the peer runtime
//! and renders the live dashboard. A fatal runtime error tears the TUI down and
//! propagates out; `q`/`Ctrl-C` cancels the shared shutdown token, which both
//! ends this loop and stops the runtime.

mod setup;
mod textinput;
mod ui;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::StreamExt;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};

use crate::app_state::{
    AppSnapshot, AppState, DialCommand, DialTarget, NameCommand, NameConflict, Role,
};
use crate::config::TransportTuning;
use crate::logging::LogBuffer;
use crate::peer_params::ResolvedPeer;
use iroh::EndpointId;
use setup::{SetupOutcome, SetupState, Step};
use textinput::handle_edit;
use ui::{ConnectForm, Screen, SocksForm, UiState};

/// Refresh interval for the render tick (also bounds key-input latency).
const TICK: Duration = Duration::from_millis(200);
/// How long the generated-secret banner (the manual-mode auth token or the quick-mode
/// rotating PIN) stays shown before auto-hiding. Re-showing it with `h` re-arms the same
/// window.
const GENERATED_TOKEN_AUTO_HIDE_AFTER: Duration = Duration::from_secs(10 * 60);

/// Everything the TUI needs to run setup and build the runtime `PeerConfig`.
pub struct TuiLaunch {
    pub logs: Arc<LogBuffer>,
    pub socks_port: Option<u16>,
    pub relay_urls: Vec<String>,
    pub relay_only: bool,
    pub dns_server: Option<String>,
    pub max_streams: Option<usize>,
    pub transport: TransportTuning,
    /// A valid auth token from config/env (pre-seeds the dial flow; used directly
    /// for listen). Pre-validated in main.
    pub config_auth_token: Option<String>,
    /// Expected token fingerprint declared by a config-mode config (`auth_token_fingerprint`),
    /// already validated in main. When set, a token pasted at the setup screen must match
    /// it. `None` in quick mode.
    pub expected_token_fingerprint: Option<String>,
    /// Nostr relay URLs for node-id discovery.
    pub nostr_relays: Vec<String>,
    /// Whether nostr node-id discovery is enabled (listener publishes, dialer
    /// looks up). The iroh identity is always ephemeral regardless.
    pub nostr_discovery: bool,
    /// This peer's own short identifier (config `name`), published under when
    /// listening in config mode. `None` in quick mode.
    pub peer_name: Option<String>,
    /// Path to the loaded peer config file (config mode), for the name-conflict rename
    /// nudge. `None` in quick mode.
    pub config_path: Option<std::path::PathBuf>,
}

/// Run the interactive setup, then the live dashboard, until the user quits or
/// the runtime stops. Initializes and restores the terminal on every exit path.
pub async fn run_tui(launch: TuiLaunch) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut events = EventStream::new();

    // Phase 1: resolve the auth token via the setup screen.
    let resolved = match run_setup(
        &mut terminal,
        &mut events,
        launch.config_auth_token.clone(),
        launch.expected_token_fingerprint.clone(),
        launch.nostr_discovery,
        launch.peer_name.clone(),
    )
    .await
    {
        SetupOutcome::Resolved(r) => r,
        SetupOutcome::Quit => {
            ratatui::restore();
            return Ok(());
        }
    };

    // Phase 2: build state + spawn the runtime.
    let state = AppState::new(
        resolved.role,
        resolved.token_generated,
        launch.logs.clone(),
        launch.socks_port,
        launch.nostr_discovery,
        launch.peer_name.clone(),
        resolved.quick_pin,
    );
    // Seed the active token now so the header fingerprint is populated from the first
    // frame (the runtime sets the same value again once it starts — idempotent). Quick PIN
    // mode has no token, so there is nothing to seed.
    if let Some(token) = resolved.auth_token.clone() {
        state.set_auth_token(token);
    }
    let cfg = build_peer_config(&resolved, &launch, state.clone());
    let mut runtime = tokio::spawn(crate::iroh_mode::run_peer(cfg));

    // Phase 3: dashboard loop.
    let mut tick = tokio::time::interval(TICK);
    let mut ui_state = UiState::default();

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = state.snapshot();
                // Pick the ring view matching the toggle; the verbose view merges both.
                let logs = if ui_state.verbose {
                    state.logs.verbose_snapshot()
                } else {
                    state.logs.concise_snapshot()
                };
                // When the first peer connects, hide the generated-secret banner once (the
                // dialer already has what it needs). It's a one-shot, not a per-tick force,
                // so the user can still toggle it back with `h` afterwards (e.g. to pair
                // another device in PIN mode).
                if snap.inbound.is_some() && !ui_state.peers_seen {
                    ui_state.peers_seen = true;
                    hide_token_banner(&mut ui_state);
                }
                maybe_auto_hide_generated_token_banner(&mut ui_state, &snap, Instant::now());
                let _ = terminal.draw(|f| {
                    ui::render(f, &snap, &logs, &ui_state);
                    if let Some(form) = &ui_state.add_form {
                        ui::render_add_tunnel_dialog(f, form);
                    }
                    if let Some(form) = &ui_state.connect_form {
                        ui::render_connect_dialog(f, form, state.nostr_discovery, state.pin_mode);
                    }
                    // A name-conflict prompt is drawn last so it sits on top of any
                    // other modal until the user resolves it.
                    if let NameConflict::Prompt { message } = &snap.name_conflict {
                        ui::render_name_conflict_dialog(f, message);
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
    // The nostr identifier is role-dependent: a listener (or the always-on serve half
    // of an interactive `Both` process) publishes under its own name; a headless dialer
    // looks up the target's name. Interactive dial targets are supplied at runtime via
    // DialCommand, so `Both` carries only the own name here.
    let nostr_identifier = match resolved.role {
        Role::Listen | Role::Both => launch.peer_name.clone(),
        Role::Dial => resolved.peer_identifier.clone(),
    };
    crate::iroh_mode::PeerConfig {
        role: resolved.role,
        peer_node_id: resolved.peer_node_id,
        autostart_socks: false,
        auth_token: resolved.auth_token.clone(),
        nostr_relays: launch.nostr_relays.clone(),
        nostr_discovery: launch.nostr_discovery,
        nostr_identifier,
        // Quick PIN mode publishes/resolves the rotating PIN over nostr.
        pin_rendezvous: resolved.quick_pin,
        report_endpoint_id: true,
        relay_urls: launch.relay_urls.clone(),
        relay_only: launch.relay_only,
        dns_server: launch.dns_server.clone(),
        max_streams: launch.max_streams,
        transport: launch.transport.clone(),
        announce_endpoint: false,
        config_path: launch.config_path.clone(),
        status: state,
    }
}

/// Run the interactive setup screen until it resolves or the user quits.
async fn run_setup(
    terminal: &mut DefaultTerminal,
    events: &mut EventStream,
    config_auth_token: Option<String>,
    expected_token_fingerprint: Option<String>,
    nostr_discovery: bool,
    own_name: Option<String>,
) -> SetupOutcome {
    let mut state = SetupState::new(
        config_auth_token,
        expected_token_fingerprint,
        nostr_discovery,
        own_name,
    );
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
/// The dashboard has two screens, toggled with `l`: the home screen (tunnels +
/// peers) and the logs screen. Keys that only make sense for one screen are routed
/// to that screen's handler so they don't collide (e.g. `g`/`G` scroll logs but do
/// nothing on home). Emergency quit (`Ctrl-C`), the screen toggle, and `h` (hide the
/// generated-token banner) work on either screen. `Esc` dismisses the logs screen back
/// to home; on the home screen a double-`Esc` quits.
fn handle_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) -> bool {
    // Ctrl-C is an always-available emergency quit, even with the modal open.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        state.shutdown.cancel();
        return true;
    }
    // A name-conflict prompt is runtime-critical: it captures all keys until the user
    // takes over, renames, or declines (the publisher then drives the outcome).
    if let NameConflict::Prompt { .. } = state.name_conflict() {
        handle_conflict_prompt(key, state);
        return false;
    }
    // While a modal is open it captures all other keys (so `j`/`k`/`q` are text).
    if ui.add_form.is_some() {
        handle_add_form(key, ui, state);
        return false;
    }
    if ui.connect_form.is_some() {
        handle_connect_form(key, ui, state);
        return false;
    }

    if key.code == KeyCode::Esc {
        // On the logs screen, Esc first exits scroll mode (back to following the
        // tail); only once already at the tail does it dismiss back to home. Neither
        // quits.
        if ui.screen == Screen::Logs {
            if ui.log_scroll > 0 {
                ui.log_scroll = 0;
            } else {
                ui.screen = Screen::Home;
            }
            ui.quit_armed = false;
            return false;
        }
        // On home, quit on a double Esc: the first Esc arms it, a second (with no
        // other key in between) confirms. Any other key disarms it.
        if ui.quit_armed {
            state.shutdown.cancel();
            return true;
        }
        ui.quit_armed = true;
        return false;
    }
    ui.quit_armed = false;

    // Screen toggle and the token-banner hide work regardless of which screen is up.
    match key.code {
        KeyCode::Char('l') => {
            ui.screen = match ui.screen {
                Screen::Home => Screen::Logs,
                Screen::Logs => Screen::Home,
            };
            return false;
        }
        KeyCode::Char('h') => {
            toggle_token_banner(ui);
            return false;
        }
        _ => {}
    }

    match ui.screen {
        Screen::Home => handle_home_key(key, ui, state),
        Screen::Logs => handle_logs_key(key, ui, state),
    }
    false
}

/// Home-screen keys. `Shift` is reserved for session lifecycle (`Shift-L` start/stop the
/// serve half, `Shift-C` connect / `Shift-D` disconnect the dial session); SOCKS proxy
/// actions are plain keys.
///
/// One-pairing rule: `Shift-C` is inert while listening and `Shift-L` while a dial
/// session exists (the runtime refuses these too; the hints are hidden). The SOCKS5
/// proxy is symmetric — once paired, either side can bind it: `e` opens the set-port
/// modal (only while the proxy is not running), `s`/`x` start/stop it (`s` is a
/// deliberate key, never the accidental `Enter`), `d` clears the port from the session
/// (config is untouched). `w` writes (dumps) the connection info to a file.
/// `Enter`/`Space` are intentionally inert here.
fn handle_home_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    match key.code {
        // Start / stop the serve half (Shift+L). It does not auto-start: this is the only
        // way to bring up the node id, PIN, and auth-token display. Refused while a dial
        // session exists (one pairing per run). Toggling stop tears the endpoint down; a
        // later start mints a fresh ephemeral id.
        KeyCode::Char('L') if state.role == Role::Both && state.can_listen() => {
            state.toggle_listen();
        }
        // Connect / re-point the on-demand dial session. Refused while listening (one
        // pairing per run).
        KeyCode::Char('C') if state.role == Role::Both && state.can_dial() => {
            ui.connect_form = Some(ConnectForm::default());
        }
        // Disconnect the current dial session, returning to idle.
        KeyCode::Char('D') if state.role == Role::Both => {
            state.send_dial(DialCommand::Disconnect);
        }
        // Set or replace the local SOCKS5 port — only while the proxy is not running (a
        // Listening proxy must be stopped first so its bound port isn't orphaned).
        KeyCode::Char('e') if !state.socks_running() => {
            ui.add_form = Some(match state.socks_port() {
                Some(port) => SocksForm::edit(port),
                None => SocksForm::default(),
            });
        }
        // Start / stop the local SOCKS5 proxy — a deliberate keypress, never automatic.
        KeyCode::Char('s') => state.start_socks(),
        KeyCode::Char('x') => state.stop_socks(),
        // Clear the SOCKS port from the session (config untouched).
        KeyCode::Char('d') | KeyCode::Delete => state.clear_socks(),
        KeyCode::Char('w') => match dump_connection_info(&state.snapshot()) {
            Ok(path) => log::info!("Wrote connection info (no auth token) to {path}"),
            Err(e) => log::warn!("Failed to write connection info: {e}"),
        },
        _ => {}
    }
}

/// Logs-screen keys: `v` toggles verbose (show the suppressed iroh/quinn churn);
/// scroll the log pane with `[`/`]`, `PageUp`/`PageDown`, and `g`/`G` (top/bottom).
fn handle_logs_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    let total = if ui.verbose {
        state.logs.verbose_len()
    } else {
        state.logs.concise_len()
    };
    match key.code {
        // Toggle the full unfiltered view. The visible-line count changes, so snap back
        // to the tail to avoid landing on a stale scroll offset.
        KeyCode::Char('v') => {
            ui.verbose = !ui.verbose;
            ui.log_scroll = 0;
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
        _ => {}
    }
}

/// Handle a key while a name-conflict prompt is showing. The decision is sent to the
/// publisher, which clears the prompt and acts (take over / rename nudge + decline /
/// decline). No quit happens here: the publisher cancels the shared shutdown for a
/// startup decline, which the dashboard loop already watches.
fn handle_conflict_prompt(key: KeyEvent, state: &Arc<AppState>) {
    match key.code {
        KeyCode::Char('t') | KeyCode::Char('T') => {
            state.send_name(NameCommand::TakeOver);
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            state.send_name(NameCommand::Rename);
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.send_name(NameCommand::Decline);
        }
        _ => {}
    }
}

fn hide_token_banner(ui: &mut UiState) {
    ui.token_banner_hidden = true;
    ui.token_banner_auto_hide_at = None;
}

/// Toggle the generated-secret banner. Hiding clears the auto-hide deadline; re-showing
/// leaves it cleared so the next tick re-arms a fresh auto-hide window.
fn toggle_token_banner(ui: &mut UiState) {
    if ui.token_banner_hidden {
        ui.token_banner_hidden = false;
        ui.token_banner_auto_hide_at = None;
    } else {
        hide_token_banner(ui);
    }
}

fn maybe_auto_hide_generated_token_banner(ui: &mut UiState, snap: &AppSnapshot, now: Instant) {
    if ui.token_banner_hidden {
        ui.token_banner_auto_hide_at = None;
        return;
    }

    if !matches!(snap.role, Role::Listen | Role::Both) || !snap.token_generated {
        ui.token_banner_auto_hide_at = None;
        return;
    }

    let deadline = *ui
        .token_banner_auto_hide_at
        .get_or_insert(now + GENERATED_TOKEN_AUTO_HIDE_AFTER);
    if now >= deadline {
        hide_token_banner(ui);
    }
}

/// Handle a key while the set-SOCKS-port modal is open. Enter validates and (on
/// success) sets the port; the proxy stays Idle until `s`. Esc cancels.
fn handle_add_form(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    form.error = None;
    match key.code {
        KeyCode::Esc => {
            ui.add_form = None;
        }
        KeyCode::Enter => submit_socks_form(ui, state),
        _ => handle_edit(&mut form.port, key, |c| c.is_ascii_digit()),
    }
}

/// Validate the modal's port and, on success, set (or replace) the SOCKS5 port.
/// Saving only *sets* the port — it leaves the proxy Idle; the user starts it
/// deliberately with `s`. Port must be a decimal in 1..=65535.
fn submit_socks_form(ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    let raw = form.port.value().trim();
    match raw.parse::<u16>() {
        Ok(port) if port != 0 => {
            state.set_socks_port(port);
            ui.add_form = None;
        }
        _ => {
            form.error = Some("Enter a port number in 1..=65535".to_string());
        }
    }
}

/// Handle a key while the connect modal is open. Enter validates the target and (on
/// success) starts the on-demand dial session; Esc cancels.
fn handle_connect_form(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.connect_form.as_mut() else {
        return;
    };
    form.error = None;
    match key.code {
        KeyCode::Esc => {
            ui.connect_form = None;
        }
        KeyCode::Enter => submit_connect_form(ui, state),
        _ => handle_edit(&mut form.target, key, |c| c.is_ascii_graphic()),
    }
}

/// Validate the connect modal's target and, on success, set the display target and
/// dispatch `DialCommand::Connect` (replacing any current session). In config mode the
/// entry is a peer name (rejecting our own); in quick mode a node id (rejecting our own
/// published id).
fn submit_connect_form(ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.connect_form.as_mut() else {
        return;
    };
    let raw = form.target.value().trim().to_string();
    let target = if state.nostr_discovery {
        if raw.is_empty() {
            form.error = Some("Enter the peer's name".to_string());
            return;
        }
        if state.own_name.as_deref().map(str::trim) == Some(raw.as_str()) {
            form.error =
                Some("That is this peer's own name; enter the other peer's name".to_string());
            return;
        }
        // Every valid listener name is alphanumeric + `_`, so reject anything else up
        // front rather than dialing a name that can never resolve.
        if let Err(e) = crate::config::validate_name(&raw) {
            form.error = Some(e.to_string());
            return;
        }
        DialTarget::Name(raw)
    } else if state.pin_mode {
        // Quick PIN mode: the user types the rotating code from the other device. Normalize
        // (ignore dashes/spaces/case) and validate the format up front; resolution to a node
        // id + token happens via nostr in the dial session.
        if raw.is_empty() {
            form.error = Some("Enter the PIN shown on the other device".to_string());
            return;
        }
        match crate::pin::normalize_pin(&raw) {
            Some(canonical) => DialTarget::Pin(canonical),
            None => {
                form.error = Some(format!(
                    "That is not a valid {}-character PIN (check for a typo)",
                    crate::pin::PIN_LEN
                ));
                return;
            }
        }
    } else {
        if raw.is_empty() {
            form.error = Some("Enter the peer's node id".to_string());
            return;
        }
        match raw.parse::<EndpointId>() {
            Ok(id) => {
                // Reject dialing our own published node id (a self-dial loop).
                if let Some(own) = state.snapshot().endpoint_id
                    && own.parse::<EndpointId>().ok() == Some(id)
                {
                    form.error = Some("That is this peer's own node id".to_string());
                    return;
                }
                DialTarget::NodeId(id)
            }
            Err(_) => {
                form.error = Some("Invalid node id".to_string());
                return;
            }
        }
    };
    // Only commit the displayed target and close the modal if the command actually
    // reached the dial manager; otherwise keep the form open with an error rather than
    // silently showing a target that never connects.
    let display = target.describe();
    if state.send_dial(DialCommand::Connect(target)) {
        state.set_dial_target(Some(display));
        ui.connect_form = None;
    } else {
        form.error = Some("Dial manager is not running; cannot connect".to_string());
    }
}

/// Write the current connection info to a timestamped file in the system temp
/// directory (`/tmp` on Linux) and return its path. The auth token is
/// deliberately excluded so the dump is safe to share. Used by the `d` shortcut.
fn dump_connection_info(snap: &AppSnapshot) -> std::io::Result<String> {
    use std::fmt::Write as _;

    let now = jiff::Zoned::now();
    let path = std::env::temp_dir().join(format!(
        "duopipe-conn-{}.txt",
        now.strftime("%Y%m%d-%H%M%S")
    ));

    let mut out = String::new();
    let _ = writeln!(out, "duopipe connection info");
    let _ = writeln!(out, "generated: {}", now.strftime("%Y-%m-%d %H:%M:%S"));
    let _ = writeln!(out, "host:      {}", snap.hostname);
    let _ = writeln!(out, "mode:      {}", ui::mode_label(snap));
    if let Some(name) = ui::own_name_display(snap) {
        let _ = writeln!(out, "name:      {name}");
    }
    let _ = writeln!(
        out,
        "node id:   {}",
        snap.endpoint_id.as_deref().unwrap_or("(pending)")
    );
    if let Some(target) = snap.dial_target.as_deref() {
        let _ = writeln!(out, "outbound:  {target}");
        let _ = writeln!(out, "status:    {}", snap.conn_status.label());
        let _ = writeln!(out, "path:      {}", snap.path.describe());
    } else {
        let _ = writeln!(out, "outbound:  not connected");
    }
    let _ = writeln!(out, "streams:   {}/{}", snap.streams_used, snap.streams_max);
    if let Some(token) = snap.auth_token.as_deref() {
        let _ = writeln!(out, "token fp:  {}", crate::auth::token_fingerprint(token));
    }

    let _ = writeln!(out, "\nSOCKS5 proxy:");
    match &snap.socks {
        None => {
            let _ = writeln!(out, "  (no port set)");
        }
        Some(s) => {
            let _ = writeln!(
                out,
                "  socks5 127.0.0.1:{:<12} {:<10} {}",
                s.port,
                s.status.label(),
                s.detail
            );
        }
    }

    let _ = writeln!(out, "\nInbound peer:");
    match &snap.inbound {
        None => {
            let _ = writeln!(out, "  (none)");
        }
        Some(p) if p.connected() => {
            let _ = writeln!(
                out,
                "  {}  up {}s  {}",
                p.remote_id,
                p.connected_since.elapsed().as_secs(),
                p.path.describe()
            );
        }
        Some(p) => {
            let _ = writeln!(out, "  {}", ui::reserved_inbound_label(&p.remote_id));
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
        AppState::new(Role::Dial, false, LogBuffer::new(16), None, false, None, false)
    }

    fn listen_generated_state() -> Arc<AppState> {
        AppState::new(Role::Listen, true, LogBuffer::new(16), None, false, None, false)
    }

    fn type_str(ui: &mut UiState, st: &Arc<AppState>, s: &str) {
        for c in s.chars() {
            handle_add_form(key(KeyCode::Char(c)), ui, st);
        }
    }

    fn type_connect_target(ui: &mut UiState, st: &Arc<AppState>, s: &str) {
        for c in s.chars() {
            handle_connect_form(key(KeyCode::Char(c)), ui, st);
        }
    }

    #[test]
    fn pin_mode_connect_form_normalizes_and_rejects_bad_pin() {
        // pin_mode = true, nostr_discovery = false (quick PIN mode).
        let st = AppState::new(Role::Both, false, LogBuffer::new(16), None, false, None, true);

        // A dashed, lowercase PIN passes normalization+validation; with no dial manager
        // running the only remaining error is the dial-manager one (i.e. it got that far).
        // Generate a real PIN so it carries a valid check digit, then group + lowercase it.
        let valid_pin = crate::pin::format_pin(&crate::pin::generate_pin()).to_ascii_lowercase();
        let mut ui = UiState {
            connect_form: Some(ConnectForm::default()),
            ..Default::default()
        };
        type_connect_target(&mut ui, &st, &valid_pin);
        handle_connect_form(key(KeyCode::Enter), &mut ui, &st);
        let form = ui.connect_form.as_ref().expect("form stays open");
        assert_eq!(
            form.error.as_deref(),
            Some("Dial manager is not running; cannot connect"),
            "valid PIN passed validation"
        );

        // A malformed PIN is rejected up front with a format error.
        let mut ui = UiState {
            connect_form: Some(ConnectForm::default()),
            ..Default::default()
        };
        type_connect_target(&mut ui, &st, "nope");
        handle_connect_form(key(KeyCode::Enter), &mut ui, &st);
        let form = ui.connect_form.as_ref().expect("form stays open");
        assert!(
            form.error.as_deref().unwrap_or("").contains("valid"),
            "bad PIN rejected: {:?}",
            form.error
        );
    }

    #[test]
    fn connect_submit_keeps_modal_open_when_dial_manager_is_absent() {
        let st = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            None,
            true,
            Some("web1".to_string()),
            false,
        );
        let mut ui = UiState {
            connect_form: Some(ConnectForm::default()),
            ..Default::default()
        };

        type_connect_target(&mut ui, &st, "homelab");
        handle_connect_form(key(KeyCode::Enter), &mut ui, &st);

        let form = ui.connect_form.as_ref().expect("form stays open");
        assert_eq!(
            form.error.as_deref(),
            Some("Dial manager is not running; cannot connect")
        );
        assert_eq!(st.snapshot().dial_target, None);
    }

    #[test]
    fn add_form_valid_submit_sets_socks_port_and_closes() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(SocksForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "1080");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit

        assert!(ui.add_form.is_none(), "form closes on successful submit");
        assert_eq!(st.socks_port(), Some(1080));
    }

    #[test]
    fn add_form_rejects_only_digits() {
        // Non-digit characters are filtered by the field char guard.
        let st = state();
        let mut ui = UiState {
            add_form: Some(SocksForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "10a8b0");
        assert_eq!(ui.add_form.as_ref().unwrap().port.value(), "1080");
    }

    #[test]
    fn add_form_invalid_port_keeps_form_open_with_error() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(SocksForm::default()),
            ..Default::default()
        };
        // Port 0 is rejected.
        type_str(&mut ui, &st, "0");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit -> error

        let form = ui.add_form.as_ref().expect("form stays open on error");
        assert!(form.error.is_some());
        assert!(!st.has_socks(), "no port set on invalid input");
    }

    #[test]
    fn d_key_clears_the_socks_port() {
        let st = state();
        st.set_socks_port(1080);
        let mut ui = UiState::default();

        // `d` clears the SOCKS port.
        assert!(!handle_key(key(KeyCode::Char('d')), &mut ui, &st));
        assert!(!st.has_socks());
        // Pressing delete with no port is a harmless no-op.
        assert!(!handle_key(key(KeyCode::Delete), &mut ui, &st));
        assert!(!st.has_socks());
    }

    #[test]
    fn e_key_opens_set_form_prefilled_from_current_port() {
        let st = state();
        st.set_socks_port(5353);
        let mut ui = UiState::default();

        assert!(!handle_key(key(KeyCode::Char('e')), &mut ui, &st));
        let form = ui.add_form.as_ref().expect("set form opened");
        assert_eq!(form.port.value(), "5353");
    }

    #[test]
    fn s_x_drive_socks_and_enter_is_inert() {
        // With a port configured, `s`/`x` are accepted (no panic, no quit) and bare
        // Enter/Space do nothing on the dashboard. There is no supervisor in a unit
        // test, so this asserts the keymap wiring, not the bind.
        let st = state();
        st.set_socks_port(1080);
        let mut ui = UiState::default();

        for code in [
            KeyCode::Enter,
            KeyCode::Char(' '),
            KeyCode::Char('s'),
            KeyCode::Char('x'),
        ] {
            assert!(!handle_key(key(code), &mut ui, &st), "{code:?} must not quit");
        }
        // None of these open a modal or clear the port.
        assert!(ui.add_form.is_none() && ui.connect_form.is_none());
        assert!(st.has_socks());
    }

    #[test]
    fn set_form_submit_replaces_in_place() {
        let st = state();
        st.set_socks_port(1080);
        let mut ui = UiState {
            add_form: Some(SocksForm::edit(9090)),
            ..Default::default()
        };

        submit_socks_form(&mut ui, &st);

        assert!(ui.add_form.is_none(), "form closes on successful submit");
        assert_eq!(st.socks_port(), Some(9090));
    }

    #[test]
    fn shift_c_ignored_while_listening_and_shift_l_ignored_while_dialing() {
        use crate::app_state::ListenStatus;
        // Shift+C must be inert while listening (one pairing per run).
        let st = AppState::new(Role::Both, false, LogBuffer::new(16), None, false, None, false);
        st.set_listen_status(ListenStatus::Listening);
        let mut ui = UiState::default();
        handle_key(key(KeyCode::Char('C')), &mut ui, &st);
        assert!(ui.connect_form.is_none(), "Shift+C must not open while listening");

        // Shift+L Start must be inert while a dial session exists.
        let st = AppState::new(Role::Both, false, LogBuffer::new(16), None, false, None, false);
        st.set_dial_target(Some("peer".into()));
        assert!(!st.can_listen());
        let mut ui = UiState::default();
        handle_key(key(KeyCode::Char('L')), &mut ui, &st);
        // toggle_listen was not called, so the status stays Stopped.
        assert!(!st.listening(), "Shift+L must not start listening while dialing");
    }

    #[test]
    fn l_toggles_between_home_and_logs_screens() {
        let st = state();
        let mut ui = UiState::default();
        assert_eq!(ui.screen, Screen::Home);
        assert!(!handle_key(key(KeyCode::Char('l')), &mut ui, &st));
        assert_eq!(ui.screen, Screen::Logs);
        assert!(!handle_key(key(KeyCode::Char('l')), &mut ui, &st));
        assert_eq!(ui.screen, Screen::Home);
    }

    #[test]
    fn esc_exits_scroll_mode_before_dismissing_the_logs_screen() {
        let st = state();
        let mut ui = UiState {
            screen: Screen::Logs,
            log_scroll: 7,
            ..Default::default()
        };
        // First Esc only drops out of scroll mode (back to the tail), still on logs.
        assert!(!handle_key(key(KeyCode::Esc), &mut ui, &st));
        assert_eq!(ui.log_scroll, 0);
        assert_eq!(ui.screen, Screen::Logs);
        assert!(!ui.quit_armed);
        // A second Esc, now at the tail, dismisses back to home (still no quit).
        assert!(!handle_key(key(KeyCode::Esc), &mut ui, &st));
        assert_eq!(ui.screen, Screen::Home);
        assert!(!ui.quit_armed);
    }

    #[test]
    fn v_toggles_verbose_only_on_the_logs_screen() {
        let st = state();
        let mut ui = UiState::default();
        // On home, `v` does nothing (it's a logs-screen key).
        handle_key(key(KeyCode::Char('v')), &mut ui, &st);
        assert!(!ui.verbose);
        // On the logs screen it flips verbose and snaps back to the tail.
        ui.screen = Screen::Logs;
        ui.log_scroll = 4;
        handle_key(key(KeyCode::Char('v')), &mut ui, &st);
        assert!(ui.verbose);
        assert_eq!(ui.log_scroll, 0);
        handle_key(key(KeyCode::Char('v')), &mut ui, &st);
        assert!(!ui.verbose);
    }

    #[test]
    fn log_scroll_keys_are_scoped_to_the_logs_screen() {
        let st = state();
        for _ in 0..5 {
            st.logs.push(crate::logging::LogLine {
                level: log::Level::Info,
                msg: "line".to_string(),
                ts: jiff::Zoned::now(),
                verbose_only: false,
            });
        }
        let mut ui = UiState::default();

        // On the home screen `g` is inert (it no longer collides with anything).
        handle_key(key(KeyCode::Char('g')), &mut ui, &st);
        assert_eq!(ui.log_scroll, 0);

        // Switch to the logs screen; now `g` jumps to the top.
        handle_key(key(KeyCode::Char('l')), &mut ui, &st);
        handle_key(key(KeyCode::Char('g')), &mut ui, &st);
        assert_eq!(ui.log_scroll, st.logs.concise_len());
    }

    #[test]
    fn double_esc_quits_but_single_esc_does_not() {
        let st = state();
        let mut ui = UiState::default();
        // First Esc only arms the quit; it does not exit.
        assert!(!handle_key(key(KeyCode::Esc), &mut ui, &st));
        assert!(ui.quit_armed);
        // Second consecutive Esc quits.
        assert!(handle_key(key(KeyCode::Esc), &mut ui, &st));
    }

    #[test]
    fn any_key_between_disarms_double_esc() {
        let st = state();
        let mut ui = UiState::default();
        handle_key(key(KeyCode::Esc), &mut ui, &st);
        assert!(ui.quit_armed);
        // A non-Esc key cancels the pending quit.
        handle_key(key(KeyCode::Char('j')), &mut ui, &st);
        assert!(!ui.quit_armed);
        // So the next single Esc only re-arms rather than quitting.
        assert!(!handle_key(key(KeyCode::Esc), &mut ui, &st));
    }

    #[test]
    fn generated_token_auto_hide_waits_until_deadline() {
        let st = listen_generated_state();
        let snap = st.snapshot();
        let mut ui = UiState::default();
        let now = Instant::now();

        maybe_auto_hide_generated_token_banner(&mut ui, &snap, now);
        assert!(!ui.token_banner_hidden);

        let deadline = ui
            .token_banner_auto_hide_at
            .expect("generated token should set an auto-hide deadline");
        assert_eq!(deadline.duration_since(now), GENERATED_TOKEN_AUTO_HIDE_AFTER);

        maybe_auto_hide_generated_token_banner(
            &mut ui,
            &snap,
            deadline - Duration::from_millis(1),
        );
        assert!(!ui.token_banner_hidden);
        assert_eq!(ui.token_banner_auto_hide_at, Some(deadline));
    }

    #[test]
    fn generated_token_auto_hide_uses_same_hidden_state_as_h() {
        let st = listen_generated_state();
        let snap = st.snapshot();
        let mut ui = UiState::default();
        let now = Instant::now();

        maybe_auto_hide_generated_token_banner(&mut ui, &snap, now);
        let deadline = ui.token_banner_auto_hide_at.expect("deadline set");
        maybe_auto_hide_generated_token_banner(&mut ui, &snap, deadline);

        assert!(ui.token_banner_hidden);
        assert!(ui.token_banner_auto_hide_at.is_none());
    }

    #[test]
    fn h_hides_generated_token_and_clears_auto_hide_deadline() {
        let st = listen_generated_state();
        let snap = st.snapshot();
        let mut ui = UiState::default();
        maybe_auto_hide_generated_token_banner(&mut ui, &snap, Instant::now());
        assert!(ui.token_banner_auto_hide_at.is_some());

        assert!(!handle_key(key(KeyCode::Char('h')), &mut ui, &st));

        assert!(ui.token_banner_hidden);
        assert!(ui.token_banner_auto_hide_at.is_none());
    }

    #[test]
    fn h_toggles_banner_back_on_and_rearms_auto_hide() {
        let st = listen_generated_state();
        let snap = st.snapshot();
        let mut ui = UiState::default();

        // Arm + hide via `h`.
        maybe_auto_hide_generated_token_banner(&mut ui, &snap, Instant::now());
        handle_key(key(KeyCode::Char('h')), &mut ui, &st);
        assert!(ui.token_banner_hidden);

        // A second `h` shows it again; the next tick re-arms a fresh auto-hide deadline.
        handle_key(key(KeyCode::Char('h')), &mut ui, &st);
        assert!(!ui.token_banner_hidden);
        assert!(ui.token_banner_auto_hide_at.is_none());
        let now = Instant::now();
        maybe_auto_hide_generated_token_banner(&mut ui, &snap, now);
        let deadline = ui.token_banner_auto_hide_at.expect("re-armed after toggle on");
        assert_eq!(deadline.duration_since(now), GENERATED_TOKEN_AUTO_HIDE_AFTER);
    }

    #[test]
    fn dump_connection_info_uses_mode_name_and_omits_idle_path() {
        let st = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            None,
            true,
            Some("web1".to_string()),
            false,
        );
        st.set_endpoint_id("node-123".to_string());

        let path = dump_connection_info(&st.snapshot()).expect("dump path");
        let text = std::fs::read_to_string(&path).expect("dump contents");
        let _ = std::fs::remove_file(&path);

        assert!(text.contains("mode:      config"));
        assert!(text.contains("name:      web1"));
        assert!(text.contains("outbound:  not connected"));
        assert!(!text.contains("role:"));
        assert!(!text.contains("status:"));
        assert!(!text.contains("path:"));
    }

    #[test]
    fn add_form_field_supports_cursor_editing() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(SocksForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "135"); // digits only
        // Cursor is at end; step left once and insert between '3' and '5'.
        handle_add_form(key(KeyCode::Left), &mut ui, &st);
        type_str(&mut ui, &st, "4");
        // Step left twice more and insert between '1' and '3'.
        handle_add_form(key(KeyCode::Left), &mut ui, &st);
        handle_add_form(key(KeyCode::Left), &mut ui, &st);
        type_str(&mut ui, &st, "2");
        assert_eq!(ui.add_form.as_ref().unwrap().port.value(), "12345");
    }

    #[test]
    fn add_form_esc_cancels() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(SocksForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "1");
        handle_add_form(key(KeyCode::Esc), &mut ui, &st);
        assert!(ui.add_form.is_none());
        assert!(!st.has_socks());
    }
}
