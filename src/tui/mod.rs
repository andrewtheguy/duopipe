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
    AppSnapshot, AppState, DialCommand, DialTarget, NameCommand, NameConflict, Role, TunnelCommand,
};
use crate::config::{AllowedSources, TransportTuning, TunnelEntry, validate_tunnel_specs};
use crate::logging::LogBuffer;
use crate::peer_params::ResolvedPeer;
use iroh::EndpointId;
use setup::{SetupOutcome, SetupState, Step};
use textinput::handle_edit;
use ui::{AddField, AddTunnelForm, ConnectForm, Screen, UiState};

/// Refresh interval for the render tick (also bounds key-input latency).
const TICK: Duration = Duration::from_millis(200);
/// How long to show a freshly generated auth token before hiding it automatically.
const GENERATED_TOKEN_AUTO_HIDE_AFTER: Duration = Duration::from_secs(10 * 60);

/// Everything the TUI needs to run setup and build the runtime `PeerConfig`.
pub struct TuiLaunch {
    pub logs: Arc<LogBuffer>,
    pub tunnels: Vec<TunnelEntry>,
    pub allowed_sources: AllowedSources,
    pub relay_urls: Vec<String>,
    pub relay_only: bool,
    pub dns_server: Option<String>,
    pub max_streams: Option<usize>,
    pub transport: TransportTuning,
    /// A valid auth token from config/env (pre-seeds the dial flow; used directly
    /// for listen). Pre-validated in main.
    pub config_auth_token: Option<String>,
    /// Expected token fingerprint declared by a nostr config (`auth_token_fingerprint`),
    /// already validated in main. When set, a token pasted at the setup screen must match
    /// it. `None` in quick mode.
    pub expected_token_fingerprint: Option<String>,
    /// Nostr relay URLs for node-id discovery.
    pub nostr_relays: Vec<String>,
    /// Whether nostr node-id discovery is enabled (listener publishes, dialer
    /// looks up). The iroh identity is always ephemeral regardless.
    pub nostr_discovery: bool,
    /// This peer's own short identifier (config `name`), published under when
    /// listening in nostr mode. `None` in quick mode.
    pub peer_name: Option<String>,
    /// Path to the loaded peer config file (nostr mode), for the name-conflict rename
    /// nudge. `None` in quick mode.
    pub config_path: Option<std::path::PathBuf>,
}

/// Run the interactive setup, then the live dashboard, until the user quits or
/// the runtime stops. Initializes and restores the terminal on every exit path.
pub async fn run_tui(launch: TuiLaunch) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut events = EventStream::new();

    // Phase 1: resolve the serving allowlist and auth token via the setup screen.
    let resolved = match run_setup(
        &mut terminal,
        &mut events,
        launch.config_auth_token.clone(),
        launch.expected_token_fingerprint.clone(),
        launch.allowed_sources.clone(),
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
        launch.tunnels.clone(),
        launch.nostr_discovery,
        launch.peer_name.clone(),
    );
    // Seed the active token now so the header fingerprint is populated from the first
    // frame (the runtime sets the same value again once it starts — idempotent).
    state.set_auth_token(resolved.auth_token.clone());
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
                // Once a peer has connected, the generated-token banner is no longer
                // needed (the dialer already has it); hide it for the rest of the run.
                if !snap.peers.is_empty() {
                    hide_token_banner(&mut ui_state);
                }
                maybe_auto_hide_generated_token_banner(&mut ui_state, &snap, Instant::now());
                let _ = terminal.draw(|f| {
                    ui::render(f, &snap, &logs, &ui_state);
                    if let Some(form) = &ui_state.add_form {
                        ui::render_add_tunnel_dialog(f, form);
                    }
                    if let Some(form) = &ui_state.connect_form {
                        ui::render_connect_dialog(f, form, state.nostr_discovery);
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
        allowed_sources: resolved.allowed_sources.clone(),
        autostart_tunnels: false,
        auth_token: resolved.auth_token.clone(),
        nostr_relays: launch.nostr_relays.clone(),
        nostr_discovery: launch.nostr_discovery,
        nostr_identifier,
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
    config_allowed_sources: AllowedSources,
    nostr_discovery: bool,
    own_name: Option<String>,
) -> SetupOutcome {
    let mut state = SetupState::new(
        config_auth_token,
        expected_token_fingerprint,
        config_allowed_sources,
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
            hide_token_banner(ui);
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

/// Home-screen keys: tunnel navigation/actions plus the connection-info dump.
///
/// Tunnels belong to the combined node's outbound dial session; a pure listen-only
/// half shows only its connected peers. Arrows / `j`/`k` move the tunnel selection
/// cursor; `Enter`/`Space` start or stop the selected tunnel; `a` opens the
/// add-tunnel modal; `e` edits the selected tunnel in place while it is not running;
/// `d`/`Del` removes the selected tunnel from the session (config is untouched);
/// `w` writes (dumps) the connection info to a file.
fn handle_home_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    let tunnels = state.tunnel_count();
    match key.code {
        // Tunnels are driven by the dial half; a pure listen-only half initiates none.
        KeyCode::Char('a') if matches!(state.role, Role::Dial | Role::Both) => {
            ui.add_form = Some(AddTunnelForm::default());
        }
        // Edit the selected tunnel in place — only while it is not running (a
        // Listening tunnel must be stopped first so its bound port isn't orphaned).
        KeyCode::Char('e') if matches!(state.role, Role::Dial | Role::Both) => {
            if let Some(id) = state.tunnel_id_at(ui.selected)
                && !state.tunnel_running(id)
                && let Some(entry) = state.get_tunnel(id)
            {
                ui.add_form = Some(AddTunnelForm::edit(id, &entry));
            }
        }
        // Connect / re-point the on-demand dial session (interactive serve+dial mode).
        // Shift-C pairs with Shift-D below as the dial-session lifecycle controls,
        // kept distinct from the lowercase per-tunnel keys (a/d) to avoid confusion.
        KeyCode::Char('C') if state.role == Role::Both => {
            ui.connect_form = Some(ConnectForm::default());
        }
        // Disconnect the current dial session, returning to serve-only.
        KeyCode::Char('D') if state.role == Role::Both => {
            state.send_dial(DialCommand::Disconnect);
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
            if let Some(id) = state.tunnel_id_at(ui.selected) {
                state.toggle_tunnel(id);
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(id) = state.tunnel_id_at(ui.selected) {
                state.delete_tunnel(id);
                // The row is gone; keep the cursor on a valid row (clamp to the last
                // remaining one, or 0 when the list is now empty).
                ui.selected = ui.selected.min(state.tunnel_count().saturating_sub(1));
            }
        }
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

/// Accept printable ASCII for the address fields (no spaces); `name` also allows
/// spaces as a free-form label.
fn is_field_char(c: char, field: AddField) -> bool {
    c.is_ascii_graphic() || (c == ' ' && field == AddField::Name)
}

/// Handle a key while the add/edit-tunnel modal is open. Up/Down (or Tab/BackTab)
/// move between fields; Enter advances, and Enter on the last field validates and
/// (on success) adds + auto-starts a new tunnel, or saves an edit in place. Esc
/// cancels.
fn handle_add_form(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    form.error = None;
    match key.code {
        KeyCode::Esc => {
            ui.add_form = None;
        }
        // Vertical form: Up/Down (and Tab/BackTab) move between fields.
        KeyCode::Down | KeyCode::Tab => {
            form.field = next_field(form.field);
        }
        KeyCode::Up | KeyCode::BackTab => {
            form.field = prev_field(form.field);
        }
        KeyCode::Enter => match form.field {
            AddField::LocalListen => submit_tunnel_form(ui, state),
            other => form.field = next_field(other),
        },
        // The protocol selector is a left/right toggle (Up/Down navigate fields).
        KeyCode::Left | KeyCode::Right if form.field == AddField::Protocol => {
            form.protocol = form.protocol.toggled();
        }
        _ => {
            let field = form.field;
            // Ignore text keystrokes while the protocol selector is focused.
            if let Some(input) = form.active_mut() {
                handle_edit(input, key, |c| is_field_char(c, field));
            }
        }
    }
}

/// The field reached by Down / Tab / Enter from `field`, cycling back to the top.
fn next_field(field: AddField) -> AddField {
    match field {
        AddField::Name => AddField::Protocol,
        AddField::Protocol => AddField::RemoteSource,
        AddField::RemoteSource => AddField::LocalListen,
        AddField::LocalListen => AddField::Name,
    }
}

/// The field reached by Up / BackTab from `field`, cycling back to the bottom.
fn prev_field(field: AddField) -> AddField {
    match field {
        AddField::Name => AddField::LocalListen,
        AddField::Protocol => AddField::Name,
        AddField::RemoteSource => AddField::Protocol,
        AddField::LocalListen => AddField::RemoteSource,
    }
}

/// Validate the modal's fields and, on success, either append a new tunnel and
/// dispatch a `Start` so it auto-starts (add mode), or replace the selected
/// tunnel's spec in place without starting it (edit mode). A blank `name` falls
/// back to the `remote_source` string as the row label, and names must be unique.
///
/// `Start` (add mode) is broadcast: if currently disconnected there's no supervisor
/// to receive it, so the row stays Idle until started (consistent with config
/// tunnels after a reconnect).
fn submit_tunnel_form(ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    // The user types only `host:port`; the selected protocol supplies the scheme.
    let host_port = form.remote_source.value().trim();
    let remote_source = format!("{}://{host_port}", form.protocol.scheme());
    let name = if form.name.value().trim().is_empty() {
        remote_source.clone()
    } else {
        form.name.value().trim().to_string()
    };
    let entry = TunnelEntry {
        name,
        remote_source,
        local_listen: form.local_listen.value().trim().to_string(),
    };
    if let Err(e) = validate_tunnel_specs(std::slice::from_ref(&entry)) {
        form.error = Some(e.to_string());
        return;
    }
    // Names must stay unique. When editing, the tunnel keeps its own name freely
    // (`editing` excludes its own row from the collision check).
    if state.tunnel_name_taken(&entry.name, form.editing) {
        form.error = Some(format!("tunnel name {:?} already in use", entry.name));
        return;
    }
    match form.editing {
        Some(id) => {
            // Edit in place: replace the spec, keep id/position, do not start. The
            // row stays where it was, so the cursor already points at it.
            state.edit_tunnel(id, entry);
        }
        None => {
            let id = state.add_tunnel(entry);
            state.send_command(TunnelCommand::Start(id));
            // The new row is appended last; point the cursor at it.
            ui.selected = state.tunnel_count().saturating_sub(1);
        }
    }
    ui.add_form = None;
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
/// dispatch `DialCommand::Connect` (replacing any current session). In nostr mode the
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
        AppState::new(Role::Dial, false, LogBuffer::new(16), Vec::new(), false, None)
    }

    fn listen_generated_state() -> Arc<AppState> {
        AppState::new(Role::Listen, true, LogBuffer::new(16), Vec::new(), false, None)
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
    fn connect_submit_keeps_modal_open_when_dial_manager_is_absent() {
        let st = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            Vec::new(),
            true,
            Some("web1".to_string()),
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
    fn add_form_valid_submit_appends_and_closes() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "ssh");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> Protocol (defaults tcp)
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> RemoteSource
        type_str(&mut ui, &st, "127.0.0.1:22"); // host:port only, scheme is implicit
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:2222");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit

        assert!(ui.add_form.is_none(), "form closes on successful submit");
        assert_eq!(st.tunnel_count(), 1);
        assert_eq!(ui.selected, 0);
        let id = st.tunnel_id_at(0).unwrap();
        let req = st.get_tunnel(id).unwrap();
        assert_eq!(req.name, "ssh");
        assert_eq!(req.remote_source, "tcp://127.0.0.1:22");
        assert_eq!(req.local_listen, "127.0.0.1:2222");
    }

    #[test]
    fn add_form_protocol_selection_sets_udp_scheme() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // Name -> Protocol
        // Toggle the protocol selector from the default tcp to udp.
        handle_add_form(key(KeyCode::Right), &mut ui, &st);
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> RemoteSource
        type_str(&mut ui, &st, "127.0.0.1:53");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:5353");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit

        assert!(ui.add_form.is_none());
        let id = st.tunnel_id_at(0).unwrap();
        let req = st.get_tunnel(id).unwrap();
        assert_eq!(req.remote_source, "udp://127.0.0.1:53");
    }

    #[test]
    fn add_form_up_down_navigate_fields() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        let field = |ui: &UiState| ui.add_form.as_ref().unwrap().field;
        assert_eq!(field(&ui), AddField::Name);

        // Down walks forward through the vertical form...
        handle_add_form(key(KeyCode::Down), &mut ui, &st);
        assert_eq!(field(&ui), AddField::Protocol);
        handle_add_form(key(KeyCode::Down), &mut ui, &st);
        assert_eq!(field(&ui), AddField::RemoteSource);

        // ...and Up walks back, even off the Protocol field (which no longer eats it).
        handle_add_form(key(KeyCode::Up), &mut ui, &st);
        assert_eq!(field(&ui), AddField::Protocol);
        handle_add_form(key(KeyCode::Up), &mut ui, &st);
        assert_eq!(field(&ui), AddField::Name);

        // Up from the top wraps to the bottom.
        handle_add_form(key(KeyCode::Up), &mut ui, &st);
        assert_eq!(field(&ui), AddField::LocalListen);
    }

    #[test]
    fn add_form_left_right_toggle_protocol_only_on_protocol_field() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        let proto = |ui: &UiState| ui.add_form.as_ref().unwrap().protocol;
        let default_proto = proto(&ui);
        // On the Name field, Left/Right are text-cursor moves, not a protocol toggle.
        handle_add_form(key(KeyCode::Right), &mut ui, &st);
        assert_eq!(proto(&ui), default_proto);
        // On the Protocol field, Left/Right toggle it.
        handle_add_form(key(KeyCode::Down), &mut ui, &st); // -> Protocol
        handle_add_form(key(KeyCode::Right), &mut ui, &st);
        assert_ne!(proto(&ui), default_proto);
    }

    #[test]
    fn add_form_invalid_source_keeps_form_open_with_error() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        // Skip name; bad remote_source (host without a port); any local_listen.
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // Name -> Protocol
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> RemoteSource
        type_str(&mut ui, &st, "127.0.0.1"); // missing :port
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:2222");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit -> error

        let form = ui.add_form.as_ref().expect("form stays open on error");
        assert!(form.error.is_some());
        assert_eq!(st.tunnel_count(), 0, "no request added on invalid input");
    }

    fn req(name: &str, src: &str, listen: &str) -> TunnelEntry {
        TunnelEntry {
            name: name.into(),
            remote_source: src.into(),
            local_listen: listen.into(),
        }
    }

    #[test]
    fn delete_key_removes_selected_tunnel_and_clamps_cursor() {
        let st = state();
        st.add_tunnel(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        st.add_tunnel(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        let mut ui = UiState {
            selected: 1,
            ..Default::default()
        };

        // `d` deletes the selected (last) tunnel and clamps the cursor onto the
        // remaining row.
        assert!(!handle_key(key(KeyCode::Char('d')), &mut ui, &st));
        assert_eq!(st.tunnel_count(), 1);
        assert_eq!(ui.selected, 0);
        assert_eq!(st.tunnel_id_at(0).and_then(|id| st.get_tunnel(id)).unwrap().name, "a");

        // `Delete` removes the last remaining tunnel; cursor clamps to 0.
        assert!(!handle_key(key(KeyCode::Delete), &mut ui, &st));
        assert_eq!(st.tunnel_count(), 0);
        assert_eq!(ui.selected, 0);
        // Pressing delete on an empty list is a harmless no-op.
        assert!(!handle_key(key(KeyCode::Char('d')), &mut ui, &st));
        assert_eq!(st.tunnel_count(), 0);
    }

    #[test]
    fn e_key_opens_edit_form_prefilled_for_idle_tunnel() {
        let st = state();
        let id = st.add_tunnel(req("db", "udp://127.0.0.1:53", "127.0.0.1:5353"));
        let mut ui = UiState {
            selected: 0,
            ..Default::default()
        };

        assert!(!handle_key(key(KeyCode::Char('e')), &mut ui, &st));
        let form = ui.add_form.as_ref().expect("edit form opened");
        assert_eq!(form.editing, Some(id));
        assert_eq!(form.name.value(), "db");
        // The scheme is split off into the protocol selector; the field holds host:port.
        assert_eq!(form.protocol, ui::Protocol::Udp);
        assert_eq!(form.remote_source.value(), "127.0.0.1:53");
        assert_eq!(form.local_listen.value(), "127.0.0.1:5353");
    }

    #[test]
    fn edit_form_submit_updates_in_place_without_changing_count() {
        let st = state();
        let id = st.add_tunnel(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        st.add_tunnel(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        // Simulate the user having edited the form to new values.
        let edited = req("a2", "udp://127.0.0.1:9", "127.0.0.1:99");
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::edit(id, &edited)),
            selected: 0,
            ..Default::default()
        };

        submit_tunnel_form(&mut ui, &st);

        assert!(ui.add_form.is_none(), "form closes on successful edit");
        assert_eq!(st.tunnel_count(), 2, "edit replaces in place, never appends");
        let got = st.get_tunnel(id).expect("tunnel still present");
        assert_eq!(got.name, "a2");
        assert_eq!(got.remote_source, "udp://127.0.0.1:9");
        assert_eq!(got.local_listen, "127.0.0.1:99");
        // The edited tunnel keeps its position.
        assert_eq!(st.tunnel_id_at(0), Some(id));
    }

    #[test]
    fn edit_to_another_tunnels_name_is_rejected() {
        let st = state();
        let a = st.add_tunnel(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        st.add_tunnel(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        // Try to rename "a" to "b" (already taken by the other tunnel).
        let collide = req("b", "tcp://127.0.0.1:1", "127.0.0.1:11");
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::edit(a, &collide)),
            ..Default::default()
        };

        submit_tunnel_form(&mut ui, &st);

        let form = ui.add_form.as_ref().expect("form stays open on collision");
        assert!(form.error.as_deref().unwrap().contains("already in use"));
        assert_eq!(st.get_tunnel(a).unwrap().name, "a", "name unchanged");
    }

    #[test]
    fn add_form_duplicate_name_is_rejected() {
        let st = state();
        st.add_tunnel(req("db", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "db"); // collides with the existing tunnel
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> Protocol
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> RemoteSource
        type_str(&mut ui, &st, "127.0.0.1:2");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:12");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit -> error

        let form = ui.add_form.as_ref().expect("form stays open on duplicate name");
        assert!(form.error.as_deref().unwrap().contains("already in use"));
        assert_eq!(st.tunnel_count(), 1, "no tunnel added on duplicate name");
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
    fn dump_connection_info_uses_mode_name_and_omits_idle_path() {
        let st = AppState::new(
            Role::Both,
            false,
            LogBuffer::new(16),
            Vec::new(),
            true,
            Some("web1".to_string()),
        );
        st.set_endpoint_id("node-123".to_string());

        let path = dump_connection_info(&st.snapshot()).expect("dump path");
        let text = std::fs::read_to_string(&path).expect("dump contents");
        let _ = std::fs::remove_file(&path);

        assert!(text.contains("mode:      nostr"));
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
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "ace");
        // Cursor is at end; step left once and insert between 'c' and 'e'.
        handle_add_form(key(KeyCode::Left), &mut ui, &st);
        type_str(&mut ui, &st, "d");
        // Step left twice more and insert between 'a' and 'c'.
        handle_add_form(key(KeyCode::Left), &mut ui, &st);
        handle_add_form(key(KeyCode::Left), &mut ui, &st);
        type_str(&mut ui, &st, "b");
        assert_eq!(ui.add_form.as_ref().unwrap().name.value(), "abcde");
    }

    #[test]
    fn add_form_esc_cancels() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddTunnelForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "x");
        handle_add_form(key(KeyCode::Esc), &mut ui, &st);
        assert!(ui.add_form.is_none());
        assert_eq!(st.tunnel_count(), 0);
    }
}
