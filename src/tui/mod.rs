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

use crate::app_state::{AppSnapshot, AppState, Role, TunnelCommand};
use crate::config::{AllowedSources, RequestEntry, TransportTuning, validate_request_specs};
use crate::logging::LogBuffer;
use crate::peer_params::ResolvedPeer;
use setup::{SetupOutcome, SetupState, Step};
use textinput::handle_edit;
use ui::{AddField, AddRequestForm, Pane, UiState};

/// Refresh interval for the render tick (also bounds key-input latency).
const TICK: Duration = Duration::from_millis(200);
/// How long to show a freshly generated auth token before hiding it automatically.
const GENERATED_TOKEN_AUTO_HIDE_AFTER: Duration = Duration::from_secs(10 * 60);

/// Everything the TUI needs to run setup and build the runtime `PeerConfig`.
pub struct TuiLaunch {
    pub logs: Arc<LogBuffer>,
    pub requests: Vec<RequestEntry>,
    pub allowed_sources: AllowedSources,
    pub relay_urls: Vec<String>,
    pub relay_only: bool,
    pub dns_server: Option<String>,
    pub max_streams: Option<usize>,
    pub transport: TransportTuning,
    /// A valid auth token from config/env (pre-seeds the dial flow; used directly
    /// for listen). Pre-validated in main.
    pub config_auth_token: Option<String>,
    /// Nostr relay URLs for node-id discovery.
    pub nostr_relays: Vec<String>,
    /// Whether nostr node-id discovery is enabled (listener publishes, dialer
    /// looks up). The iroh identity is always ephemeral regardless.
    pub nostr_discovery: bool,
    /// This peer's own short identifier (config `name`), published under when
    /// listening in nostr mode. `None` in quick mode.
    pub peer_name: Option<String>,
}

/// Run the interactive setup, then the live dashboard, until the user quits or
/// the runtime stops. Initializes and restores the terminal on every exit path.
pub async fn run_tui(launch: TuiLaunch) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut events = EventStream::new();

    // Phase 1: resolve role/target/token via the interactive setup screen.
    let resolved = match run_setup(
        &mut terminal,
        &mut events,
        launch.config_auth_token.clone(),
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
                // Peers and their tunnels come and go; keep both cursors in range so
                // an action never targets a stale row.
                clamp_cursors(&mut ui_state, &snap);
                // Once a peer has connected, the generated-token banner is no longer
                // needed (the dialer already has it); hide it for the rest of the run.
                if !snap.peers.is_empty() {
                    hide_token_banner(&mut ui_state);
                }
                maybe_auto_hide_generated_token_banner(&mut ui_state, &snap, Instant::now());
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
    // The nostr identifier is role-dependent: a listener publishes under its own
    // name (config), a dialer looks up the target's name (entered in setup).
    let nostr_identifier = match resolved.role {
        Role::Listen => launch.peer_name.clone(),
        Role::Dial => resolved.peer_identifier.clone(),
    };
    crate::iroh_mode::PeerConfig {
        role: resolved.role,
        peer_node_id: resolved.peer_node_id,
        allowed_sources: resolved.allowed_sources.clone(),
        autostart_requests: false,
        auth_token: resolved.auth_token.clone(),
        nostr_relays: launch.nostr_relays.clone(),
        nostr_discovery: launch.nostr_discovery,
        nostr_identifier,
        relay_urls: launch.relay_urls.clone(),
        relay_only: launch.relay_only,
        dns_server: launch.dns_server.clone(),
        max_streams: launch.max_streams,
        transport: launch.transport.clone(),
        announce_endpoint: false,
        status: state,
    }
}

/// Run the interactive setup screen until it resolves or the user quits.
async fn run_setup(
    terminal: &mut DefaultTerminal,
    events: &mut EventStream,
    config_auth_token: Option<String>,
    config_allowed_sources: AllowedSources,
    nostr_discovery: bool,
    own_name: Option<String>,
) -> SetupOutcome {
    let mut state = SetupState::new(
        config_auth_token,
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
/// `Tab` toggles focus between the peer list and the selected peer's tunnels.
/// Arrows / `j`/`k` move the cursor in the focused pane; `Enter`/`Space` start or
/// stop the selected tunnel of the selected peer; `a` opens the add-request modal
/// (adds to the selected peer); `x`/`Del` removes the selected tunnel from that
/// peer (config is untouched); `h` hides the generated-token banner. Logs scroll
/// with `PageUp`/`PageDown` and `[`/`]`. A double `Esc` quits (or `Ctrl-C`).
fn handle_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) -> bool {
    // Ctrl-C is an always-available emergency quit, even with the modal open.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        state.shutdown.cancel();
        return true;
    }
    // While the modal is open it captures all other keys (so `j`/`k`/`q` are text).
    if ui.add_form.is_some() {
        handle_add_form(key, ui, state);
        return false;
    }

    // Quit on a double Esc: the first Esc arms it, a second (with no other key in
    // between) confirms. Any other key disarms it.
    if key.code == KeyCode::Esc {
        if ui.quit_armed {
            state.shutdown.cancel();
            return true;
        }
        ui.quit_armed = true;
        return false;
    }
    ui.quit_armed = false;

    let total = state.logs.len();
    let peer_count = state.peer_count();
    let peer = state.peer_at(ui.selected_peer);
    let tunnel_count = peer.as_ref().map(|p| p.tunnel_count()).unwrap_or(0);
    match key.code {
        KeyCode::Tab => {
            ui.focus = match ui.focus {
                Pane::Tunnels => Pane::Peers,
                Pane::Peers => Pane::Tunnels,
            };
        }
        KeyCode::Char('a') => {
            ui.add_form = Some(AddRequestForm::default());
        }
        KeyCode::Char('h') => {
            hide_token_banner(ui);
        }
        KeyCode::Up | KeyCode::Char('k') => match ui.focus {
            Pane::Peers => ui.selected_peer = ui.selected_peer.saturating_sub(1),
            Pane::Tunnels => ui.selected = ui.selected.saturating_sub(1),
        },
        KeyCode::Down | KeyCode::Char('j') => match ui.focus {
            Pane::Peers => {
                if peer_count > 0 {
                    ui.selected_peer = (ui.selected_peer + 1).min(peer_count - 1);
                }
            }
            Pane::Tunnels => {
                if tunnel_count > 0 {
                    ui.selected = (ui.selected + 1).min(tunnel_count - 1);
                }
            }
        },
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(peer) = &peer
                && let Some(id) = peer.tunnel_id_at(ui.selected)
            {
                peer.toggle_tunnel(id);
            }
        }
        KeyCode::Char('x') | KeyCode::Delete => {
            if let Some(peer) = &peer
                && let Some(id) = peer.tunnel_id_at(ui.selected)
            {
                peer.delete_request(id);
                // The row is gone; keep the cursor on a valid row (clamp to the last
                // remaining one, or 0 when the list is now empty).
                ui.selected = ui.selected.min(peer.tunnel_count().saturating_sub(1));
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

fn hide_token_banner(ui: &mut UiState) {
    ui.token_banner_hidden = true;
    ui.token_banner_auto_hide_at = None;
}

/// Keep the peer and tunnel cursors within range as peers connect/disconnect and
/// tunnels are added/removed, so a later keypress can't act on a stale row.
fn clamp_cursors(ui: &mut UiState, snap: &AppSnapshot) {
    let peer_count = snap.peers.len();
    ui.selected_peer = ui.selected_peer.min(peer_count.saturating_sub(1));
    let tunnel_count = snap
        .peers
        .get(ui.selected_peer)
        .map(|p| p.tunnels.len())
        .unwrap_or(0);
    ui.selected = ui.selected.min(tunnel_count.saturating_sub(1));
}

fn maybe_auto_hide_generated_token_banner(ui: &mut UiState, snap: &AppSnapshot, now: Instant) {
    if ui.token_banner_hidden {
        ui.token_banner_auto_hide_at = None;
        return;
    }

    if snap.role != Role::Listen || !snap.token_generated {
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
            form.field = next_field(form.field);
        }
        KeyCode::Enter => match form.field {
            AddField::LocalListen => submit_add_form(ui, state),
            other => form.field = next_field(other),
        },
        // The protocol selector is a toggle, not a text field.
        KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down
            if form.field == AddField::Protocol =>
        {
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

/// The field reached by Tab / Enter from `field`, cycling back to the top.
fn next_field(field: AddField) -> AddField {
    match field {
        AddField::Name => AddField::Protocol,
        AddField::Protocol => AddField::RemoteSource,
        AddField::RemoteSource => AddField::LocalListen,
        AddField::LocalListen => AddField::Name,
    }
}

/// Validate the modal's fields and, on success, append the request to the selected
/// peer's session and dispatch a `Start` so it begins immediately. A blank `name`
/// falls back to the `remote_source` string as the row label. Requires a selected
/// peer (tunnels are always directed at one connection); with none, the form shows
/// an error.
fn submit_add_form(ui: &mut UiState, state: &Arc<AppState>) {
    let Some(form) = ui.add_form.as_mut() else {
        return;
    };
    let Some(peer) = state.peer_at(ui.selected_peer) else {
        form.error = Some("No peer connected to add a tunnel for".to_string());
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
    let req = RequestEntry {
        name,
        remote_source,
        local_listen: form.local_listen.value().trim().to_string(),
    };
    match validate_request_specs(std::slice::from_ref(&req)) {
        Ok(()) => {
            let id = peer.add_request(req);
            peer.send_command(TunnelCommand::Start(id));
            // The new row is appended last; point the cursor at it.
            ui.selected = peer.tunnel_count().saturating_sub(1);
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
    let path = std::env::temp_dir().join(format!(
        "duopipe-conn-{}.txt",
        now.strftime("%Y%m%d-%H%M%S")
    ));

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
    }
    let _ = writeln!(out, "streams:   {}/{}", snap.streams_used, snap.streams_max);

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
            if p.tunnels.is_empty() {
                let _ = writeln!(out, "    (no tunnels configured)");
            } else {
                for t in &p.tunnels {
                    let _ = writeln!(
                        out,
                        "    {:<16} {:<40} {:<10} {}",
                        t.name,
                        t.spec,
                        t.status.label(),
                        t.detail
                    );
                }
            }
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

    fn listen_generated_state() -> Arc<AppState> {
        AppState::new(Role::Listen, true, LogBuffer::new(16), Vec::new())
    }

    fn type_str(ui: &mut UiState, st: &Arc<AppState>, s: &str) {
        for c in s.chars() {
            handle_add_form(key(KeyCode::Char(c)), ui, st);
        }
    }

    #[test]
    fn add_form_valid_submit_appends_and_closes() {
        let st = state();
        let peer = st.attach_peer("peer-a".into()).unwrap();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
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
        assert_eq!(peer.tunnel_count(), 1);
        assert_eq!(ui.selected, 0);
        let id = peer.tunnel_id_at(0).unwrap();
        let req = peer.get_request(id).unwrap();
        assert_eq!(req.name, "ssh");
        assert_eq!(req.remote_source, "tcp://127.0.0.1:22");
        assert_eq!(req.local_listen, "127.0.0.1:2222");
    }

    #[test]
    fn add_form_without_a_peer_errors() {
        let st = state(); // no peer attached
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "ssh");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> Protocol
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> RemoteSource
        type_str(&mut ui, &st, "127.0.0.1:22");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // -> LocalListen
        type_str(&mut ui, &st, "127.0.0.1:2222");
        handle_add_form(key(KeyCode::Enter), &mut ui, &st); // submit

        let form = ui.add_form.as_ref().expect("form stays open without a peer");
        assert!(form.error.is_some());
    }

    #[test]
    fn add_form_protocol_selection_sets_udp_scheme() {
        let st = state();
        let peer = st.attach_peer("peer-a".into()).unwrap();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
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
        let id = peer.tunnel_id_at(0).unwrap();
        let req = peer.get_request(id).unwrap();
        assert_eq!(req.remote_source, "udp://127.0.0.1:53");
    }

    #[test]
    fn add_form_invalid_source_keeps_form_open_with_error() {
        let st = state();
        let peer = st.attach_peer("peer-a".into()).unwrap();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
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
        assert_eq!(peer.tunnel_count(), 0, "no request added on invalid input");
    }

    fn req(name: &str, src: &str, listen: &str) -> RequestEntry {
        RequestEntry {
            name: name.into(),
            remote_source: src.into(),
            local_listen: listen.into(),
        }
    }

    #[test]
    fn delete_key_removes_selected_tunnel_and_clamps_cursor() {
        let st = state();
        let peer = st.attach_peer("peer-a".into()).unwrap();
        peer.add_request(req("a", "tcp://127.0.0.1:1", "127.0.0.1:11"));
        peer.add_request(req("b", "tcp://127.0.0.1:2", "127.0.0.1:12"));
        let mut ui = UiState {
            selected: 1,
            ..Default::default()
        };

        // `x` deletes the selected (last) tunnel and clamps the cursor onto the
        // remaining row.
        assert!(!handle_key(key(KeyCode::Char('x')), &mut ui, &st));
        assert_eq!(peer.tunnel_count(), 1);
        assert_eq!(ui.selected, 0);
        assert_eq!(
            peer.tunnel_id_at(0)
                .and_then(|id| peer.get_request(id))
                .unwrap()
                .name,
            "a"
        );

        // `Delete` removes the last remaining tunnel; cursor clamps to 0.
        assert!(!handle_key(key(KeyCode::Delete), &mut ui, &st));
        assert_eq!(peer.tunnel_count(), 0);
        assert_eq!(ui.selected, 0);
        // Pressing delete on an empty list is a harmless no-op.
        assert!(!handle_key(key(KeyCode::Char('x')), &mut ui, &st));
        assert_eq!(peer.tunnel_count(), 0);
    }

    #[test]
    fn tab_toggles_focus_and_peer_cursor_moves() {
        let st = state();
        st.attach_peer("peer-a".into()).unwrap();
        st.attach_peer("peer-b".into()).unwrap();
        let mut ui = UiState::default();
        assert_eq!(ui.focus, Pane::Tunnels);

        // Tab moves focus to the peer pane; Down then advances the peer cursor.
        handle_key(key(KeyCode::Tab), &mut ui, &st);
        assert_eq!(ui.focus, Pane::Peers);
        handle_key(key(KeyCode::Down), &mut ui, &st);
        assert_eq!(ui.selected_peer, 1);
        // Clamped at the last peer.
        handle_key(key(KeyCode::Down), &mut ui, &st);
        assert_eq!(ui.selected_peer, 1);

        // Tab returns focus to tunnels; Down there no longer moves the peer cursor.
        handle_key(key(KeyCode::Tab), &mut ui, &st);
        assert_eq!(ui.focus, Pane::Tunnels);
        handle_key(key(KeyCode::Down), &mut ui, &st);
        assert_eq!(ui.selected_peer, 1, "tunnel-pane nav leaves the peer cursor put");
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
    fn add_form_field_supports_cursor_editing() {
        let st = state();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
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
        let peer = st.attach_peer("peer-a".into()).unwrap();
        let mut ui = UiState {
            add_form: Some(AddRequestForm::default()),
            ..Default::default()
        };
        type_str(&mut ui, &st, "x");
        handle_add_form(key(KeyCode::Esc), &mut ui, &st);
        assert!(ui.add_form.is_none());
        assert_eq!(peer.tunnel_count(), 0);
    }
}
