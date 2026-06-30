//! Rendering for the duopipe TUI. Pure functions over an [`AppSnapshot`].

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use tui_input::Input;

use super::textinput::{INPUT_FIELD_HEIGHT, render_input_field};
use crate::app_state::{
    AppSnapshot, ConnStatus, NameConflict, PeerRow, Role, TunnelRow, TunnelStatus,
};
use crate::config::TunnelEntry;
use crate::logging::LogLine;

/// Which top-level screen the dashboard is showing. Logs live on their own screen
/// so their scroll keys (`[`/`]`, `g`/`G`, PgUp/PgDn) don't collide with the home
/// screen's tunnel navigation.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// Header + tunnels + connected peers.
    #[default]
    Home,
    /// Header + a full-height log pane.
    Logs,
}

/// View state owned by the TUI loop (not shared with the runtime).
#[derive(Default)]
pub struct UiState {
    /// Which screen is visible (toggled with `l`).
    pub screen: Screen,
    /// Lines scrolled up from the bottom of the log pane. 0 = follow tail.
    pub log_scroll: usize,
    /// When true, the log pane shows every captured line (including the iroh/quinn
    /// `Warn` churn flagged `verbose_only`); otherwise only the concise view. Toggled
    /// with `v` on the logs screen.
    pub verbose: bool,
    /// When `Some`, the set-tunnel modal is open and captures all keystrokes.
    pub add_form: Option<AddTunnelForm>,
    /// When `Some`, the "connect to peer" modal is open and captures all keystrokes.
    pub connect_form: Option<ConnectForm>,
    /// Whether the generated-secret banner (manual-mode auth token or quick-mode PIN) is
    /// currently hidden. Set by `h`, by the auto-hide timeout, or once when the first peer
    /// connects; `h` toggles it back on.
    pub token_banner_hidden: bool,
    /// Deadline for auto-hiding the generated-secret banner. Set by the dashboard loop, not
    /// by rendering; cleared while hidden and re-armed when shown again.
    pub token_banner_auto_hide_at: Option<Instant>,
    /// Set once the first inbound peer has connected, so the one-shot connect-hide does not
    /// re-fire every tick (which would fight the `h` toggle).
    pub peers_seen: bool,
    /// First Esc of a double-Esc quit has been seen; the next Esc quits. Cleared
    /// by any other key. Drives the "press Esc again" hint.
    pub quit_armed: bool,
}

/// Which field the set-tunnel modal is currently editing. Both fields are bare
/// `host:port` text inputs.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddField {
    #[default]
    RemoteSource,
    LocalListen,
}

/// In-progress entry for the set-tunnel modal (modal state). Used both to set a
/// fresh tunnel and to replace the current one (only allowed while it is not
/// running). Both fields hold a bare `host:port`.
#[derive(Default)]
pub struct AddTunnelForm {
    pub field: AddField,
    pub remote_source: Input,
    pub local_listen: Input,
    /// Inline validation error from the last failed submit; cleared on next keypress.
    pub error: Option<String>,
}

impl AddTunnelForm {
    /// Build a form pre-filled from `entry`'s current spec (replace in place).
    pub fn edit(entry: &TunnelEntry) -> Self {
        Self {
            field: AddField::RemoteSource,
            remote_source: Input::new(entry.remote_source.clone()),
            local_listen: Input::new(entry.local_listen.clone()),
            error: None,
        }
    }

    /// The text input for the field currently being edited.
    pub fn active_mut(&mut self) -> Option<&mut Input> {
        match self.field {
            AddField::RemoteSource => Some(&mut self.remote_source),
            AddField::LocalListen => Some(&mut self.local_listen),
        }
    }
}

/// In-progress entry for the runtime "connect to peer" modal (single text field).
#[derive(Default)]
pub struct ConnectForm {
    /// The target: a peer name (connect mode) or a full node id (quick mode).
    pub target: Input,
    /// Inline validation error from the last failed submit; cleared on next keypress.
    pub error: Option<String>,
}

pub fn render(frame: &mut Frame, snap: &AppSnapshot, logs: &[LogLine], ui: &UiState) {
    match ui.screen {
        Screen::Home => render_home(frame, snap, ui),
        Screen::Logs => render_logs_screen(frame, snap, logs, ui),
    }
}

/// The home screen: header, the tunnel table, and the connected-peers table. Logs
/// live on their own screen (`l`) so their keys don't fight the tunnel navigation.
fn render_home(frame: &mut Frame, snap: &AppSnapshot, ui: &UiState) {
    // Show the freshly generated token in the header until a peer connects or the
    // user dismisses it (both captured by `token_banner_hidden`).
    let show_token_banner = show_generated_token_banner(snap, ui);
    let show_pin_banner = show_pin_banner(snap, ui);
    let hide_at = banner_hide_at(show_token_banner || show_pin_banner, ui);
    let show_conflict_warning = matches!(snap.name_conflict, NameConflict::Degraded { .. });
    let tunnel_rows = 1u16 + 2; // single tunnel row + header + border
    let peer_rows = snap.peers.len().max(1) as u16 + 2;
    let [header_area, tunnels_area, peers_area, _filler, footer_area] = Layout::vertical([
        Constraint::Length(header_height(show_token_banner, show_pin_banner, show_conflict_warning)),
        Constraint::Length(tunnel_rows.clamp(4, 10)),
        Constraint::Length(peer_rows.clamp(3, 8)),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    // The dial hint advertises the home-only Shift-C/Shift-D controls, so it shows
    // only here (not on the logs screen, where those keys are inert).
    render_header(
        frame,
        header_area,
        snap,
        show_token_banner,
        show_pin_banner,
        hide_at.as_deref(),
        true,
    );
    render_tunnels(frame, tunnels_area, snap, ui);
    render_peers(frame, peers_area, snap);
    render_home_footer(frame, footer_area, snap, ui);
}

/// The logs screen: the same header plus a full-height log pane.
fn render_logs_screen(frame: &mut Frame, snap: &AppSnapshot, logs: &[LogLine], ui: &UiState) {
    let show_token_banner = show_generated_token_banner(snap, ui);
    let show_pin_banner = show_pin_banner(snap, ui);
    let hide_at = banner_hide_at(show_token_banner || show_pin_banner, ui);
    let show_conflict_warning = matches!(snap.name_conflict, NameConflict::Degraded { .. });
    let [header_area, logs_area] = Layout::vertical([
        Constraint::Length(header_height(show_token_banner, show_pin_banner, show_conflict_warning)),
        Constraint::Min(3),
    ])
    .areas(frame.area());

    render_header(
        frame,
        header_area,
        snap,
        show_token_banner,
        show_pin_banner,
        hide_at.as_deref(),
        false,
    );
    render_logs(frame, logs_area, logs, ui);
}

/// One-line footer for the home screen carrying the global key hints (the per-pane
/// hints live in the tunnel/log titles).
fn render_home_footer(frame: &mut Frame, area: Rect, snap: &AppSnapshot, ui: &UiState) {
    let text = if ui.quit_armed {
        "press Esc again to quit".to_string()
    } else {
        let secret = if snap.pin_mode { "PIN" } else { "token" };
        format!("l logs · w dump · h show/hide {secret} · Esc Esc quit")
    };
    let para = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(para, area);
}

fn show_generated_token_banner(snap: &AppSnapshot, ui: &UiState) -> bool {
    // In quick PIN mode the rotating-PIN banner replaces the raw token banner entirely.
    matches!(snap.role, Role::Listen | Role::Both)
        && snap.token_generated
        && !snap.pin_mode
        && !ui.token_banner_hidden
}

/// Quick PIN mode shows a banner with the current rotating PIN and its refresh countdown,
/// shown once the publisher has minted the first PIN. Like the token banner it auto-hides
/// after a few minutes and is toggled with `h`.
fn show_pin_banner(snap: &AppSnapshot, ui: &UiState) -> bool {
    matches!(snap.role, Role::Listen | Role::Both)
        && snap.pin_mode
        && snap.current_pin.is_some()
        && !ui.token_banner_hidden
}

/// The wall-clock time the visible generated-secret banner will auto-hide, as an absolute
/// `HH:MM` string (deliberately not a live countdown). `None` when no banner is showing or
/// no auto-hide deadline is armed yet (e.g. just after a toggle, before the next tick).
fn banner_hide_at(showing: bool, ui: &UiState) -> Option<String> {
    if !showing {
        return None;
    }
    let deadline = ui.token_banner_auto_hide_at?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let at = jiff::Zoned::now()
        .checked_add(jiff::Span::new().seconds(remaining.as_secs() as i64))
        .unwrap_or_else(|_| jiff::Zoned::now());
    Some(at.strftime("%H:%M").to_string())
}

fn header_height(show_token_banner: bool, show_pin_banner: bool, show_conflict_warning: bool) -> u16 {
    // Five content rows (app identity, mode/name, streams/fp, node id, dial line) plus
    // the border. The token *or* PIN banner adds two rows.
    let base = if show_token_banner || show_pin_banner { 9 } else { 7 };
    base + if show_conflict_warning { 1 } else { 0 }
}

fn render_header(
    frame: &mut Frame,
    area: Rect,
    snap: &AppSnapshot,
    show_token_banner: bool,
    show_pin_banner: bool,
    hide_at: Option<&str>,
    show_dial_hint: bool,
) {
    let endpoint = snap.endpoint_id.as_deref().unwrap_or("(pending)");
    // Spread the header fields over a few short rows (at most two fields each) instead
    // of one long line, so the header still reads on a narrow terminal.
    let app_line = vec![
        Span::styled("duopipe", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            concat!(" v", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(" @ "),
        Span::styled(
            snap.hostname.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    // This peer's identity: mode and (in connect mode) its name.
    let mut id_line = vec![
        Span::raw("mode: "),
        Span::styled(mode_label(snap), Style::default().add_modifier(Modifier::BOLD)),
    ];
    if let Some(name) = own_name_display(snap) {
        id_line.push(Span::raw("  name: "));
        id_line.push(Span::styled(
            name.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    // Live status: open streams and a short, stable fingerprint of the active token,
    // shown in every mode and role so the user can confirm two devices share the same
    // token even after the full token is hidden (the only place it can be cross-checked).
    let mut status_line = vec![
        Span::raw("streams: "),
        Span::raw(format!("{}/{}", snap.streams_used, snap.streams_max)),
    ];
    if let Some(token) = snap.auth_token.as_deref() {
        status_line.push(Span::raw("  token fp: "));
        status_line.push(Span::styled(
            crate::auth::token_fingerprint(token),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }

    let mut lines = vec![
        Line::from(app_line),
        Line::from(id_line),
        Line::from(status_line),
        Line::from(vec![Span::raw("node id: "), Span::raw(endpoint)]),
        dial_header_line(snap, show_dial_hint),
    ];

    if show_token_banner {
        // Freshly generated token, not yet dismissed: surface it so the dialer can
        // copy it. Hidden once a peer connects or the user presses `h`.
        let token = snap.auth_token.as_deref().unwrap_or("(pending)");
        let mut token_line = vec![
            Span::raw("auth token: "),
            Span::styled(
                token.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ];
        if let Some(token) = snap.auth_token.as_deref() {
            token_line.push(Span::styled(
                format!("  (fp: {})", crate::auth::token_fingerprint(token)),
                Style::default().fg(Color::DarkGray),
            ));
        }
        lines.push(Line::from(token_line));
        let hint = match hide_at {
            Some(at) => format!("auto-hides at {at} · press h to hide/show"),
            None => "press h to hide/show".to_string(),
        };
        lines.push(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        )));
    }

    if show_pin_banner {
        // Quick PIN mode: the rotating code the other device types to connect. It carries
        // this peer's node id + token, so no copy-paste is needed.
        let pin = snap.current_pin.as_deref().unwrap_or("");
        let mut pin_line = vec![
            Span::raw("dial PIN: "),
            Span::styled(
                crate::pin::format_pin(pin),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ];
        if let Some(token) = snap.auth_token.as_deref() {
            pin_line.push(Span::styled(
                format!("  (fp: {})", crate::auth::token_fingerprint(token)),
                Style::default().fg(Color::DarkGray),
            ));
        }
        lines.push(Line::from(pin_line));

        // Two timers: a live 60s refresh countdown (the PIN itself rotates) and the
        // absolute auto-hide time (shown as a clock time, not a countdown, to avoid
        // confusion with the refresh).
        let refresh = snap
            .pin_deadline
            .map(|d| d.saturating_duration_since(Instant::now()).as_secs())
            .unwrap_or(0);
        let hint = match hide_at {
            Some(at) => format!("refreshes in {refresh:>2}s · auto-hides at {at} · press h to hide/show"),
            None => format!("refreshes in {refresh:>2}s · press h to hide/show"),
        };
        lines.push(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        )));
    }

    if let NameConflict::Degraded { message } = &snap.name_conflict {
        lines.push(Line::from(Span::styled(
            format!("⚠ {message}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }

    let para = Paragraph::new(lines).block(Block::default().borders(Borders::ALL));
    frame.render_widget(para, area);
}

/// Modal prompting the user to resolve a nostr name conflict. The body text is built
/// by the publisher (it knows startup vs mid-session consequences); this renders it
/// verbatim with a key legend.
pub fn render_name_conflict_dialog(frame: &mut Frame, message: &str) {
    let mut lines = vec![Line::from(Span::styled(
        "Name conflict",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::raw(""));
    for line in message.lines() {
        lines.push(Line::from(Span::raw(line.to_string())));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "t take over · r rename · n decline",
        Style::default().fg(Color::DarkGray),
    )));

    let area = centered(frame.area(), 80, lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" name conflict "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

pub(super) fn mode_label(snap: &AppSnapshot) -> &'static str {
    if snap.nostr_discovery {
        "connect"
    } else {
        "quick"
    }
}

pub(super) fn own_name_display(snap: &AppSnapshot) -> Option<&str> {
    if snap.nostr_discovery {
        snap.own_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
    } else {
        None
    }
}

pub(super) fn dial_text(snap: &AppSnapshot) -> String {
    snap.dial_target
        .as_deref()
        .map(|target| format!("Outbound → {target}"))
        .unwrap_or_else(|| "Outbound: not connected".to_string())
}

/// The dial-session control hint, styled to stand out as an action. It lives on the
/// dial header line (not the Tunnels box) so connecting/disconnecting the outbound
/// session reads as separate from the per-tunnel actions. `Shift-C` connects (or
/// re-points) the session; `Shift-D` disconnects it.
fn dial_hint(connected: bool) -> Span<'static> {
    let text = if connected {
        "   [Shift-D disconnect]"
    } else {
        "   [Shift-C connect]"
    };
    Span::styled(
        text,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

/// `show_hint` is false on the logs screen, where the Shift-C/Shift-D dial controls
/// are inert — the status still shows, just without the dead action hint.
fn dial_header_line(snap: &AppSnapshot, show_hint: bool) -> Line<'static> {
    let Some(target) = snap.dial_target.as_deref() else {
        let mut spans = vec![Span::raw(dial_text(snap))];
        if show_hint {
            spans.push(dial_hint(false));
        }
        return Line::from(spans);
    };

    let mut spans = vec![
        Span::raw(format!("Outbound → {target}   status: ")),
        Span::styled(
            snap.conn_status.label(),
            Style::default().fg(conn_color(&snap.conn_status)),
        ),
        Span::raw("   path: "),
        Span::raw(snap.path.describe()),
    ];
    if show_hint {
        spans.push(dial_hint(true));
    }
    Line::from(spans)
}

/// Modal for setting the single tunnel at runtime. Two text fields are rendered
/// as standard bordered input boxes; the active one owns the terminal cursor.
pub fn render_add_tunnel_dialog(frame: &mut Frame, form: &AddTunnelForm) {
    let error_rows = if form.error.is_some() { 2 } else { 0 };
    let area = centered(
        frame.area(),
        92,
        2 + 2 + INPUT_FIELD_HEIGHT * 2 + 1 + 2 + error_rows + 1,
    );
    frame.render_widget(Clear, area);
    let panel = Block::default()
        .borders(Borders::ALL)
        .title(" set tunnel ");
    frame.render_widget(panel, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    let mut constraints = vec![
        Constraint::Length(2),
        Constraint::Length(INPUT_FIELD_HEIGHT),
        Constraint::Length(INPUT_FIELD_HEIGHT),
        Constraint::Length(1),
        Constraint::Length(2),
    ];
    if form.error.is_some() {
        constraints.extend([Constraint::Length(1), Constraint::Length(1)]);
    }
    constraints.extend([Constraint::Min(0), Constraint::Length(1)]);
    let chunks = Layout::vertical(constraints).split(inner);
    let mut i = 0;

    render_modal_lines(
        frame,
        chunks[i],
        vec![
            Line::from(Span::styled(
                "Set tunnel",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
        ],
    );
    i += 1;
    render_input_field(
        frame,
        chunks[i],
        "Remote source",
        &form.remote_source,
        form.field == AddField::RemoteSource,
    );
    i += 1;
    render_input_field(
        frame,
        chunks[i],
        "Local listen",
        &form.local_listen,
        form.field == AddField::LocalListen,
    );
    i += 1;
    render_modal_line(
        frame,
        chunks[i],
        Line::from(Span::styled(
            "remote_source: host:port (TCP, on the peer)   local_listen: host:port (here)",
            Style::default().fg(Color::DarkGray),
        )),
    );
    i += 1;
    render_modal_line(
        frame,
        chunks[i],
        Line::from(Span::styled(
            "↑/↓ move field · Enter on local_listen sets (s to start) · Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    );
    i += 1;

    if let Some(err) = &form.error {
        i += 1; // spacer before the error
        render_modal_line(
            frame,
            chunks[i],
            Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))),
        );
    }

    render_modal_line(
        frame,
        chunks[chunks.len() - 1],
        Line::from(Span::styled(
            "Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    );
}

/// Modal for starting the on-demand dial session. One text field whose meaning depends
/// on the mode: a peer name (connect), a rotating PIN (quick PIN mode), or a full node id
/// (quick manual mode).
pub fn render_connect_dialog(
    frame: &mut Frame,
    form: &ConnectForm,
    nostr_discovery: bool,
    pin_mode: bool,
) {
    let (label, hint) = if nostr_discovery {
        (
            "Peer name",
            "the target peer's name (its config `name`); looked up via nostr",
        )
    } else if pin_mode {
        (
            "Dial PIN",
            "the short code shown on the other device (dashes/case ignored)",
        )
    } else {
        ("Node id", "the target peer's full node id")
    };

    let error_rows = if form.error.is_some() { 2 } else { 0 };
    let area = centered(
        frame.area(),
        84,
        2 + 2 + INPUT_FIELD_HEIGHT + 1 + 2 + error_rows + 1,
    );
    frame.render_widget(Clear, area);
    let panel = Block::default().borders(Borders::ALL).title(" connect ");
    frame.render_widget(panel, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    let mut constraints = vec![
        Constraint::Length(2),
        Constraint::Length(INPUT_FIELD_HEIGHT),
        Constraint::Length(1),
        Constraint::Length(2),
    ];
    if form.error.is_some() {
        constraints.extend([Constraint::Length(1), Constraint::Length(1)]);
    }
    constraints.extend([Constraint::Min(0), Constraint::Length(1)]);
    let chunks = Layout::vertical(constraints).split(inner);
    let mut i = 0;

    render_modal_lines(
        frame,
        chunks[i],
        vec![
            Line::from(Span::styled(
                "Connect to peer",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
        ],
    );
    i += 1;
    render_input_field(frame, chunks[i], label, &form.target, true);
    i += 1;
    i += 1; // spacer before hint
    render_modal_line(
        frame,
        chunks[i],
        Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))),
    );
    i += 1;

    if let Some(err) = &form.error {
        i += 1; // spacer before the error
        render_modal_line(
            frame,
            chunks[i],
            Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))),
        );
    }

    render_modal_line(
        frame,
        chunks[chunks.len() - 1],
        Line::from(Span::styled(
            "Enter connect · Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    );
}

fn render_modal_line(frame: &mut Frame, area: Rect, line: Line<'static>) {
    render_modal_lines(frame, area, vec![line]);
}

fn render_modal_lines(frame: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// Center a fixed-size area within `area`.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [h] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(area);
    let [v] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(h);
    v
}

fn render_tunnels(frame: &mut Frame, area: Rect, snap: &AppSnapshot, _ui: &UiState) {
    let header = Row::new(["", "SPEC", "STATUS", "DETAIL"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    // A pure listen-only half initiates no tunnel of its own, so its table stays
    // empty; the combined node's dial half drives the single tunnel.
    let empty_msg = match snap.role {
        Role::Listen => "(serving peers — this side initiates no tunnel)",
        Role::Dial | Role::Both => "(no tunnel set — press e)",
    };
    let rows: Vec<Row> = match &snap.tunnel {
        None => vec![Row::new(["", empty_msg, "", ""])],
        Some(t) => vec![tunnel_row(t)],
    };
    let widths = [
        Constraint::Length(3),
        Constraint::Percentage(55),
        Constraint::Length(10),
        Constraint::Percentage(30),
    ];
    let title = tunnel_title(snap);
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

fn tunnel_title(snap: &AppSnapshot) -> &'static str {
    match snap.role {
        Role::Listen => " Tunnel ",
        Role::Dial | Role::Both if has_connected_dial(snap) => {
            " Outbound Tunnel  [s start · x stop · e set · d clear] "
        }
        // Without a dial session the tunnel can be set but not started; the connect
        // hint lives on the dial header line above, not here.
        Role::Dial | Role::Both => " Outbound Tunnel  [e set · d clear] ",
    }
}

fn has_connected_dial(snap: &AppSnapshot) -> bool {
    snap.dial_target.is_some() && snap.conn_status == ConnStatus::Connected
}

fn tunnel_row(t: &TunnelRow) -> Row<'static> {
    let marker = if t.status.is_running() { "▶" } else { " " };
    Row::new(vec![
        Cell::from(format!(" {marker}")),
        Cell::from(t.spec.clone()),
        Cell::from(Span::styled(
            t.status.label(),
            Style::default().fg(tunnel_color(t.status)),
        )),
        Cell::from(t.detail.clone()),
    ])
}

fn render_peers(frame: &mut Frame, area: Rect, snap: &AppSnapshot) {
    let title = match snap.role {
        // The listener serves many peers at once; all currently-connected ones show here.
        // Both runs a listen half too, so it shows the same inbound-peers list.
        Role::Listen | Role::Both => " Connected peers ",
        Role::Dial => " Connection ",
    };
    let header = Row::new(["REMOTE ID", "SINCE", "PATH"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = match snap.role {
        Role::Listen | Role::Both => {
            if !snap.peers.is_empty() {
                snap.peers.iter().map(peer_row).collect()
            } else {
                vec![Row::new(["", "(waiting for peers)", ""])]
            }
        }
        Role::Dial => {
            let remote = snap
                .peers
                .first()
                .map(|p| short_id(&p.remote_id))
                .unwrap_or_else(|| "-".to_string());
            vec![Row::new(vec![
                Cell::from(remote),
                Cell::from(snap.conn_status.label()),
                Cell::from(snap.path.describe()),
            ])]
        }
    };

    let widths = [
        Constraint::Length(16),
        Constraint::Length(16),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

fn peer_row(p: &PeerRow) -> Row<'static> {
    Row::new(vec![
        Cell::from(short_id(&p.remote_id)),
        Cell::from(fmt_elapsed(p.connected_since.elapsed())),
        Cell::from(p.path.describe()),
    ])
}

fn render_logs(frame: &mut Frame, area: Rect, logs: &[LogLine], ui: &UiState) {
    // `logs` is already the right view for the mode (concise ring, or both rings merged
    // for verbose) — the caller picks which snapshot to pass, so render just paints it.
    // Visible body height inside the border.
    let body = area.height.saturating_sub(2) as usize;
    let total = logs.len();
    // Clamp the scroll so at least a full body of lines stays visible.
    let max_scroll = total.saturating_sub(body);
    let scroll = ui.log_scroll.min(max_scroll);
    let end = total - scroll;
    let start = end.saturating_sub(body);
    let lines: Vec<Line> = logs[start..end].iter().map(log_line).collect();

    let mode = if ui.verbose { "verbose" } else { "concise" };
    let title = if ui.quit_armed {
        format!(" Logs ({total}, {mode})  [press Esc again to quit] ")
    } else if scroll == 0 {
        format!(
            " Logs ({total}, {mode})  [Esc/l home · v verbose · [/] PgUp/Dn scroll · g/G top/bottom] "
        )
    } else {
        format!(" Logs ({total}, {mode})  [scrolled +{scroll} · Esc follow tail] ")
    };
    let para = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

fn log_line(l: &LogLine) -> Line<'static> {
    let time = l.ts.strftime("%H:%M:%S").to_string();
    let level = l.level.as_str();
    Line::from(vec![
        Span::styled(time, Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
        Span::styled(
            format!("{level:<5}"),
            Style::default().fg(level_color(l.level)),
        ),
        Span::raw(" "),
        Span::raw(l.msg.clone()),
    ])
}

fn short_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…", &id[..11])
    } else {
        id.to_string()
    }
}

fn fmt_elapsed(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

fn conn_color(status: &ConnStatus) -> Color {
    match status {
        ConnStatus::Connected => Color::Green,
        ConnStatus::Connecting | ConnStatus::Authenticating | ConnStatus::Reconnecting { .. } => {
            Color::Yellow
        }
        ConnStatus::Closed => Color::Red,
        ConnStatus::Idle => Color::DarkGray,
    }
}

fn tunnel_color(status: TunnelStatus) -> Color {
    match status {
        TunnelStatus::Listening => Color::Green,
        TunnelStatus::Idle => Color::DarkGray,
        TunnelStatus::Error => Color::Red,
    }
}

fn level_color(level: log::Level) -> Color {
    match level {
        log::Level::Error => Color::Red,
        log::Level::Warn => Color::Yellow,
        log::Level::Info => Color::Green,
        log::Level::Debug | log::Level::Trace => Color::DarkGray,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::PathInfo;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn base_snapshot(nostr_discovery: bool, own_name: Option<&str>) -> AppSnapshot {
        AppSnapshot {
            role: Role::Both,
            hostname: "test-host".to_string(),
            token_generated: false,
            nostr_discovery,
            pin_mode: false,
            current_pin: None,
            pin_deadline: None,
            own_name: own_name.map(str::to_string),
            endpoint_id: Some("node-123".to_string()),
            auth_token: None,
            conn_status: ConnStatus::Idle,
            path: PathInfo::establishing(),
            dial_target: None,
            name_conflict: crate::app_state::NameConflict::Inactive,
            peers: Vec::new(),
            tunnel: None,
            streams_used: 0,
            streams_max: 64,
        }
    }

    fn render_text(snap: &AppSnapshot, ui: &UiState) -> String {
        render_text_with_logs(snap, &[], ui)
    }

    fn render_text_with_logs(snap: &AppSnapshot, logs: &[LogLine], ui: &UiState) -> String {
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, snap, logs, ui))
            .expect("render");

        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn log(level: log::Level, msg: &str, verbose_only: bool) -> LogLine {
        LogLine {
            level,
            msg: msg.to_string(),
            ts: jiff::Zoned::now(),
            verbose_only,
        }
    }

    #[test]
    fn pin_mode_header_shows_rotating_pin_and_countdown_not_token() {
        let mut snap = base_snapshot(false, None);
        snap.pin_mode = true;
        snap.token_generated = true; // quick mode always has one, but PIN mode hides it
        snap.auth_token = Some(crate::auth::generate_token());
        snap.current_pin = Some("K7P29QXM".to_string());
        snap.pin_deadline = Some(Instant::now() + std::time::Duration::from_secs(41));

        let out = render_text(&snap, &UiState::default());
        assert!(out.contains("dial PIN"), "PIN banner shown");
        assert!(out.contains("K7P2-9QXM"), "PIN is grouped for display");
        assert!(out.contains("refreshes in"), "countdown shown");
        // The raw auth-token banner must not appear in PIN mode.
        assert!(!out.contains("auth token:"), "token banner suppressed in PIN mode");
    }

    #[test]
    fn connect_dialog_label_depends_on_mode() {
        let backend = TestBackend::new(120, 24);
        let render_dialog = |nostr: bool, pin: bool| {
            let mut terminal = Terminal::new(backend.clone()).expect("terminal");
            let form = ConnectForm::default();
            terminal
                .draw(|f| render_connect_dialog(f, &form, nostr, pin))
                .expect("draw");
            let buf = terminal.backend().buffer();
            let mut out = String::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    out.push_str(buf[(x, y)].symbol());
                }
            }
            out
        };
        assert!(render_dialog(true, false).contains("Peer name"));
        assert!(render_dialog(false, true).contains("Dial PIN"));
        assert!(render_dialog(false, false).contains("Node id"));
    }

    #[test]
    fn log_screen_labels_the_active_view_mode() {
        let snap = base_snapshot(false, None);
        // The caller passes the view that matches the toggle (concise ring vs merged);
        // render paints it and labels the mode in the title.
        let concise_logs = vec![log(log::Level::Info, "own-line", false)];
        let merged_logs = vec![
            log(log::Level::Info, "own-line", false),
            log(log::Level::Warn, "iroh-churn", true),
        ];

        let concise = render_text_with_logs(
            &snap,
            &concise_logs,
            &UiState {
                screen: Screen::Logs,
                ..Default::default()
            },
        );
        assert!(concise.contains("own-line"));
        assert!(!concise.contains("iroh-churn"));
        assert!(concise.contains("concise"));

        let verbose = render_text_with_logs(
            &snap,
            &merged_logs,
            &UiState {
                screen: Screen::Logs,
                verbose: true,
                ..Default::default()
            },
        );
        assert!(verbose.contains("own-line"));
        assert!(verbose.contains("iroh-churn"));
        assert!(verbose.contains("verbose"));
    }

    #[test]
    fn connect_idle_dashboard_shows_mode_name_and_idle_dial() {
        let snap = base_snapshot(true, Some("web1"));

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("mode: connect"));
        assert!(text.contains("name: web1"));
        assert!(text.contains("Outbound: not connected"));
        // The connect control hint lives on the dial header line, not the Tunnels box.
        assert!(text.contains("Shift-C connect"));
    }

    #[test]
    fn header_shows_app_version_on_both_screens() {
        let snap = base_snapshot(false, None);
        let version = concat!("v", env!("CARGO_PKG_VERSION"));

        let home = render_text(&snap, &UiState::default());
        assert!(home.contains(version), "home header should show the version");

        let logs_ui = UiState {
            screen: Screen::Logs,
            ..Default::default()
        };
        let logs = render_text(&snap, &logs_ui);
        assert!(logs.contains(version), "logs header should show the version");
    }

    #[test]
    fn home_screen_hides_log_pane_and_logs_screen_shows_it() {
        let snap = base_snapshot(false, None);

        // Home screen: no log pane, but a footer pointing at the logs screen.
        let home = render_text(&snap, &UiState::default());
        assert!(!home.contains("Logs ("));
        assert!(home.contains("l logs"));

        // Logs screen: the log pane is present, peers/tunnels are not.
        let logs_ui = UiState {
            screen: Screen::Logs,
            ..Default::default()
        };
        let logs = render_text(&snap, &logs_ui);
        assert!(logs.contains("Logs ("));
        assert!(!logs.contains("Connected peers"));
    }

    #[test]
    fn dial_hint_shows_on_home_but_not_on_logs_screen() {
        let snap = base_snapshot(true, Some("web1"));

        let home = render_text(&snap, &UiState::default());
        assert!(home.contains("Shift-C connect"));

        // The Shift-C/Shift-D dial controls are home-only, so the logs header drops
        // the hint while still showing the dial status line.
        let logs_ui = UiState {
            screen: Screen::Logs,
            ..Default::default()
        };
        let logs = render_text(&snap, &logs_ui);
        assert!(logs.contains("Outbound: not connected"));
        assert!(!logs.contains("Shift-C connect"));
    }

    #[test]
    fn quick_idle_dashboard_shows_mode_without_name() {
        let snap = base_snapshot(false, None);

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("mode: quick"));
        assert!(!text.contains("name:"));
    }

    #[test]
    fn idle_dashboard_omits_role_idle_status_and_establishing_path() {
        let snap = base_snapshot(false, None);

        let text = render_text(&snap, &UiState::default());

        assert!(!text.contains("role:"));
        assert!(!text.contains("status: Idle"));
        assert!(!text.contains("path: establishing"));
    }

    #[test]
    fn active_dial_dashboard_shows_target_status_and_path() {
        let mut snap = base_snapshot(true, Some("web1"));
        snap.dial_target = Some("homelab".to_string());
        snap.conn_status = ConnStatus::Connecting;

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("Outbound → homelab"));
        assert!(text.contains("status: Connecting"));
        assert!(text.contains("path: establishing…"));
        // An active session offers disconnect (not connect) on the dial header line.
        assert!(text.contains("Shift-D disconnect"));
    }

    #[test]
    fn generated_token_banner_is_visible() {
        let mut snap = base_snapshot(false, None);
        snap.token_generated = true;
        snap.auth_token = Some("generated-secret-token".to_string());

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("auth token:"));
        assert!(text.contains("generated-secret-token"));
    }

    #[test]
    fn tunnel_title_matches_dial_state() {
        let snap = base_snapshot(false, None);
        let idle_text = render_text(&snap, &UiState::default());
        // Idle (no dial session): no start/stop hint, and the Tunnel box carries only
        // set/clear actions (the connect hint moved to the dial header line).
        assert!(!idle_text.contains("s start"));
        assert!(idle_text.contains("[e set · d clear]"));

        let mut connected = base_snapshot(false, None);
        connected.dial_target = Some("peer".to_string());
        connected.conn_status = ConnStatus::Connected;
        let connected_text = render_text(&connected, &UiState::default());
        assert!(connected_text.contains("s start"));
    }
}
