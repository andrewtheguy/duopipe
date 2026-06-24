//! Rendering for the duopipe TUI. Pure functions over an [`AppSnapshot`].

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use tui_input::Input;

use super::textinput::render_spans;
use crate::app_state::{
    AppSnapshot, ConnStatus, NameConflict, PeerRow, Role, TunnelRow, TunnelStatus,
};
use crate::logging::LogLine;

/// View state owned by the TUI loop (not shared with the runtime).
#[derive(Default)]
pub struct UiState {
    /// Lines scrolled up from the bottom of the log pane. 0 = follow tail.
    pub log_scroll: usize,
    /// Index of the highlighted tunnel row (toggled with Enter).
    pub selected: usize,
    /// When `Some`, the "add request" modal is open and captures all keystrokes.
    pub add_form: Option<AddRequestForm>,
    /// When `Some`, the "connect to peer" modal is open and captures all keystrokes.
    pub connect_form: Option<ConnectForm>,
    /// Set once the user presses `h`, once a peer has connected, or once the
    /// auto-hide timeout expires: hides the generated-token banner for the rest
    /// of the session.
    pub token_banner_hidden: bool,
    /// Deadline for auto-hiding a freshly generated auth token. Set by the
    /// dashboard loop, not by rendering.
    pub token_banner_auto_hide_at: Option<Instant>,
    /// First Esc of a double-Esc quit has been seen; the next Esc quits. Cleared
    /// by any other key. Drives the "press Esc again" hint.
    pub quit_armed: bool,
}

/// Which field the "add request" modal is currently editing.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum AddField {
    #[default]
    Name,
    /// Protocol selector (tcp/udp) for `remote_source`; not a text field.
    Protocol,
    RemoteSource,
    LocalListen,
}

/// Transport protocol chosen on the add-request form. Becomes the `remote_source`
/// URL scheme, so the user types only `host:port`.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

impl Protocol {
    /// URL scheme for this protocol (`tcp` / `udp`).
    pub fn scheme(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }

    /// Toggle between the two protocols.
    pub fn toggled(self) -> Self {
        match self {
            Protocol::Tcp => Protocol::Udp,
            Protocol::Udp => Protocol::Tcp,
        }
    }
}

/// In-progress entry for a runtime-added tunnel request (modal state).
#[derive(Default)]
pub struct AddRequestForm {
    pub field: AddField,
    pub name: Input,
    /// Protocol for `remote_source`; defaults to TCP.
    pub protocol: Protocol,
    pub remote_source: Input,
    pub local_listen: Input,
    /// Inline validation error from the last failed submit; cleared on next keypress.
    pub error: Option<String>,
}

impl AddRequestForm {
    /// The text input for the field currently being edited, or `None` for the
    /// non-text [`AddField::Protocol`] selector.
    pub fn active_mut(&mut self) -> Option<&mut Input> {
        match self.field {
            AddField::Name => Some(&mut self.name),
            AddField::RemoteSource => Some(&mut self.remote_source),
            AddField::LocalListen => Some(&mut self.local_listen),
            AddField::Protocol => None,
        }
    }
}

/// In-progress entry for the runtime "connect to peer" modal (single text field).
#[derive(Default)]
pub struct ConnectForm {
    /// The target: a peer name (nostr mode) or a full node id (quick mode).
    pub target: Input,
    /// Inline validation error from the last failed submit; cleared on next keypress.
    pub error: Option<String>,
}

pub fn render(frame: &mut Frame, snap: &AppSnapshot, logs: &[LogLine], ui: &UiState) {
    // Show the freshly generated token in the header until a peer connects or the
    // user dismisses it (both captured by `token_banner_hidden`).
    let show_token_banner = show_generated_token_banner(snap, ui);
    let show_conflict_warning = matches!(snap.name_conflict, NameConflict::Degraded { .. });
    let tunnel_rows = snap.tunnels.len().max(1) as u16 + 2; // header + border
    let peer_rows = snap.peers.len().max(1) as u16 + 2;
    let [header_area, tunnels_area, peers_area, logs_area] = Layout::vertical([
        Constraint::Length(header_height(show_token_banner, show_conflict_warning)),
        Constraint::Length(tunnel_rows.clamp(4, 10)),
        Constraint::Length(peer_rows.clamp(3, 8)),
        Constraint::Min(3),
    ])
    .areas(frame.area());

    render_header(frame, header_area, snap, show_token_banner);
    render_tunnels(frame, tunnels_area, snap, ui);
    render_peers(frame, peers_area, snap);
    render_logs(frame, logs_area, logs, ui);
}

fn show_generated_token_banner(snap: &AppSnapshot, ui: &UiState) -> bool {
    matches!(snap.role, Role::Listen | Role::Both) && snap.token_generated && !ui.token_banner_hidden
}

fn header_height(show_token_banner: bool, show_conflict_warning: bool) -> u16 {
    let base = if show_token_banner { 6 } else { 5 };
    base + if show_conflict_warning { 1 } else { 0 }
}

fn render_header(frame: &mut Frame, area: Rect, snap: &AppSnapshot, show_token_banner: bool) {
    let endpoint = snap.endpoint_id.as_deref().unwrap_or("(pending)");
    let mut app_line = vec![
        Span::styled("duopipe", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" @ "),
        Span::styled(
            snap.hostname.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  mode: "),
        Span::styled(mode_label(snap), Style::default().add_modifier(Modifier::BOLD)),
    ];
    if let Some(name) = own_name_display(snap) {
        app_line.push(Span::raw("  name: "));
        app_line.push(Span::styled(
            name.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    app_line.push(Span::raw("  streams: "));
    app_line.push(Span::raw(format!(
        "{}/{}",
        snap.streams_used, snap.streams_max
    )));

    let mut lines = vec![
        Line::from(app_line),
        Line::from(vec![Span::raw("node id: "), Span::raw(endpoint)]),
        dial_header_line(snap),
    ];

    if show_token_banner {
        // Freshly generated token, not yet dismissed: surface it so the dialer can
        // copy it. Hidden once a peer connects or the user presses `h`.
        let token = snap.auth_token.as_deref().unwrap_or("(pending)");
        lines.push(Line::from(vec![
            Span::raw("auth token: "),
            Span::styled(
                token.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  (hides after 10m, h to hide now)",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
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
        "nostr"
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
        .map(|target| format!("dial → {target}"))
        .unwrap_or_else(|| "dial: not connected (press c)".to_string())
}

fn dial_header_line(snap: &AppSnapshot) -> Line<'static> {
    let Some(target) = snap.dial_target.as_deref() else {
        return Line::from(Span::raw(dial_text(snap)));
    };

    Line::from(vec![
        Span::raw(format!("dial → {target}   status: ")),
        Span::styled(
            snap.conn_status.label(),
            Style::default().fg(conn_color(&snap.conn_status)),
        ),
        Span::raw("   path: "),
        Span::raw(snap.path.describe()),
    ])
}

/// Modal for adding a tunnel request at runtime. Three labeled fields; the active
/// one carries a blinking block cursor. Mirrors the setup-screen input style.
pub fn render_add_request_dialog(frame: &mut Frame, form: &AddRequestForm) {
    let field_line = |label: &str, input: &Input, active: bool| -> Line<'static> {
        let mut spans = vec![Span::raw(format!("{label:<14}"))];
        let style = Style::default().fg(Color::Cyan);
        if active {
            spans.extend(render_spans(input, style));
        } else {
            spans.push(Span::styled(input.value().to_string(), style));
        }
        Line::from(spans)
    };

    let protocol_active = form.field == AddField::Protocol;
    let protocol_line = {
        let mut spans = vec![Span::raw(format!("{:<14}", "protocol:"))];
        for p in [Protocol::Tcp, Protocol::Udp] {
            let selected = form.protocol == p;
            let mut style = Style::default();
            if selected {
                style = style.fg(Color::Cyan).add_modifier(Modifier::BOLD);
                if protocol_active {
                    style = style.add_modifier(Modifier::REVERSED);
                }
            } else {
                style = style.fg(Color::DarkGray);
            }
            spans.push(Span::styled(format!(" {} ", p.scheme()), style));
            spans.push(Span::raw(" "));
        }
        if protocol_active {
            spans.push(Span::styled(
                "←/→ to switch",
                Style::default().fg(Color::DarkGray),
            ));
        }
        Line::from(spans)
    };

    let mut lines = vec![
        Line::from(Span::styled(
            "Add tunnel request",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        field_line("name:", &form.name, form.field == AddField::Name),
        protocol_line,
        field_line(
            "remote_source:",
            &form.remote_source,
            form.field == AddField::RemoteSource,
        ),
        field_line(
            "local_listen:",
            &form.local_listen,
            form.field == AddField::LocalListen,
        ),
        Line::raw(""),
        Line::from(Span::styled(
            "remote_source: host:port (protocol prepended)   local_listen: host:port   (name optional)",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    if let Some(err) = &form.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Tab/Enter next field · ←/→ switch protocol · Enter on local_listen adds & starts · Esc cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let area = centered(frame.area(), 88, lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" add request "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// Modal for starting the on-demand dial session. One text field whose meaning depends
/// on the mode: a peer name (nostr) or a full node id (quick).
pub fn render_connect_dialog(frame: &mut Frame, form: &ConnectForm, nostr_discovery: bool) {
    let (label, hint) = if nostr_discovery {
        (
            "peer name:",
            "the target peer's name (its config `name`); looked up via nostr",
        )
    } else {
        ("node id:", "the target peer's full node id")
    };

    let mut field_spans = vec![Span::raw(format!("{label:<10}"))];
    field_spans.extend(render_spans(&form.target, Style::default().fg(Color::Cyan)));

    let mut lines = vec![
        Line::from(Span::styled(
            "Connect to peer",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(field_spans),
        Line::raw(""),
        Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray))),
    ];

    if let Some(err) = &form.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Enter connect · Esc cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let area = centered(frame.area(), 80, lines.len() as u16 + 2);
    frame.render_widget(Clear, area);
    let para = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" connect "))
        .wrap(Wrap { trim: false });
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

fn render_tunnels(frame: &mut Frame, area: Rect, snap: &AppSnapshot, ui: &UiState) {
    let header = Row::new(["", "NAME", "SPEC", "STATUS", "DETAIL"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    // The listen role is a pure server: it serves the peers' requests and initiates
    // no tunnels of its own, so its table stays empty.
    let empty_msg = match snap.role {
        Role::Listen => "(serving peers — this side initiates no tunnels)",
        // Both runs a dial half, so its tunnel table is interactive like Dial.
        Role::Dial | Role::Both => "(no tunnels configured)",
    };
    let rows: Vec<Row> = if snap.tunnels.is_empty() {
        vec![Row::new(["", "", empty_msg, "", ""])]
    } else {
        snap.tunnels
            .iter()
            .enumerate()
            .map(|(i, t)| tunnel_row(t, i == ui.selected))
            .collect()
    };
    let widths = [
        Constraint::Length(3),
        Constraint::Length(14),
        Constraint::Percentage(45),
        Constraint::Length(10),
        Constraint::Percentage(25),
    ];
    let title = tunnel_title(snap);
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

fn tunnel_title(snap: &AppSnapshot) -> &'static str {
    match snap.role {
        Role::Listen => " Tunnels ",
        Role::Dial | Role::Both if has_connected_dial(snap) => {
            " Tunnels  [↑/↓ select · Enter start/stop · a add · x/Del delete] "
        }
        Role::Dial | Role::Both => " Tunnels  [c connect · a add · x/Del delete] ",
    }
}

fn has_connected_dial(snap: &AppSnapshot) -> bool {
    snap.dial_target.is_some() && snap.conn_status == ConnStatus::Connected
}

fn tunnel_row(t: &TunnelRow, selected: bool) -> Row<'static> {
    let marker = if t.status.is_running() { "▶" } else { " " };
    let cursor = if selected { "›" } else { " " };
    let row = Row::new(vec![
        Cell::from(format!("{cursor}{marker}")),
        Cell::from(t.name.clone()),
        Cell::from(t.spec.clone()),
        Cell::from(Span::styled(
            t.status.label(),
            Style::default().fg(tunnel_color(t.status)),
        )),
        Cell::from(t.detail.clone()),
    ]);
    if selected {
        row.style(Style::default().add_modifier(Modifier::REVERSED))
    } else {
        row
    }
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
    // Visible body height inside the border.
    let body = area.height.saturating_sub(2) as usize;
    let total = logs.len();
    // Clamp the scroll so at least a full body of lines stays visible.
    let max_scroll = total.saturating_sub(body);
    let scroll = ui.log_scroll.min(max_scroll);
    let end = total - scroll;
    let start = end.saturating_sub(body);
    let lines: Vec<Line> = logs[start..end].iter().map(log_line).collect();

    let title = if ui.quit_armed {
        format!(" Logs ({total})  [press Esc again to quit] ")
    } else if scroll == 0 {
        format!(
            " Logs ({total})  [Esc Esc quit · [/] or PgUp/PgDn scroll · g/G top/bottom · d dump] "
        )
    } else {
        format!(" Logs ({total})  [scrolled +{scroll}] ")
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
            own_name: own_name.map(str::to_string),
            endpoint_id: Some("node-123".to_string()),
            auth_token: None,
            conn_status: ConnStatus::Idle,
            path: PathInfo::establishing(),
            dial_target: None,
            name_conflict: crate::app_state::NameConflict::Inactive,
            peers: Vec::new(),
            tunnels: Vec::new(),
            streams_used: 0,
            streams_max: 64,
        }
    }

    fn render_text(snap: &AppSnapshot, ui: &UiState) -> String {
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| render(frame, snap, &[], ui))
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

    #[test]
    fn nostr_idle_dashboard_shows_mode_name_and_idle_dial() {
        let snap = base_snapshot(true, Some("web1"));

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("mode: nostr"));
        assert!(text.contains("name: web1"));
        assert!(text.contains("dial: not connected (press c)"));
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

        assert!(text.contains("dial → homelab"));
        assert!(text.contains("status: Connecting"));
        assert!(text.contains("path: establishing…"));
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
        assert!(idle_text.contains("c connect"));
        assert!(!idle_text.contains("Enter start/stop"));

        let mut connected = base_snapshot(false, None);
        connected.dial_target = Some("peer".to_string());
        connected.conn_status = ConnStatus::Connected;
        let connected_text = render_text(&connected, &UiState::default());
        assert!(connected_text.contains("Enter start/stop"));
    }
}
