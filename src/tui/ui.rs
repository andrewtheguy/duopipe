//! Rendering for the duopipe TUI. Pure functions over an [`AppSnapshot`].

use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use ratatui::Frame;
use tui_input::Input;

use super::textinput::render_spans;
use crate::app_state::{
    AppSnapshot, ConnStatus, PeerRow, Role, TunnelRow, TunnelStatus,
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
    /// Set once the user presses `h`, or once a peer has connected: hides the
    /// generated-token banner in the header for the rest of the session.
    pub token_banner_hidden: bool,
    /// First Esc of a double-Esc quit has been seen; the next Esc quits. Cleared
    /// by any other key. Drives the "press Esc again" hint.
    pub quit_armed: bool,
}

/// Which field the "add request" modal is currently editing.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum AddField {
    #[default]
    Name,
    RemoteSource,
    LocalListen,
}

/// In-progress entry for a runtime-added tunnel request (modal state).
#[derive(Default)]
pub struct AddRequestForm {
    pub field: AddField,
    pub name: Input,
    pub remote_source: Input,
    pub local_listen: Input,
    /// Inline validation error from the last failed submit; cleared on next keypress.
    pub error: Option<String>,
}

impl AddRequestForm {
    /// The input for the field currently being edited.
    pub fn active_mut(&mut self) -> &mut Input {
        match self.field {
            AddField::Name => &mut self.name,
            AddField::RemoteSource => &mut self.remote_source,
            AddField::LocalListen => &mut self.local_listen,
        }
    }
}

pub fn render(frame: &mut Frame, snap: &AppSnapshot, logs: &[LogLine], ui: &UiState) {
    let tunnel_rows = snap.tunnels.len().max(1) as u16 + 2; // header + border
    let peer_rows = snap.peers.len().max(1) as u16 + 2;
    let [header_area, tunnels_area, peers_area, logs_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(tunnel_rows.clamp(4, 10)),
        Constraint::Length(peer_rows.clamp(3, 8)),
        Constraint::Min(3),
    ])
    .areas(frame.area());

    // Show the freshly generated token in the header until a peer connects or the
    // user dismisses it (both captured by `token_banner_hidden`).
    let show_token_banner =
        snap.role == Role::Listen && snap.token_generated && !ui.token_banner_hidden;
    render_header(frame, header_area, snap, show_token_banner);
    render_tunnels(frame, tunnels_area, snap, ui);
    render_peers(frame, peers_area, snap);
    render_logs(frame, logs_area, logs, ui);
}

fn render_header(frame: &mut Frame, area: Rect, snap: &AppSnapshot, show_token_banner: bool) {
    let endpoint = snap.endpoint_id.as_deref().unwrap_or("(pending)");
    let status_label = snap.conn_status.label();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("duopipe", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" @ "),
            Span::styled(
                snap.hostname.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  role: "),
            Span::styled(
                snap.role.label(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  sessions: "),
            Span::raw(format!("{}/{}", snap.sessions_used, snap.sessions_max)),
        ]),
        Line::from(vec![Span::raw("node id: "), Span::raw(endpoint)]),
    ];

    if snap.role == Role::Dial {
        lines.push(Line::from(vec![
            Span::raw("status: "),
            Span::styled(status_label, Style::default().fg(conn_color(&snap.conn_status))),
            Span::raw("   path: "),
            Span::raw(snap.path.describe()),
        ]));
    } else if show_token_banner {
        // Listen + freshly generated token, not yet dismissed: surface the token so
        // the dialer can copy it. Hidden once a peer connects or the user presses `h`.
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
                "  (generated — press h to hide)",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else {
        // Listen role: the node id (above) is ephemeral and stays visible so the
        // dialer can copy it. The token itself is not shown here.
        let hint = if snap.token_generated {
            "auth token generated for this session"
        } else {
            "auth token loaded from config"
        };
        lines.push(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines).block(Block::default().borders(Borders::ALL));
    frame.render_widget(para, area);
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

    let mut lines = vec![
        Line::from(Span::styled(
            "Add tunnel request",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        field_line("name:", &form.name, form.field == AddField::Name),
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
            "remote_source: tcp:// or udp://host:port   local_listen: host:port   (name optional)",
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
        "Tab/Enter next field · Enter on local_listen adds & starts · Esc cancel",
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
    let rows: Vec<Row> = if snap.tunnels.is_empty() {
        vec![Row::new(["", "", "(no tunnels configured)", "", ""])]
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
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Tunnels  [↑/↓ select · Enter start/stop · a add] "),
    );
    frame.render_widget(table, area);
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
        Role::Listen => " Connected peers ",
        Role::Dial => " Connection ",
    };
    let header = Row::new(["REMOTE ID", "SINCE", "PATH"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = match snap.role {
        Role::Listen => {
            if snap.peers.is_empty() {
                vec![Row::new(["", "(waiting for peers)", ""])]
            } else {
                snap.peers.iter().map(peer_row).collect()
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
        format!(" Logs ({total})  [Esc Esc quit · [/] or PgUp/PgDn scroll · g/G top/bottom · d dump] ")
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
        ConnStatus::Connecting
        | ConnStatus::Authenticating
        | ConnStatus::Reconnecting { .. } => Color::Yellow,
        ConnStatus::Closed => Color::Red,
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
