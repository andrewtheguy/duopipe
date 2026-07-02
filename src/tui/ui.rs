//! Rendering for the duopipe TUI. Pure functions over an [`AppSnapshot`].

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use tui_input::Input;

use super::textinput::{INPUT_FIELD_HEIGHT, render_input_field};
use crate::app_state::{AppSnapshot, ConnStatus, NameConflict, Role, SocksRow, SocksStatus};
use crate::logging::LogLine;

/// Which top-level screen the dashboard is showing. Logs live on their own screen
/// so their scroll keys (`[`/`]`, `g`/`G`, PgUp/PgDn) don't collide with the home
/// screen's tunnel navigation.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// Header (with inline paired-peer status) + tunnels.
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
    /// When `Some`, the set-SOCKS-port modal is open and captures all keystrokes.
    pub add_form: Option<SocksForm>,
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

/// In-progress entry for the set-SOCKS-port modal (modal state). Used both to set a
/// fresh port and to replace the current one (only allowed while the proxy is not
/// running). The single field holds a decimal port (1..=65535).
#[derive(Default)]
pub struct SocksForm {
    pub port: Input,
    /// Inline validation error from the last failed submit; cleared on next keypress.
    pub error: Option<String>,
}

impl SocksForm {
    /// Build a form pre-filled with the current port (replace in place).
    pub fn edit(port: u16) -> Self {
        Self {
            port: Input::new(port.to_string()),
            error: None,
        }
    }
}

/// In-progress entry for the runtime "connect to peer" modal (single text field).
#[derive(Default)]
pub struct ConnectForm {
    /// The target: a peer name (config mode) or a full node id (quick mode).
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

/// The home screen: header (which now carries the single paired-peer status inline) and the
/// tunnel table. Logs live on their own screen (`l`) so their keys don't fight the tunnel
/// navigation.
fn render_home(frame: &mut Frame, snap: &AppSnapshot, ui: &UiState) {
    // Show the freshly generated token in the header until a peer connects or the
    // user dismisses it (both captured by `token_banner_hidden`).
    let show_token_banner = show_generated_token_banner(snap, ui);
    let show_pin_banner = show_pin_banner(snap);
    let hide_at = banner_hide_at(show_token_banner || show_pin_banner, ui);
    let show_conflict_warning = matches!(snap.name_conflict, NameConflict::Degraded { .. });
    let tunnel_rows = 1u16 + 2; // single tunnel row + header + border
    let [header_area, tunnels_area, _filler, footer_area] = Layout::vertical([
        Constraint::Length(header_height(
            snap,
            show_token_banner,
            show_pin_banner,
            show_conflict_warning,
        )),
        Constraint::Length(tunnel_rows.clamp(4, 10)),
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
        HeaderBanners {
            show_token: show_token_banner,
            show_pin: show_pin_banner,
            pin_hidden: ui.token_banner_hidden,
            hide_at: hide_at.as_deref(),
        },
        true,
    );
    render_tunnels(frame, tunnels_area, snap, ui);
    render_home_footer(frame, footer_area, snap, ui);
}

/// The logs screen: the same header plus a full-height log pane.
fn render_logs_screen(frame: &mut Frame, snap: &AppSnapshot, logs: &[LogLine], ui: &UiState) {
    let show_token_banner = show_generated_token_banner(snap, ui);
    let show_pin_banner = show_pin_banner(snap);
    let hide_at = banner_hide_at(show_token_banner || show_pin_banner, ui);
    let show_conflict_warning = matches!(snap.name_conflict, NameConflict::Degraded { .. });
    let [header_area, logs_area] = Layout::vertical([
        Constraint::Length(header_height(
            snap,
            show_token_banner,
            show_pin_banner,
            show_conflict_warning,
        )),
        Constraint::Min(3),
    ])
    .areas(frame.area());

    render_header(
        frame,
        header_area,
        snap,
        HeaderBanners {
            show_token: show_token_banner,
            show_pin: show_pin_banner,
            pin_hidden: ui.token_banner_hidden,
            hide_at: hide_at.as_deref(),
        },
        false,
    );
    render_logs(frame, logs_area, logs, ui);
}

/// The inbound-peer status shown inline in the header (replacing the old connected-peers panel):
/// who this endpoint is paired with, or that it is waiting / reserved. `None` before listening,
/// where the node-id line already prompts the user to press Shift+L.
fn inbound_status_line(snap: &AppSnapshot) -> Option<Line<'static>> {
    if !snap.listening {
        return None;
    }
    let line = match &snap.inbound {
        Some(p) if p.connected() => Line::from(vec![
            Span::raw("inbound ← "),
            Span::styled(
                short_id(&p.remote_id),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "   path: {}   up {}",
                p.path.describe(),
                fmt_elapsed(p.connected_since.elapsed())
            )),
        ]),
        Some(p) => Line::from(vec![
            Span::raw("inbound: "),
            Span::styled(
                reserved_inbound_label(&short_id(&p.remote_id)),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        None => Line::from(Span::styled(
            "inbound: waiting for a peer",
            Style::default().fg(Color::DarkGray),
        )),
    };
    Some(line)
}

/// Shared wording for the paired-but-disconnected (reserved) inbound state, so the header line and
/// the `w` connection dump describe it identically. `id` is the caller's chosen form of the peer's
/// node id (truncated in the header, full in the dump).
pub(super) fn reserved_inbound_label(id: &str) -> String {
    format!("reserved for {id} (disconnected)")
}

/// One-line footer for the home screen carrying the global key hints (the per-pane
/// hints live in the tunnel/log titles).
fn render_home_footer(frame: &mut Frame, area: Rect, snap: &AppSnapshot, ui: &UiState) {
    let text = if ui.quit_armed {
        "press Esc again to quit".to_string()
    } else {
        // The show/hide-secret hint only makes sense while listening — there is no node
        // id / PIN / token banner to toggle before the serve half is up. One-pairing rule:
        // while an outbound dial session exists, listening is unavailable, so drop the
        // Shift+L hint entirely.
        let (listen, secret_hint) = if snap.listening {
            let secret = if snap.pin_mode { "PIN" } else { "token" };
            (
                "Shift+L stop listening · ".to_string(),
                format!(" · h show/hide {secret}"),
            )
        } else if snap.dial_target.is_some() {
            (String::new(), String::new())
        } else {
            ("Shift+L start listening · ".to_string(), String::new())
        };
        format!("{listen}l logs · w dump{secret_hint} · Esc Esc quit")
    };
    let para = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(para, area);
}

fn show_generated_token_banner(snap: &AppSnapshot, ui: &UiState) -> bool {
    // In quick PIN mode the rotating-PIN banner replaces the raw token banner entirely.
    // Hidden until the serve half is up, since there is nothing to pair with before then.
    snap.listening
        && matches!(snap.role, Role::Listen | Role::Both)
        && snap.token_generated
        && !snap.pin_mode
        && !ui.token_banner_hidden
}

/// Quick PIN mode shows a banner with the current rotating PIN and its refresh countdown,
/// shown once the publisher has minted the first PIN. Like the token banner it auto-hides
/// after a few minutes and is toggled with `h`.
fn show_pin_banner(snap: &AppSnapshot) -> bool {
    // The banner *area* is present whenever the serve half is up in quick PIN mode and a
    // PIN has been minted, hidden or not. Visibility of the value itself is decoupled from
    // presence (`token_banner_hidden`): when hidden, the `dial PIN:` label and the
    // `press h to hide/show` hint stay sticky so the user can bring the code back.
    snap.listening
        && matches!(snap.role, Role::Listen | Role::Both)
        && snap.pin_mode
        && snap.current_pin.is_some()
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

fn header_height(
    snap: &AppSnapshot,
    show_token_banner: bool,
    show_pin_banner: bool,
    show_conflict_warning: bool,
) -> u16 {
    // Three fixed content rows (app identity, mode/name, streams/fp) plus a 2-row
    // frame. The remaining rows are direction-committed (see `render_header`): the
    // listen/node-id line unless dialing, the inbound line while listening, and the
    // outbound line unless listening. A token *or* PIN banner adds two rows.
    let dialing = snap.dial_target.is_some();
    let node_line = u16::from(snap.listening || !dialing);
    let inbound_line = u16::from(snap.listening);
    let dial_line = u16::from(dialing || !snap.listening);
    let banner = if show_token_banner || show_pin_banner { 2 } else { 0 };
    2 + 3 + node_line + inbound_line + dial_line + banner + u16::from(show_conflict_warning)
}

/// The header's optional banner state, bundled to keep `render_header`'s signature small.
struct HeaderBanners<'a> {
    /// The freshly generated auth-token banner (manual quick mode / config mode).
    show_token: bool,
    /// The rotating dial-PIN banner (quick PIN mode); present even while the value is hidden.
    show_pin: bool,
    /// Whether the secret value is hidden. For the PIN the label and hide/show hint stay
    /// sticky while the value/timers are masked.
    pin_hidden: bool,
    /// Absolute auto-hide time (`HH:MM`), when a banner with an armed deadline is shown.
    hide_at: Option<&'a str>,
}

fn render_header(
    frame: &mut Frame,
    area: Rect,
    snap: &AppSnapshot,
    banners: HeaderBanners<'_>,
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
    // This peer's identity: mode and (in config mode) its name.
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
    // Only meaningful once the serve half is up and there is a live endpoint to pair with.
    // Suppressed whenever the token was auto-generated: it is shared automatically (via the
    // PIN or the token banner) and is identical across paired devices, so the fp is pure
    // noise. With a config-supplied token the fp lets the user confirm both devices match.
    if snap.listening && !snap.token_generated && let Some(token) = snap.auth_token.as_deref() {
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
    ];

    // A run commits to one direction, so the header shows only the relevant side:
    //   - listening → the node-id + inbound (listener) lines, no outbound line;
    //   - dialing   → the outbound line, no listen/node-id line;
    //   - idle      → both prompts, so the user can pick a direction.
    let dialing = snap.dial_target.is_some();

    // Listen side: the node id (once up) or the Shift+L prompt (idle). A dialer doesn't
    // care about listening, so this is hidden while a dial session exists.
    if snap.listening {
        // Truncated to the same short form as the inbound-peer line — the full
        // 64-char id is visual noise (and not needed to pair in any mode).
        let mut node_line = vec![Span::raw("node id: "), Span::raw(short_id(endpoint))];
        // Shift+D resets the serve half to idle (releasing the pairing claim so a new peer can
        // pair, or the run can switch to dialing). Home-only, like the dial controls.
        if show_dial_hint {
            node_line.push(listen_reset_hint());
        }
        lines.push(Line::from(node_line));
    } else if !dialing {
        lines.push(Line::from(Span::styled(
            "not listening — press Shift+L to start",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }
    // Who the serve half is paired with (or waiting/reserved) — shown only while listening.
    if let Some(inbound) = inbound_status_line(snap) {
        lines.push(inbound);
    }
    // Dial side: the outbound status (once dialing) or the Shift+C prompt (idle). A listener
    // doesn't care about outbound, so this is hidden while listening.
    if dialing || !snap.listening {
        lines.push(dial_header_line(snap, show_dial_hint));
    }

    if banners.show_token {
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
        let hint = match banners.hide_at {
            Some(at) => format!("auto-hides at {at} · press h to hide/show"),
            None => "press h to hide/show".to_string(),
        };
        lines.push(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        )));
    }

    if banners.show_pin {
        // Quick PIN mode: the rotating code the other device types to connect. It carries
        // this peer's node id + token, so no copy-paste is needed. When hidden, the label
        // and hide/show hint stay sticky (the value and its timers/fp are masked) so the
        // user still sees a PIN exists and how to bring it back.
        if banners.pin_hidden {
            lines.push(Line::from(vec![
                Span::raw("dial PIN: "),
                Span::styled("(hidden)", Style::default().fg(Color::DarkGray)),
            ]));
            lines.push(Line::from(Span::styled(
                "press h to hide/show",
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            let pin = snap.current_pin.as_deref().unwrap_or("");
            // No fp here: the PIN's token is always auto-generated and carried by the PIN
            // itself, so the fingerprint is redundant noise (matching the status line).
            let pin_line = vec![
                Span::raw("dial PIN: "),
                Span::styled(
                    crate::pin::format_pin(pin),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ];
            lines.push(Line::from(pin_line));

            // Two timers: a live 60s refresh countdown (the PIN itself rotates) and the
            // absolute auto-hide time (shown as a clock time, not a countdown, to avoid
            // confusion with the refresh).
            let refresh = snap
                .pin_deadline
                .map(|d| d.saturating_duration_since(Instant::now()).as_secs())
                .unwrap_or(0);
            let hint = match banners.hide_at {
                Some(at) => format!("refreshes in {refresh:>2}s · auto-hides at {at} · press h to hide/show"),
                None => format!("refreshes in {refresh:>2}s · press h to hide/show"),
            };
            lines.push(Line::from(Span::styled(
                hint,
                Style::default().fg(Color::DarkGray),
            )));
        }
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
        "config"
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

/// The serve-half reset hint (Shift-D), styled like [`dial_hint`]. Shown on the node-id line
/// while listening so the same key resets either side back to idle — including recovering a
/// listener whose paired peer has disconnected (the claim is retained until reset).
fn listen_reset_hint() -> Span<'static> {
    Span::styled(
        "   [Shift-D reset]",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )
}

/// `show_hint` is false on the logs screen, where the Shift-C/Shift-D dial controls
/// are inert — the status still shows, just without the dead action hint.
fn dial_header_line(snap: &AppSnapshot, show_hint: bool) -> Line<'static> {
    let Some(target) = snap.dial_target.as_deref() else {
        let mut spans = vec![Span::raw(dial_text(snap))];
        // One-pairing rule: dialing is unavailable while listening, so hide the
        // connect hint in that state (Shift+C is refused by the runtime too).
        if show_hint && !snap.listening {
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

/// Modal for setting the local SOCKS5 proxy port at runtime. One text field
/// rendered as a standard bordered input box; it owns the terminal cursor.
pub fn render_add_tunnel_dialog(frame: &mut Frame, form: &SocksForm) {
    let error_rows = if form.error.is_some() { 2 } else { 0 };
    let area = centered(
        frame.area(),
        84,
        2 + 2 + INPUT_FIELD_HEIGHT + 1 + 2 + error_rows + 1,
    );
    frame.render_widget(Clear, area);
    let panel = Block::default()
        .borders(Borders::ALL)
        .title(" set SOCKS5 port ");
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
                "Set SOCKS5 proxy port",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
        ],
    );
    i += 1;
    render_input_field(frame, chunks[i], "Local port", &form.port, true);
    i += 1;
    i += 1; // spacer before hint
    render_modal_line(
        frame,
        chunks[i],
        Line::from(Span::styled(
            "binds 127.0.0.1/::1 · Enter set (s to start) · Esc cancel",
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
    let header = Row::new(["", "PROXY", "STATUS", "DETAIL"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = match &snap.socks {
        None => vec![Row::new(["", "(no SOCKS5 port set — press e)", "", ""])],
        Some(s) => vec![socks_row(s)],
    };
    let widths = [
        Constraint::Length(3),
        Constraint::Percentage(55),
        Constraint::Length(10),
        Constraint::Percentage(30),
    ];
    let title = socks_title(snap);
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

/// The SOCKS proxy is symmetric: either side can bind it once paired. Show the
/// start/stop hints when there is a live authenticated connection (inbound peer or
/// outbound dial); before that the proxy has no session to tunnel through.
fn socks_title(snap: &AppSnapshot) -> &'static str {
    if has_live_pairing(snap) {
        " SOCKS5 Proxy  [s start · x stop · e set · d clear] "
    } else {
        " SOCKS5 Proxy  [e set · d clear — pair first] "
    }
}

/// Whether a live authenticated connection exists in either direction (so the local
/// SOCKS proxy would have a session to tunnel through).
fn has_live_pairing(snap: &AppSnapshot) -> bool {
    let dial_up = snap.dial_target.is_some() && snap.conn_status == ConnStatus::Connected;
    let inbound_up = snap.inbound.as_ref().is_some_and(|p| p.connected());
    dial_up || inbound_up
}

fn socks_row(s: &SocksRow) -> Row<'static> {
    let marker = if s.status.is_running() { "▶" } else { " " };
    // Show the bound address (from detail) while running, else the configured port.
    let spec = if s.detail.is_empty() {
        format!("socks5 127.0.0.1:{}", s.port)
    } else {
        format!("socks5 {}", s.detail)
    };
    Row::new(vec![
        Cell::from(format!(" {marker}")),
        Cell::from(spec),
        Cell::from(Span::styled(
            s.status.label(),
            Style::default().fg(socks_color(s.status)),
        )),
        Cell::from(s.detail.clone()),
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

fn socks_color(status: SocksStatus) -> Color {
    match status {
        SocksStatus::Listening => Color::Green,
        SocksStatus::Idle => Color::DarkGray,
        SocksStatus::Error => Color::Red,
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
    use crate::app_state::{InboundPeer, PathInfo};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn base_snapshot(nostr_discovery: bool, own_name: Option<&str>) -> AppSnapshot {
        AppSnapshot {
            role: Role::Both,
            hostname: "test-host".to_string(),
            // Most existing assertions expect the node id / banners to render, which now
            // requires the serve half to be up.
            listening: true,
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
            inbound: None,
            socks: None,
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
        let full_id = "f06c35c4091d1a83532599547815186b25ecb75c9edcd53c4359d64cf880e4f7";
        snap.endpoint_id = Some(full_id.to_string());

        let out = render_text(&snap, &UiState::default());
        assert!(out.contains("dial PIN"), "PIN banner shown");
        assert!(out.contains("K7P2-9QXM"), "PIN is grouped for display");
        assert!(out.contains("refreshes in"), "countdown shown");
        // The raw auth-token banner must not appear in PIN mode.
        assert!(!out.contains("auth token:"), "token banner suppressed in PIN mode");
        // The token fp is redundant noise in PIN mode (the PIN carries the token) — dropped
        // both on the status line and from the PIN banner itself.
        assert!(!out.contains("token fp:"), "token fp dropped in PIN mode");
        assert!(!out.contains("(fp:"), "no fp alongside the PIN");
        // The node id is truncated, not the full 64-char hash.
        assert!(out.contains("node id: f06c35c4091"), "node id shown truncated");
        assert!(!out.contains(full_id), "full node id not shown");
    }

    #[test]
    fn config_token_listening_keeps_token_fp() {
        // A config-supplied token (not auto-generated) keeps the fp so the user can
        // cross-check that both devices share the same token.
        let mut snap = base_snapshot(false, None); // listening = true, token_generated = false
        snap.auth_token = Some(crate::auth::generate_token());

        let out = render_text(&snap, &UiState::default());
        assert!(out.contains("token fp:"), "token fp shown for a config token");
    }

    #[test]
    fn generated_token_listening_hides_token_fp() {
        // An auto-generated token is shared automatically and identical across devices, so
        // its fp is noise — dropped even outside PIN mode (quick manual mode).
        let mut snap = base_snapshot(false, None); // listening = true, pin_mode = false
        snap.token_generated = true;
        snap.auth_token = Some(crate::auth::generate_token());

        let out = render_text(&snap, &UiState::default());
        assert!(!out.contains("token fp:"), "token fp dropped for a generated token");
    }

    #[test]
    fn pin_banner_sticky_when_hidden() {
        // Hiding the PIN (via `h` or auto-hide) keeps the label and hide/show hint on
        // screen while masking the value and its timers/fingerprint.
        let mut snap = base_snapshot(false, None); // listening = true
        snap.pin_mode = true;
        snap.token_generated = true;
        snap.auth_token = Some(crate::auth::generate_token());
        snap.current_pin = Some("K7P29QXM".to_string());
        snap.pin_deadline = Some(Instant::now() + std::time::Duration::from_secs(41));

        let ui = UiState {
            token_banner_hidden: true,
            ..Default::default()
        };
        let out = render_text(&snap, &ui);
        assert!(out.contains("dial PIN:"), "label stays sticky when hidden");
        assert!(out.contains("(hidden)"), "value is masked");
        assert!(out.contains("press h to hide/show"), "hint stays sticky when hidden");
        // The secret value and its timers must not leak while hidden — neither the
        // grouped display form nor the raw unformatted PIN.
        assert!(!out.contains("K7P2-9QXM"), "grouped PIN value hidden");
        assert!(!out.contains("K7P29QXM"), "raw PIN value hidden");
        assert!(!out.contains("refreshes in"), "refresh countdown hidden");
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
    fn config_idle_dashboard_shows_mode_name_and_idle_dial() {
        // Not listening: the one-pairing rule allows dialing, so the connect hint shows.
        let mut snap = base_snapshot(true, Some("web1"));
        snap.listening = false;

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("mode: config"));
        assert!(text.contains("name: web1"));
        assert!(text.contains("Outbound: not connected"));
        // The connect control hint lives on the dial header line, not the Proxy box.
        assert!(text.contains("Shift-C connect"));
    }

    #[test]
    fn connect_hint_hidden_while_listening() {
        // One-pairing rule: a listening node cannot dial, so the Shift-C hint is hidden.
        let snap = base_snapshot(true, Some("web1")); // listening = true
        let text = render_text(&snap, &UiState::default());
        assert!(!text.contains("Shift-C connect"));
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

        // Logs screen: the log pane is present, the tunnels table is not (the header — including
        // the inline inbound-peer line — is shared by both screens).
        let logs_ui = UiState {
            screen: Screen::Logs,
            ..Default::default()
        };
        let logs = render_text(&snap, &logs_ui);
        assert!(logs.contains("Logs ("));
        assert!(!logs.contains("SPEC"));
    }

    #[test]
    fn header_shows_paired_peer_then_reservation() {
        let mut snap = base_snapshot(false, None);

        // Listening but unpaired: the header invites a peer.
        assert!(
            render_text(&snap, &UiState::default()).contains("waiting for a peer"),
            "unpaired header must show it is waiting"
        );

        let id = "abcdef0123456789abcdef";
        // Paired and connected: the short id shows on the inbound line.
        snap.inbound = Some(InboundPeer {
            remote_id: id.to_string(),
            active_conns: 1,
            connected_since: Instant::now(),
            path: PathInfo::establishing(),
        });
        let home = render_text(&snap, &UiState::default());
        assert!(home.contains("inbound"), "connected header must show inbound");
        assert!(home.contains(&short_id(id)), "must show the paired peer's short id");

        // Disconnected: the endpoint stays reserved for that peer.
        snap.inbound = Some(InboundPeer {
            remote_id: id.to_string(),
            active_conns: 0,
            connected_since: Instant::now(),
            path: PathInfo::establishing(),
        });
        assert!(
            render_text(&snap, &UiState::default()).contains("reserved for"),
            "disconnected header must show the reservation"
        );

        // Not listening: no inbound line at all.
        snap.listening = false;
        let idle = render_text(&snap, &UiState::default());
        assert!(!idle.contains("reserved for") && !idle.contains("waiting for a peer"));
    }

    #[test]
    fn dial_hint_shows_on_home_but_not_on_logs_screen() {
        // Not listening: dialing is allowed, so the connect hint can appear on home.
        let mut snap = base_snapshot(true, Some("web1"));
        snap.listening = false;

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
    fn non_listening_dashboard_prompts_for_shift_l_and_hides_node_id_and_secrets() {
        // The serve half is started on-demand: until then the header points the user at
        // Shift+L instead of a node id, and no secret (token banner / PIN) is surfaced.
        let mut snap = base_snapshot(false, None);
        snap.listening = false;
        // A generated token *and* a rotating PIN exist, but neither must show pre-listen.
        snap.token_generated = true;
        snap.pin_mode = true;
        snap.auth_token = Some("generated-secret-token".to_string());
        snap.current_pin = Some("K7P29QXM".to_string());
        snap.pin_deadline = Some(Instant::now() + std::time::Duration::from_secs(41));
        snap.endpoint_id = Some("node-123".to_string());

        let text = render_text(&snap, &UiState::default());

        // Node-id row replaced by the call-to-action; the id itself stays hidden.
        assert!(text.contains("not listening — press Shift+L to start"));
        assert!(!text.contains("node id:"));
        assert!(!text.contains("node-123"));
        // Both secret banners are suppressed while not listening.
        assert!(!text.contains("auth token:"), "token banner suppressed pre-listen");
        assert!(!text.contains("generated-secret-token"));
        assert!(!text.contains("dial PIN"), "PIN banner suppressed pre-listen");
        // The token fingerprint line is gated too (nothing to pair with yet).
        assert!(!text.contains("token fp:"));
        // Footer offers to start listening and drops the show/hide-secret hint.
        assert!(text.contains("Shift+L start listening"));
        assert!(!text.contains("h show/hide"));
    }

    #[test]
    fn listening_dashboard_shows_node_id_and_stop_hint() {
        // The flip side of the idle state: once listening, the node id renders and the
        // footer offers to stop and to show/hide the secret.
        let snap = base_snapshot(false, None); // base_snapshot is listening = true

        let text = render_text(&snap, &UiState::default());

        assert!(text.contains("node id: node-123"));
        assert!(!text.contains("not listening — press Shift+L to start"));
        assert!(text.contains("Shift+L stop listening"));
        assert!(text.contains("h show/hide"));
    }

    #[test]
    fn dialer_header_hides_the_listen_line() {
        // A dialing run only cares about outbound: no "not listening" prompt.
        let mut snap = base_snapshot(false, None);
        snap.listening = false;
        snap.dial_target = Some("peer".to_string());
        snap.conn_status = ConnStatus::Connected;
        let text = render_text(&snap, &UiState::default());
        assert!(text.contains("Outbound → peer"));
        assert!(!text.contains("not listening — press Shift+L to start"));
    }

    #[test]
    fn listener_header_hides_the_outbound_line() {
        // A listening run only cares about inbound: no "Outbound" line.
        let snap = base_snapshot(false, None); // listening = true, no dial session
        let text = render_text(&snap, &UiState::default());
        assert!(text.contains("node id:"));
        assert!(!text.contains("Outbound"));
    }

    #[test]
    fn idle_header_shows_both_direction_prompts() {
        // Idle (neither): both prompts appear so the user can pick a direction.
        let mut snap = base_snapshot(false, None);
        snap.listening = false;
        let text = render_text(&snap, &UiState::default());
        assert!(text.contains("not listening — press Shift+L to start"));
        assert!(text.contains("Outbound: not connected"));
    }

    #[test]
    fn socks_title_matches_pairing_state() {
        // No live pairing: the Proxy box shows only set/clear and a "pair first" note.
        let mut snap = base_snapshot(false, None);
        snap.listening = false;
        let idle_text = render_text(&snap, &UiState::default());
        assert!(!idle_text.contains("s start"));
        assert!(idle_text.contains("pair first"));

        // A live outbound session enables start/stop of the local proxy.
        let mut connected = base_snapshot(false, None);
        connected.listening = false;
        connected.dial_target = Some("peer".to_string());
        connected.conn_status = ConnStatus::Connected;
        let connected_text = render_text(&connected, &UiState::default());
        assert!(connected_text.contains("s start"));
    }
}
