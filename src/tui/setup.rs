//! Interactive in-TUI setup: collect the serving allowlist and confirm token
//! generation before the runtime starts.
//!
//! There is no role question: every interactive run is always listening, and the
//! single outbound dial session is started on demand from the dashboard (see
//! `super::handle_key`). Setup therefore only resolves the serving `[allowed_sources]`
//! (when config supplies none) and the auth token (supplied, or freshly generated).
//!
//! Pure state machine ([`SetupState`] + [`handle_key`]) plus a pure [`render`]. The
//! driver lives in [`super::run_setup`]. Validation (CRC16 on a supplied token, CIDR
//! parse on the allowlist) happens here.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tui_input::Input;

use super::textinput::{handle_edit, render_spans};
use crate::app_state::Role;
use crate::auth;
use crate::config::{AllowedSources, validate_cidr};
use crate::peer_params::ResolvedPeer;

/// Which question the setup screen is currently asking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SetupPhase {
    /// Start screen: a summary plus — when config supplies no `[allowed_sources]` — the
    /// TCP/UDP CIDR allowlists gating what inbound peers may request. Enter proceeds.
    Start,
    /// When no token came from config/env: confirm a fresh one will be generated for
    /// this run before generating it.
    ConfirmGenerateToken,
}

/// Which CIDR field of the [`SetupPhase::Start`] screen has focus. Only relevant when
/// config supplies no `[allowed_sources]` (otherwise there are no editable fields).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StartSection {
    AllowedTcp,
    AllowedUdp,
}

/// Result of running the setup screen to completion.
pub enum SetupOutcome {
    Resolved(ResolvedPeer),
    Quit,
}

/// Internal result of handling one key press.
pub enum Step {
    Continue,
    Done(ResolvedPeer),
    Quit,
}

/// Mutable state of the setup screen.
pub struct SetupState {
    phase: SetupPhase,
    /// A valid auth token already supplied by config/env (pre-validated in main).
    config_auth_token: Option<String>,
    /// Allowlist supplied by config. When non-empty the interactive allowlist fields
    /// are hidden (config wins); when empty they are shown on the start screen.
    config_allowed_sources: AllowedSources,
    /// Focused CIDR field (only used when the allowlist fields are shown).
    section: StartSection,
    /// TCP/UDP CIDR text entered on the start screen (only used when
    /// `config_allowed_sources` is empty).
    allowed_tcp: Input,
    allowed_udp: Input,
    /// Allowlist resolved once the start screen is submitted, carried to `Done`.
    allowed_sources: AllowedSources,
    /// Whether nostr discovery is active (nostr mode) — display only, for the summary.
    nostr_discovery: bool,
    /// This machine's own nostr name (config `name`) — display only, for the summary.
    own_name: Option<String>,
    /// Resolved credential, carried to `Done`.
    auth_token: Option<String>,
    token_generated: bool,
    /// Inline error from the last failed validation; cleared on the next keypress.
    error: Option<String>,
}

impl SetupState {
    pub fn new(
        config_auth_token: Option<String>,
        config_allowed_sources: AllowedSources,
        nostr_discovery: bool,
        own_name: Option<String>,
    ) -> Self {
        Self {
            phase: SetupPhase::Start,
            config_auth_token,
            config_allowed_sources,
            section: StartSection::AllowedTcp,
            allowed_tcp: Input::default(),
            allowed_udp: Input::default(),
            allowed_sources: AllowedSources::default(),
            nostr_discovery,
            own_name,
            auth_token: None,
            token_generated: false,
            error: None,
        }
    }
}

/// Resolve the credential (config/env token or a freshly generated one) and finish.
fn finalize(state: &mut SetupState) -> Step {
    let (auth_token, token_generated) = match state.config_auth_token.clone() {
        Some(token) => (token, false),
        None => (auth::generate_token(), true),
    };
    state.auth_token = Some(auth_token);
    state.token_generated = token_generated;
    Step::Done(build_resolved(state))
}

/// Build the final `ResolvedPeer`. Interactive runs are always `Role::Both` (serve
/// always + dial on demand); the dial target is supplied at runtime, not here.
fn build_resolved(state: &SetupState) -> ResolvedPeer {
    ResolvedPeer {
        role: Role::Both,
        peer_node_id: None,
        peer_identifier: None,
        auth_token: state.auth_token.clone().unwrap_or_default(),
        token_generated: state.token_generated,
        allowed_sources: state.allowed_sources.clone(),
    }
}

/// Whether the interactive allowlist fields are shown (config supplies none).
fn allowlist_fields_shown(state: &SetupState) -> bool {
    state.config_allowed_sources.is_empty()
}

/// Submit the start screen: resolve the allowlist (from config or the entered CIDRs),
/// then finish (a token is present) or confirm token generation. A bad CIDR keeps the
/// screen open with an error.
fn submit_start(state: &mut SetupState) -> Step {
    let allowed = if !allowlist_fields_shown(state) {
        state.config_allowed_sources.clone()
    } else {
        let tcp = match parse_cidr_list(state.allowed_tcp.value()) {
            Ok(list) => list,
            Err(e) => {
                state.section = StartSection::AllowedTcp;
                state.error = Some(format!("Invalid TCP CIDR: {e}"));
                return Step::Continue;
            }
        };
        let udp = match parse_cidr_list(state.allowed_udp.value()) {
            Ok(list) => list,
            Err(e) => {
                state.section = StartSection::AllowedUdp;
                state.error = Some(format!("Invalid UDP CIDR: {e}"));
                return Step::Continue;
            }
        };
        AllowedSources { tcp, udp }
    };
    state.allowed_sources = allowed;

    if state.config_auth_token.is_some() {
        // A config/env token is used as-is, no confirmation.
        finalize(state)
    } else {
        // No token: confirm before generating a fresh one.
        state.phase = SetupPhase::ConfirmGenerateToken;
        Step::Continue
    }
}

/// Parse a line of space/comma-separated CIDRs, validating each. Empty input yields an
/// empty list; `run_peer` later applies the localhost default.
fn parse_cidr_list(buffer: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for tok in buffer.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
        validate_cidr(tok).map_err(|e| e.to_string())?;
        out.push(tok.to_string());
    }
    Ok(out)
}

/// Handle a key press, advancing the state machine.
pub fn handle_key(key: KeyEvent, state: &mut SetupState) -> Step {
    // Ctrl-C quits from any phase.
    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl_c {
        return Step::Quit;
    }
    // Any keypress clears a stale error message.
    state.error = None;

    match state.phase {
        SetupPhase::Start => match key.code {
            KeyCode::Esc => Step::Quit,
            KeyCode::Enter => submit_start(state),
            KeyCode::Tab => {
                // Toggle between the two CIDR fields, but only when they exist.
                if allowlist_fields_shown(state) {
                    state.section = match state.section {
                        StartSection::AllowedTcp => StartSection::AllowedUdp,
                        StartSection::AllowedUdp => StartSection::AllowedTcp,
                    };
                }
                Step::Continue
            }
            _ => {
                if allowlist_fields_shown(state) {
                    match state.section {
                        StartSection::AllowedTcp => {
                            handle_edit(&mut state.allowed_tcp, key, is_cidr_char)
                        }
                        StartSection::AllowedUdp => {
                            handle_edit(&mut state.allowed_udp, key, is_cidr_char)
                        }
                    }
                }
                Step::Continue
            }
        },
        SetupPhase::ConfirmGenerateToken => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => finalize(state),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                state.phase = SetupPhase::Start;
                Step::Continue
            }
            _ => Step::Continue,
        },
    }
}

/// CIDR entry accepts printable ASCII plus spaces/commas as separators between entries.
fn is_cidr_char(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
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

/// Render the setup screen.
pub fn render(frame: &mut Frame, state: &SetupState) {
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            concat!("duopipe v", env!("CARGO_PKG_VERSION"), " — setup"),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
    ];

    match state.phase {
        SetupPhase::Start => {
            lines.push(Line::from("This instance will always listen for peers."));
            if state.nostr_discovery
                && let Some(name) = &state.own_name
            {
                lines.push(Line::from(Span::styled(
                    format!("  Reachable via nostr as \"{name}\"."),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            lines.push(Line::from(Span::styled(
                "  Dial a peer on demand from the dashboard (press Shift-C).",
                Style::default().fg(Color::DarkGray),
            )));
            if allowlist_fields_shown(state) {
                lines.push(Line::raw(""));
                lines.push(Line::from(
                    "Allowed TCP sources the peer may request (CIDR):",
                ));
                lines.push(field_input_line(
                    &state.allowed_tcp,
                    state.section == StartSection::AllowedTcp,
                ));
                lines.push(Line::from(Span::styled(
                    "  space/comma-separated, e.g. 192.168.0.0/16 — blank = localhost (127.0.0.0/8 ::1/128)",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(
                    "Allowed UDP sources the peer may request (CIDR):",
                ));
                lines.push(field_input_line(
                    &state.allowed_udp,
                    state.section == StartSection::AllowedUdp,
                ));
                lines.push(Line::from(Span::styled(
                    "  space/comma-separated, e.g. 10.0.0.0/8 — blank = localhost (127.0.0.0/8 ::1/128)",
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        SetupPhase::ConfirmGenerateToken => {
            lines.push(Line::from("No auth token configured."));
            lines.push(Line::from(Span::styled(
                "  A fresh token will be generated for this session (changes every run).",
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from("Proceed? (Y/n)"));
        }
    }

    if let Some(err) = &state.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    lines.push(Line::raw(""));
    let footer = match state.phase {
        SetupPhase::Start => {
            if allowlist_fields_shown(state) {
                "Tab next field · Enter start · Esc / Ctrl-C quit"
            } else {
                "Enter start · Esc / Ctrl-C quit"
            }
        }
        SetupPhase::ConfirmGenerateToken => "Esc back · Ctrl-C quit",
    };
    lines.push(Line::from(Span::styled(
        footer,
        Style::default().fg(Color::DarkGray),
    )));

    let height = lines.len() as u16 + 2;
    let area = centered(frame.area(), 76, height.min(frame.area().height));
    let para = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" setup "))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// A text-input line. When `active`, a block cursor marks the edit position; otherwise
/// the value is shown plainly.
fn field_input_line(buffer: &Input, active: bool) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    let style = Style::default().fg(Color::Cyan);
    if active {
        spans.extend(render_spans(buffer, style));
    } else {
        spans.push(Span::styled(buffer.value().to_string(), style));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_str(state: &mut SetupState, s: &str) {
        for c in s.chars() {
            handle_key(key(KeyCode::Char(c)), state);
        }
    }

    /// A non-empty config allowlist so the start screen shows no editable fields.
    fn from_config() -> AllowedSources {
        AllowedSources {
            tcp: vec!["127.0.0.0/8".into()],
            udp: vec![],
        }
    }

    #[test]
    fn start_with_config_token_finishes_as_both() {
        let token = auth::generate_token();
        let mut s = SetupState::new(Some(token.clone()), from_config(), true, Some("hl".into()));
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert!(r.peer_node_id.is_none());
                assert!(r.peer_identifier.is_none());
                assert!(!r.token_generated);
                assert_eq!(r.auth_token, token);
                assert_eq!(r.allowed_sources.tcp, vec!["127.0.0.0/8".to_string()]);
            }
            _ => panic!("expected Done(Both)"),
        }
    }

    #[test]
    fn start_without_token_confirms_then_generates() {
        let mut s = SetupState::new(None, from_config(), false, None);
        // Without a config token, the start screen first asks for confirmation.
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::ConfirmGenerateToken);
        match handle_key(key(KeyCode::Char('y')), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert!(r.token_generated);
                assert!(auth::validate_token(&r.auth_token).is_ok());
            }
            _ => panic!("expected Done(Both)"),
        }
    }

    #[test]
    fn confirm_decline_returns_to_start() {
        let mut s = SetupState::new(None, from_config(), false, None);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::ConfirmGenerateToken);
        assert!(matches!(
            handle_key(key(KeyCode::Char('n')), &mut s),
            Step::Continue
        ));
        assert_eq!(s.phase, SetupPhase::Start);
    }

    #[test]
    fn start_screen_collects_tcp_then_udp_allowlist() {
        // Empty config allowlist -> the two CIDR fields appear; TCP is focused first.
        let mut s = SetupState::new(
            Some(auth::generate_token()),
            AllowedSources::default(),
            false,
            None,
        );
        type_str(&mut s, "127.0.0.0/8 192.168.0.0/16");
        handle_key(key(KeyCode::Tab), &mut s); // -> AllowedUdp
        type_str(&mut s, "10.0.0.0/8");
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert_eq!(
                    r.allowed_sources.tcp,
                    vec!["127.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
                );
                assert_eq!(r.allowed_sources.udp, vec!["10.0.0.0/8".to_string()]);
            }
            _ => panic!("expected Done(Both) with the entered allowlist"),
        }
    }

    #[test]
    fn bad_cidr_keeps_screen_open_with_error() {
        let mut s = SetupState::new(
            Some(auth::generate_token()),
            AllowedSources::default(),
            false,
            None,
        );
        type_str(&mut s, "not-a-cidr");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
        assert_eq!(s.phase, SetupPhase::Start);
    }

    #[test]
    fn allowlist_field_supports_cursor_editing() {
        let mut s = SetupState::new(
            Some(auth::generate_token()),
            AllowedSources::default(),
            false,
            None,
        );
        type_str(&mut s, "abcd");
        handle_key(key(KeyCode::Left), &mut s);
        handle_key(key(KeyCode::Left), &mut s);
        type_str(&mut s, "XY");
        assert_eq!(s.allowed_tcp.value(), "abXYcd");
    }

    #[test]
    fn ctrl_c_quits() {
        let mut s = SetupState::new(None, from_config(), false, None);
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(k, &mut s), Step::Quit));
    }
}
