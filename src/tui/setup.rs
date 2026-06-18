//! Interactive in-TUI setup: collect role, allowlist, target node id, and auth
//! token before the runtime starts.
//!
//! Pure state machine ([`SetupState`] + [`handle_key`]) plus a pure [`render`].
//! The driver lives in [`super::run_setup`]. Validation (CRC16 on the auth token,
//! `EndpointId` parse on the node id, CIDR parse on the allowlist) happens here, so
//! the dialer never attempts a connection with bad inputs.

use iroh::EndpointId;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use tui_input::Input;

use super::textinput::{handle_edit, render_spans};
use crate::app_state::Role;
use crate::auth;
use crate::config::{validate_cidr, AllowedSources};
use crate::peer_params::ResolvedPeer;

/// The two roles offered on the start screen, in display order. Index 0 (listen)
/// is the default highlight.
const CONNECT_OPTIONS: [&str; 2] = [
    "Start a new instance (listen for a connection)",
    "Connect to an existing instance (dial)",
];
/// Index of the "dial" option within [`CONNECT_OPTIONS`].
const CONNECT_DIAL: usize = 1;

/// Which question the setup screen is currently asking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SetupPhase {
    /// Combined start screen: pick the role and — when config supplies no
    /// `[allowed_sources]` — enter the TCP/UDP CIDR allowlists. The allowlist
    /// applies to either role, so it is collected here up front.
    Start,
    /// Listen only, when no config token: confirm a fresh token will be
    /// generated for this run before generating it.
    ConfirmGenerateToken,
    /// Dial only: the existing instance's node id.
    NodeId,
    /// Dial only: the auth token (skipped when one came from config/env).
    AuthToken,
}

/// Which part of the [`SetupPhase::Start`] screen currently has focus. The
/// allowlist sections only exist when config supplies no `[allowed_sources]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StartSection {
    Role,
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
    /// Used directly for Listen, and skips the token prompt for Dial.
    config_auth_token: Option<String>,
    /// Allowlist supplied by config. When non-empty the interactive allowlist
    /// fields are hidden (config wins); when empty they are shown on the start
    /// screen.
    config_allowed_sources: AllowedSources,
    /// Highlighted option in the start screen's role list.
    connect_choice: usize,
    /// Focused section of the start screen.
    section: StartSection,
    /// TCP/UDP CIDR text entered on the start screen (only used when
    /// `config_allowed_sources` is empty).
    allowed_tcp: Input,
    allowed_udp: Input,
    /// Allowlist resolved once the start screen is submitted, carried to `Done`.
    allowed_sources: AllowedSources,
    node_id: Option<EndpointId>,
    /// Resolved credential, carried to `Done`.
    auth_token: Option<String>,
    token_generated: bool,
    /// Current text field contents (node id / token).
    buffer: Input,
    /// Inline error from the last failed validation; cleared on the next keypress.
    error: Option<String>,
}

impl SetupState {
    pub fn new(config_auth_token: Option<String>, config_allowed_sources: AllowedSources) -> Self {
        Self {
            phase: SetupPhase::Start,
            config_auth_token,
            config_allowed_sources,
            connect_choice: 0,
            section: StartSection::Role,
            allowed_tcp: Input::default(),
            allowed_udp: Input::default(),
            allowed_sources: AllowedSources::default(),
            node_id: None,
            auth_token: None,
            token_generated: false,
            buffer: Input::default(),
            error: None,
        }
    }
}

/// Resolve the Listen credential (config/env token or a fresh one) and finish.
fn finalize_listen(state: &mut SetupState) -> Step {
    let (auth_token, token_generated) = match state.config_auth_token.clone() {
        Some(token) => (token, false),
        None => (auth::generate_token(), true),
    };
    state.auth_token = Some(auth_token);
    state.token_generated = token_generated;
    state.node_id = None;
    Step::Done(build_resolved(state))
}

/// Build the final `ResolvedPeer` from accumulated state.
fn build_resolved(state: &SetupState) -> ResolvedPeer {
    let role = if state.node_id.is_some() {
        Role::Dial
    } else {
        Role::Listen
    };
    ResolvedPeer {
        role,
        peer_node_id: state.node_id,
        auth_token: state.auth_token.clone().unwrap_or_default(),
        token_generated: state.token_generated,
        allowed_sources: state.allowed_sources.clone(),
    }
}

/// Whether the interactive allowlist fields are shown (config supplies none).
fn allowlist_fields_shown(state: &SetupState) -> bool {
    state.config_allowed_sources.is_empty()
}

/// Submit the start screen: resolve the allowlist (from config or the entered
/// CIDRs), then advance by role. A bad CIDR keeps the screen open with an error.
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

    if state.connect_choice == CONNECT_DIAL {
        state.phase = SetupPhase::NodeId;
        state.buffer.reset();
        Step::Continue
    } else if state.config_auth_token.is_some() {
        // Listen with a config/env token: used as-is, no confirmation.
        finalize_listen(state)
    } else {
        // Listen without a token: confirm before generating a fresh one.
        state.phase = SetupPhase::ConfirmGenerateToken;
        state.buffer.reset();
        Step::Continue
    }
}

/// Parse a line of space/comma-separated CIDRs, validating each. Empty input is an
/// empty list (fail-closed for that protocol).
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
                // Cycle Role -> TCP -> UDP -> Role, but only when the allowlist
                // fields exist.
                if allowlist_fields_shown(state) {
                    state.section = match state.section {
                        StartSection::Role => StartSection::AllowedTcp,
                        StartSection::AllowedTcp => StartSection::AllowedUdp,
                        StartSection::AllowedUdp => StartSection::Role,
                    };
                }
                Step::Continue
            }
            _ => match state.section {
                StartSection::Role => match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        state.connect_choice = state.connect_choice.saturating_sub(1);
                        Step::Continue
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        state.connect_choice =
                            (state.connect_choice + 1).min(CONNECT_OPTIONS.len() - 1);
                        Step::Continue
                    }
                    _ => Step::Continue,
                },
                StartSection::AllowedTcp => {
                    handle_edit(&mut state.allowed_tcp, key, is_cidr_char);
                    Step::Continue
                }
                StartSection::AllowedUdp => {
                    handle_edit(&mut state.allowed_udp, key, is_cidr_char);
                    Step::Continue
                }
            },
        },
        SetupPhase::ConfirmGenerateToken => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => finalize_listen(state),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                state.phase = SetupPhase::Start;
                state.buffer.reset();
                Step::Continue
            }
            _ => Step::Continue,
        },
        SetupPhase::NodeId => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::Start;
                state.buffer.reset();
                Step::Continue
            }
            KeyCode::Enter => match state.buffer.value().trim().parse::<EndpointId>() {
                Ok(id) => {
                    state.node_id = Some(id);
                    match state.config_auth_token.clone() {
                        Some(token) => {
                            state.auth_token = Some(token);
                            state.token_generated = false;
                            Step::Done(build_resolved(state))
                        }
                        None => {
                            state.phase = SetupPhase::AuthToken;
                            state.buffer.reset();
                            Step::Continue
                        }
                    }
                }
                Err(_) => {
                    state.error = Some("Invalid node id".to_string());
                    Step::Continue
                }
            },
            _ => {
                handle_edit(&mut state.buffer, key, is_input_char);
                Step::Continue
            }
        },
        SetupPhase::AuthToken => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::NodeId;
                state.buffer.reset();
                Step::Continue
            }
            KeyCode::Enter => {
                let token = state.buffer.value().trim().to_string();
                match auth::validate_token(&token) {
                    Ok(()) => {
                        state.auth_token = Some(token);
                        state.token_generated = false;
                        Step::Done(build_resolved(state))
                    }
                    Err(e) => {
                        state.error = Some(format!("Invalid auth token: {e}"));
                        Step::Continue
                    }
                }
            }
            _ => {
                handle_edit(&mut state.buffer, key, is_input_char);
                Step::Continue
            }
        },
    }
}

/// Accept printable ASCII (node ids and tokens are ASCII; no spaces).
fn is_input_char(c: char) -> bool {
    c.is_ascii_graphic()
}

/// CIDR entry additionally accepts spaces/commas as separators between entries.
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
            "duopipe — setup",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
    ];

    match state.phase {
        SetupPhase::Start => {
            lines.push(Line::from("How do you want to start?"));
            lines.push(Line::raw(""));
            for (i, label) in CONNECT_OPTIONS.iter().enumerate() {
                if i == state.connect_choice {
                    lines.push(Line::from(Span::styled(
                        format!("  ▶ {label}"),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )));
                } else {
                    lines.push(Line::from(format!("    {label}")));
                }
            }
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
                    "  space/comma-separated, e.g. 10.0.0.0/8 — blank = none (rejects all)",
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
        SetupPhase::NodeId => {
            lines.push(Line::from("Existing instance node id:"));
            lines.push(field_input_line(&state.buffer, true));
        }
        SetupPhase::AuthToken => {
            lines.push(Line::from("Auth token:"));
            lines.push(field_input_line(&state.buffer, true));
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
                match state.section {
                    StartSection::Role => {
                        "↑/↓ choose role · Tab next field · Enter continue · Esc / Ctrl-C quit"
                    }
                    StartSection::AllowedTcp | StartSection::AllowedUdp => {
                        "Tab next field · Enter continue · Esc / Ctrl-C quit"
                    }
                }
            } else {
                "↑/↓ select · Enter continue · Esc / Ctrl-C quit"
            }
        }
        SetupPhase::ConfirmGenerateToken => "Esc back · Ctrl-C quit",
        SetupPhase::NodeId | SetupPhase::AuthToken => "Enter confirm · Esc back · Ctrl-C quit",
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

/// A text-input line. When `active`, a block cursor marks the edit position;
/// otherwise the value is shown plainly.
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

    /// Move the start-screen role selection to the dial option and confirm it.
    fn choose_dial(state: &mut SetupState) -> Step {
        handle_key(key(KeyCode::Down), state);
        handle_key(key(KeyCode::Enter), state)
    }

    /// Confirm the default (listen) role on the start screen.
    fn choose_listen(state: &mut SetupState) -> Step {
        handle_key(key(KeyCode::Enter), state)
    }

    /// A non-empty config allowlist so the start screen shows only the role list
    /// (the interactive allowlist fields appear only when config supplies none).
    fn from_config() -> AllowedSources {
        AllowedSources {
            tcp: vec!["127.0.0.0/8".into()],
            udp: vec![],
        }
    }

    #[test]
    fn listen_generates_token_when_none() {
        let mut s = SetupState::new(None, from_config());
        // Without a config token, choosing listen first asks for confirmation.
        assert!(matches!(choose_listen(&mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::ConfirmGenerateToken);
        // Confirming generates a fresh token and finishes (config supplies the allowlist).
        match handle_key(key(KeyCode::Char('y')), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Listen);
                assert!(r.peer_node_id.is_none());
                assert!(r.token_generated);
                assert!(auth::validate_token(&r.auth_token).is_ok());
                assert_eq!(r.allowed_sources.tcp, vec!["127.0.0.0/8".to_string()]);
            }
            _ => panic!("expected Done(Listen)"),
        }
    }

    #[test]
    fn listen_no_token_confirm_back_returns_to_start() {
        let mut s = SetupState::new(None, from_config());
        assert!(matches!(choose_listen(&mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::ConfirmGenerateToken);
        // Declining the confirmation returns to the start screen.
        assert!(matches!(handle_key(key(KeyCode::Char('n')), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::Start);
    }

    #[test]
    fn listen_on_enter_reuses_config_token() {
        let token = auth::generate_token();
        let mut s = SetupState::new(Some(token.clone()), from_config());
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Listen);
                assert_eq!(r.auth_token, token);
            }
            _ => panic!("expected Done(Listen)"),
        }
    }

    #[test]
    fn dial_rejects_bad_node_id_and_keeps_editing() {
        let mut s = SetupState::new(Some(auth::generate_token()), from_config());
        assert!(matches!(choose_dial(&mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::NodeId);
        type_str(&mut s, "not-a-node-id");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
    }

    #[test]
    fn dial_full_flow_with_config_token_skips_token_prompt() {
        let token = auth::generate_token();
        let node_id = iroh::SecretKey::generate().public().to_string();
        let mut s = SetupState::new(Some(token.clone()), from_config());
        choose_dial(&mut s);
        type_str(&mut s, &node_id);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Dial);
                assert_eq!(r.peer_node_id.map(|id| id.to_string()), Some(node_id));
                assert_eq!(r.auth_token, token);
            }
            _ => panic!("expected Done(Dial) without a token prompt"),
        }
    }

    #[test]
    fn dial_prompts_token_when_absent_and_validates_it() {
        let node_id = iroh::SecretKey::generate().public().to_string();
        let token = auth::generate_token();
        let mut s = SetupState::new(None, from_config());
        choose_dial(&mut s);
        type_str(&mut s, &node_id);
        // Valid node id with no config token -> advance to the token prompt.
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        // A bad token is rejected inline.
        type_str(&mut s, "short");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
        // Clear and enter a valid token.
        for _ in 0.."short".len() {
            handle_key(key(KeyCode::Backspace), &mut s);
        }
        type_str(&mut s, &token);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Dial);
                assert_eq!(r.auth_token, token);
            }
            _ => panic!("expected Done(Dial)"),
        }
    }

    #[test]
    fn node_id_field_supports_cursor_editing() {
        let mut s = SetupState::new(Some(auth::generate_token()), from_config());
        choose_dial(&mut s); // -> NodeId
        type_str(&mut s, "abcd");
        // Move left twice and insert in the middle.
        handle_key(key(KeyCode::Left), &mut s);
        handle_key(key(KeyCode::Left), &mut s);
        type_str(&mut s, "XY");
        assert_eq!(s.buffer.value(), "abXYcd");
        // Home, then delete-forward removes the first char.
        handle_key(key(KeyCode::Home), &mut s);
        handle_key(key(KeyCode::Delete), &mut s);
        assert_eq!(s.buffer.value(), "bXYcd");
    }

    #[test]
    fn start_role_selection_navigates_and_clamps() {
        let mut s = SetupState::new(Some(auth::generate_token()), from_config());
        // Default highlight is the listen option.
        assert_eq!(s.connect_choice, 0);
        // Up at the top clamps.
        handle_key(key(KeyCode::Up), &mut s);
        assert_eq!(s.connect_choice, 0);
        // Down moves to the dial option and clamps at the bottom.
        handle_key(key(KeyCode::Down), &mut s);
        assert_eq!(s.connect_choice, CONNECT_DIAL);
        handle_key(key(KeyCode::Down), &mut s);
        assert_eq!(s.connect_choice, CONNECT_DIAL);
        // Enter on the dial option advances to the node id prompt.
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::NodeId);
    }

    #[test]
    fn ctrl_c_quits() {
        let mut s = SetupState::new(None, from_config());
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(k, &mut s), Step::Quit));
    }

    #[test]
    fn start_screen_collects_tcp_then_udp_allowlist() {
        // Empty config allowlist -> the two CIDR fields appear on the start screen,
        // reached with Tab.
        let mut s = SetupState::new(Some(auth::generate_token()), AllowedSources::default());
        handle_key(key(KeyCode::Tab), &mut s); // Role -> AllowedTcp
        type_str(&mut s, "127.0.0.0/8 192.168.0.0/16");
        handle_key(key(KeyCode::Tab), &mut s); // -> AllowedUdp
        type_str(&mut s, "10.0.0.0/8");
        // Enter submits the whole screen; listen with a config token finishes.
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Listen);
                assert_eq!(
                    r.allowed_sources.tcp,
                    vec!["127.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
                );
                assert_eq!(r.allowed_sources.udp, vec!["10.0.0.0/8".to_string()]);
            }
            _ => panic!("expected Done(Listen) with the entered allowlist"),
        }
    }

    #[test]
    fn dial_carries_start_screen_allowlist() {
        // The allowlist entered on the start screen reaches a dial result too.
        let token = auth::generate_token();
        let node_id = iroh::SecretKey::generate().public().to_string();
        let mut s = SetupState::new(Some(token), AllowedSources::default());
        handle_key(key(KeyCode::Down), &mut s); // role -> dial
        handle_key(key(KeyCode::Tab), &mut s); // -> AllowedTcp
        type_str(&mut s, "10.0.0.0/8");
        handle_key(key(KeyCode::Enter), &mut s); // submit -> NodeId
        assert_eq!(s.phase, SetupPhase::NodeId);
        type_str(&mut s, &node_id);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Dial);
                assert_eq!(r.allowed_sources.tcp, vec!["10.0.0.0/8".to_string()]);
                assert!(r.allowed_sources.udp.is_empty());
            }
            _ => panic!("expected Done(Dial)"),
        }
    }

    #[test]
    fn allowlist_rejects_invalid_cidr_inline() {
        let mut s = SetupState::new(Some(auth::generate_token()), AllowedSources::default());
        handle_key(key(KeyCode::Tab), &mut s); // -> AllowedTcp
        type_str(&mut s, "not-a-cidr");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
        assert_eq!(s.phase, SetupPhase::Start); // stays put
        assert_eq!(s.section, StartSection::AllowedTcp);
    }

    #[test]
    fn allowlist_blank_entries_yield_empty_lists() {
        let mut s = SetupState::new(Some(auth::generate_token()), AllowedSources::default());
        // Blank TCP/UDP, default listen role: Enter finishes with empty
        // (fail-closed) lists.
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert!(r.allowed_sources.is_empty());
            }
            _ => panic!("expected Done with empty allowlist"),
        }
    }
}
