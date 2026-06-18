//! Interactive in-TUI setup: collect role, target node id, and auth token
//! before the runtime starts.
//!
//! Pure state machine ([`SetupState`] + [`handle_key`]) plus a pure [`render`].
//! The driver lives in [`super::run_setup`]. Validation (CRC16 on the auth token,
//! `EndpointId` parse on the node id) happens here, so the dialer never attempts
//! a connection with bad inputs.

use iroh::EndpointId;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app_state::Role;
use crate::auth;
use crate::config::{validate_cidr, AllowedSources};
use crate::peer_params::ResolvedPeer;

/// Which question the setup screen is currently asking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SetupPhase {
    /// "Connect to an existing instance? (y/N)"
    ConnectExisting,
    /// Listen only, when no config token: confirm a fresh token will be
    /// generated for this run before generating it.
    ConfirmGenerateToken,
    /// Dial only: the existing instance's node id.
    NodeId,
    /// Dial only: the auth token (skipped when one came from config/env).
    AuthToken,
    /// Both roles, only when config supplies no `[allowed_sources]`: the TCP CIDR
    /// allowlist the peer may request of us.
    AllowedTcp,
    /// Both roles, only when config supplies no `[allowed_sources]`: the UDP CIDR
    /// allowlist.
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
    /// prompts are skipped (config wins); when empty they are shown.
    config_allowed_sources: AllowedSources,
    node_id: Option<EndpointId>,
    /// Resolved credential, carried across the allowlist phases before `Done`.
    auth_token: Option<String>,
    token_generated: bool,
    /// TCP CIDRs entered interactively in `AllowedTcp`, held until `AllowedUdp`
    /// completes the allowlist (only used when `config_allowed_sources` empty).
    allowed_tcp: Vec<String>,
    /// Current text field contents (node id / token / CIDR entry).
    buffer: String,
    /// Inline error from the last failed validation; cleared on the next keypress.
    error: Option<String>,
}

impl SetupState {
    pub fn new(config_auth_token: Option<String>, config_allowed_sources: AllowedSources) -> Self {
        Self {
            phase: SetupPhase::ConnectExisting,
            config_auth_token,
            config_allowed_sources,
            node_id: None,
            auth_token: None,
            token_generated: false,
            allowed_tcp: Vec::new(),
            buffer: String::new(),
            error: None,
        }
    }
}

/// Resolve the Listen credential (config/env token or a fresh one), then proceed to
/// the allowlist prompts or finish.
fn finalize_listen(state: &mut SetupState) -> Step {
    let (auth_token, token_generated) = match state.config_auth_token.clone() {
        Some(token) => (token, false),
        None => (auth::generate_token(), true),
    };
    state.auth_token = Some(auth_token);
    state.token_generated = token_generated;
    state.node_id = None;
    after_credentials(state)
}

/// After role + credential are resolved: skip straight to `Done` when config
/// supplies an allowlist, otherwise enter the interactive allowlist prompts.
fn after_credentials(state: &mut SetupState) -> Step {
    if !state.config_allowed_sources.is_empty() {
        Step::Done(build_resolved(state, state.config_allowed_sources.clone()))
    } else {
        state.phase = SetupPhase::AllowedTcp;
        state.buffer.clear();
        Step::Continue
    }
}

/// Build the final `ResolvedPeer` from accumulated state plus the allowlist.
fn build_resolved(state: &SetupState, allowed_sources: AllowedSources) -> ResolvedPeer {
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
        allowed_sources,
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
    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl_c {
        return Step::Quit;
    }
    // Any keypress clears a stale error message.
    state.error = None;

    match state.phase {
        SetupPhase::ConnectExisting => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                state.phase = SetupPhase::NodeId;
                state.buffer.clear();
                Step::Continue
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Enter => {
                // A config/env token is used as-is (no confirmation). Without one,
                // confirm before generating a fresh ephemeral token.
                if state.config_auth_token.is_some() {
                    finalize_listen(state)
                } else {
                    state.phase = SetupPhase::ConfirmGenerateToken;
                    state.buffer.clear();
                    Step::Continue
                }
            }
            KeyCode::Char('q') | KeyCode::Esc => Step::Quit,
            _ => Step::Continue,
        },
        SetupPhase::ConfirmGenerateToken => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => finalize_listen(state),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                state.phase = SetupPhase::ConnectExisting;
                state.buffer.clear();
                Step::Continue
            }
            KeyCode::Char('q') => Step::Quit,
            _ => Step::Continue,
        },
        SetupPhase::NodeId => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::ConnectExisting;
                state.buffer.clear();
                Step::Continue
            }
            KeyCode::Enter => match state.buffer.trim().parse::<EndpointId>() {
                Ok(id) => {
                    state.node_id = Some(id);
                    match state.config_auth_token.clone() {
                        Some(token) => {
                            state.auth_token = Some(token);
                            state.token_generated = false;
                            after_credentials(state)
                        }
                        None => {
                            state.phase = SetupPhase::AuthToken;
                            state.buffer.clear();
                            Step::Continue
                        }
                    }
                }
                Err(_) => {
                    state.error = Some("Invalid node id".to_string());
                    Step::Continue
                }
            },
            KeyCode::Backspace => {
                state.buffer.pop();
                Step::Continue
            }
            KeyCode::Char(c) if is_input_char(c) => {
                state.buffer.push(c);
                Step::Continue
            }
            _ => Step::Continue,
        },
        SetupPhase::AuthToken => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::NodeId;
                state.buffer.clear();
                Step::Continue
            }
            KeyCode::Enter => {
                let token = state.buffer.trim().to_string();
                match auth::validate_token(&token) {
                    Ok(()) => {
                        state.auth_token = Some(token);
                        state.token_generated = false;
                        after_credentials(state)
                    }
                    Err(e) => {
                        state.error = Some(format!("Invalid auth token: {e}"));
                        Step::Continue
                    }
                }
            }
            KeyCode::Backspace => {
                state.buffer.pop();
                Step::Continue
            }
            KeyCode::Char(c) if is_input_char(c) => {
                state.buffer.push(c);
                Step::Continue
            }
            _ => Step::Continue,
        },
        SetupPhase::AllowedTcp => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::ConnectExisting;
                state.buffer.clear();
                Step::Continue
            }
            KeyCode::Enter => match parse_cidr_list(&state.buffer) {
                Ok(list) => {
                    state.allowed_tcp = list;
                    state.phase = SetupPhase::AllowedUdp;
                    state.buffer.clear();
                    Step::Continue
                }
                Err(e) => {
                    state.error = Some(format!("Invalid CIDR: {e}"));
                    Step::Continue
                }
            },
            KeyCode::Backspace => {
                state.buffer.pop();
                Step::Continue
            }
            KeyCode::Char(c) if is_cidr_char(c) => {
                state.buffer.push(c);
                Step::Continue
            }
            _ => Step::Continue,
        },
        SetupPhase::AllowedUdp => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::AllowedTcp;
                state.buffer.clear();
                Step::Continue
            }
            KeyCode::Enter => match parse_cidr_list(&state.buffer) {
                Ok(list) => {
                    let allowed = AllowedSources {
                        tcp: state.allowed_tcp.clone(),
                        udp: list,
                    };
                    Step::Done(build_resolved(state, allowed))
                }
                Err(e) => {
                    state.error = Some(format!("Invalid CIDR: {e}"));
                    Step::Continue
                }
            },
            KeyCode::Backspace => {
                state.buffer.pop();
                Step::Continue
            }
            KeyCode::Char(c) if is_cidr_char(c) => {
                state.buffer.push(c);
                Step::Continue
            }
            _ => Step::Continue,
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
        SetupPhase::ConnectExisting => {
            lines.push(Line::from("Connect to an existing instance?"));
            lines.push(Line::from(Span::styled(
                "  y = dial an existing instance     n / Enter = start a new (listening) instance",
                Style::default().fg(Color::DarkGray),
            )));
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
            lines.push(input_line(&state.buffer));
        }
        SetupPhase::AuthToken => {
            lines.push(Line::from("Auth token:"));
            lines.push(input_line(&state.buffer));
        }
        SetupPhase::AllowedTcp => {
            lines.push(Line::from("Allowed TCP sources the peer may request (CIDR):"));
            lines.push(input_line(&state.buffer));
            lines.push(Line::from(Span::styled(
                "  space/comma-separated, e.g. 192.168.0.0/16 — blank = localhost (127.0.0.0/8 ::1/128)",
                Style::default().fg(Color::DarkGray),
            )));
        }
        SetupPhase::AllowedUdp => {
            lines.push(Line::from("Allowed UDP sources the peer may request (CIDR):"));
            lines.push(input_line(&state.buffer));
            lines.push(Line::from(Span::styled(
                "  space/comma-separated, e.g. 10.0.0.0/8 — blank = none (rejects all)",
                Style::default().fg(Color::DarkGray),
            )));
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
    // `q` quits only at the y/n prompt; in the text fields it's literal input,
    // so don't advertise it there.
    let footer = match state.phase {
        SetupPhase::ConnectExisting | SetupPhase::ConfirmGenerateToken => "Ctrl-C / q quit",
        SetupPhase::NodeId
        | SetupPhase::AuthToken
        | SetupPhase::AllowedTcp
        | SetupPhase::AllowedUdp => "Enter confirm · Esc back · Ctrl-C quit",
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

/// A text-input line with a trailing block cursor.
fn input_line(buffer: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(buffer.to_string(), Style::default().fg(Color::Cyan)),
        Span::styled(
            "█",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::SLOW_BLINK),
        ),
    ])
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

    /// A non-empty allowlist so setup finishes in one step (the interactive
    /// allowlist prompts are only shown when config supplies none).
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
        assert!(matches!(handle_key(key(KeyCode::Char('n')), &mut s), Step::Continue));
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
    fn listen_no_token_confirm_back_returns_to_connect_existing() {
        let mut s = SetupState::new(None, from_config());
        assert!(matches!(handle_key(key(KeyCode::Char('n')), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::ConfirmGenerateToken);
        // Declining the confirmation returns to the initial prompt.
        assert!(matches!(handle_key(key(KeyCode::Char('n')), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::ConnectExisting);
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
        assert!(matches!(handle_key(key(KeyCode::Char('y')), &mut s), Step::Continue));
        type_str(&mut s, "not-a-node-id");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
    }

    #[test]
    fn dial_full_flow_with_config_token_skips_token_prompt() {
        let token = auth::generate_token();
        let node_id = iroh::SecretKey::generate().public().to_string();
        let mut s = SetupState::new(Some(token.clone()), from_config());
        handle_key(key(KeyCode::Char('y')), &mut s);
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
        handle_key(key(KeyCode::Char('y')), &mut s);
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
    fn ctrl_c_quits() {
        let mut s = SetupState::new(None, from_config());
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(k, &mut s), Step::Quit));
    }

    #[test]
    fn listen_without_config_allowlist_prompts_tcp_then_udp() {
        // Empty config allowlist -> the two CIDR prompts appear before Done.
        let mut s = SetupState::new(Some(auth::generate_token()), AllowedSources::default());
        // Choose listen; advances to the TCP allowlist prompt rather than finishing.
        assert!(matches!(handle_key(key(KeyCode::Char('n')), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::AllowedTcp);
        type_str(&mut s, "127.0.0.0/8 192.168.0.0/16");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::AllowedUdp);
        type_str(&mut s, "10.0.0.0/8");
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Listen);
                assert_eq!(
                    r.allowed_sources.tcp,
                    vec!["127.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
                );
                assert_eq!(r.allowed_sources.udp, vec!["10.0.0.0/8".to_string()]);
            }
            _ => panic!("expected Done(Listen) after the allowlist prompts"),
        }
    }

    #[test]
    fn allowlist_rejects_invalid_cidr_inline() {
        let mut s = SetupState::new(Some(auth::generate_token()), AllowedSources::default());
        handle_key(key(KeyCode::Char('n')), &mut s);
        assert_eq!(s.phase, SetupPhase::AllowedTcp);
        type_str(&mut s, "not-a-cidr");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
        assert_eq!(s.phase, SetupPhase::AllowedTcp); // stays put
    }

    #[test]
    fn allowlist_blank_entries_yield_empty_lists() {
        let mut s = SetupState::new(Some(auth::generate_token()), AllowedSources::default());
        handle_key(key(KeyCode::Char('n')), &mut s);
        // Blank TCP -> advance; blank UDP -> Done with empty (fail-closed) lists.
        handle_key(key(KeyCode::Enter), &mut s);
        assert_eq!(s.phase, SetupPhase::AllowedUdp);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert!(r.allowed_sources.is_empty());
            }
            _ => panic!("expected Done with empty allowlist"),
        }
    }
}
