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
use crate::peer_params::ResolvedPeer;

/// Which question the setup screen is currently asking.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupPhase {
    /// "Connect to an existing instance? (y/N)"
    ConnectExisting,
    /// Dial only: the existing instance's node id.
    NodeId,
    /// Dial only: the auth token (skipped when one came from config/env).
    AuthToken,
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
    node_id: Option<EndpointId>,
    /// Current text field contents (node id or token entry).
    buffer: String,
    /// Inline error from the last failed validation; cleared on the next keypress.
    error: Option<String>,
}

impl SetupState {
    pub fn new(config_auth_token: Option<String>) -> Self {
        Self {
            phase: SetupPhase::ConnectExisting,
            config_auth_token,
            node_id: None,
            buffer: String::new(),
            error: None,
        }
    }
}

/// Finalize the Listen role: reuse the config/env token or generate a fresh one.
fn finalize_listen(state: &SetupState) -> ResolvedPeer {
    let (auth_token, token_generated) = match state.config_auth_token.clone() {
        Some(token) => (token, false),
        None => (auth::generate_token(), true),
    };
    ResolvedPeer {
        role: Role::Listen,
        peer_node_id: None,
        auth_token,
        token_generated,
    }
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
                Step::Done(finalize_listen(state))
            }
            KeyCode::Char('q') | KeyCode::Esc => Step::Quit,
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
                    match &state.config_auth_token {
                        Some(token) => Step::Done(ResolvedPeer {
                            role: Role::Dial,
                            peer_node_id: Some(id),
                            auth_token: token.clone(),
                            token_generated: false,
                        }),
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
                    Ok(()) => Step::Done(ResolvedPeer {
                        role: Role::Dial,
                        peer_node_id: state.node_id,
                        auth_token: token,
                        token_generated: false,
                    }),
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
    }
}

/// Accept printable ASCII (node ids and tokens are ASCII; no spaces).
fn is_input_char(c: char) -> bool {
    c.is_ascii_graphic()
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
        SetupPhase::NodeId => {
            lines.push(Line::from("Existing instance node id:"));
            lines.push(input_line(&state.buffer));
        }
        SetupPhase::AuthToken => {
            lines.push(Line::from("Auth token:"));
            lines.push(input_line(&state.buffer));
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
    lines.push(Line::from(Span::styled(
        "Esc back · Ctrl-C / q quit",
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

    #[test]
    fn listen_generates_token_when_none() {
        let mut s = SetupState::new(None);
        match handle_key(key(KeyCode::Char('n')), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Listen);
                assert!(r.peer_node_id.is_none());
                assert!(auth::validate_token(&r.auth_token).is_ok());
            }
            _ => panic!("expected Done(Listen)"),
        }
    }

    #[test]
    fn listen_on_enter_reuses_config_token() {
        let token = auth::generate_token();
        let mut s = SetupState::new(Some(token.clone()));
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
        let mut s = SetupState::new(Some(auth::generate_token()));
        assert!(matches!(handle_key(key(KeyCode::Char('y')), &mut s), Step::Continue));
        type_str(&mut s, "not-a-node-id");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
    }

    #[test]
    fn dial_full_flow_with_config_token_skips_token_prompt() {
        let token = auth::generate_token();
        let node_id = iroh::SecretKey::generate().public().to_string();
        let mut s = SetupState::new(Some(token.clone()));
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
        let mut s = SetupState::new(None);
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
        let mut s = SetupState::new(None);
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(k, &mut s), Step::Quit));
    }
}
