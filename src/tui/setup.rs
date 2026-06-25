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

use super::textinput::{handle_edit, render_field};
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
    /// No token from config/env: set one up. Quick mode shows a "Generate new" button
    /// alongside an inline entry field (the token is ephemeral); nostr mode shows only
    /// the entry field (its token is a pre-shared secret, generated out of band with
    /// `duopipe generate-auth-token`). Validated before it is accepted.
    TokenSetup,
}

/// Which element of the [`SetupPhase::TokenSetup`] screen has focus. `Generate` is only
/// present in quick mode; nostr mode stays on `Input`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TokenFocus {
    /// The "Generate new" button (quick mode only): make a fresh ephemeral token,
    /// surfaced in the dashboard so it can be copied to the other device.
    Generate,
    /// The inline token entry field: type or paste a token shared from another device.
    Input,
}

/// Which element of the [`SetupPhase::Start`] screen has focus. The two CIDR fields
/// only appear (and so are only focusable) when config supplies no `[allowed_sources]`;
/// the `Start`/`Exit` buttons are always present. Arrow keys move focus; Enter
/// activates it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StartFocus {
    AllowedTcp,
    AllowedUdp,
    Start,
    Exit,
}

impl StartFocus {
    fn is_button(self) -> bool {
        matches!(self, StartFocus::Start | StartFocus::Exit)
    }
}

/// Up/Down move between vertical rows, top to bottom as rendered: the Start/Exit
/// button row (the two buttons share one row; Left/Right pick between them), then the
/// first CIDR field, then the second. The CIDR rows only exist when shown.
fn move_focus(state: &mut SetupState, down: bool) {
    // One representative per row; the button row stays on whichever button is focused
    // while moving within it, and is entered (from a field) on the primary Start button.
    let button_row = if state.focus.is_button() {
        state.focus
    } else {
        StartFocus::Start
    };
    let rows: &[StartFocus] = if allowlist_fields_shown(state) {
        &[button_row, StartFocus::AllowedTcp, StartFocus::AllowedUdp]
    } else {
        &[button_row]
    };
    let i = rows.iter().position(|f| *f == state.focus).unwrap_or(0) as isize;
    let n = rows.len() as isize;
    let delta = if down { 1 } else { -1 };
    state.focus = rows[(((i + delta) % n + n) % n) as usize];
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
    /// Expected token fingerprint declared by a nostr config (validated in main). When
    /// set, a token pasted here must match it — guarding against a token meant for a
    /// different pairing. `None` in quick mode.
    expected_token_fingerprint: Option<String>,
    /// Allowlist supplied by config. When non-empty the interactive allowlist fields
    /// are hidden (config wins); when empty they are shown on the start screen.
    config_allowed_sources: AllowedSources,
    /// Currently focused element of the start screen.
    focus: StartFocus,
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
    /// Focused element on the [`SetupPhase::TokenSetup`] screen.
    token_focus: TokenFocus,
    /// Token typed/pasted on the [`SetupPhase::TokenSetup`] screen.
    auth_token_input: Input,
    /// Resolved credential, carried to `Done`.
    auth_token: Option<String>,
    token_generated: bool,
    /// Inline error from the last failed validation; cleared on the next keypress.
    error: Option<String>,
}

impl SetupState {
    pub fn new(
        config_auth_token: Option<String>,
        expected_token_fingerprint: Option<String>,
        config_allowed_sources: AllowedSources,
        nostr_discovery: bool,
        own_name: Option<String>,
    ) -> Self {
        Self {
            phase: SetupPhase::Start,
            config_auth_token,
            expected_token_fingerprint,
            config_allowed_sources,
            // The Start button is the primary action and focused first; the optional
            // CIDR fields are reached by arrowing down.
            focus: StartFocus::Start,
            allowed_tcp: Input::default(),
            allowed_udp: Input::default(),
            allowed_sources: AllowedSources::default(),
            nostr_discovery,
            own_name,
            token_focus: TokenFocus::Generate,
            auth_token_input: Input::default(),
            auth_token: None,
            token_generated: false,
            error: None,
        }
    }
}

/// Record the resolved credential and finish. `generated` is `true` only for a
/// freshly generated token (the dashboard then surfaces it for copying); a
/// config/env or pasted token is `false`.
fn finalize(state: &mut SetupState, auth_token: String, generated: bool) -> Step {
    state.auth_token = Some(auth_token);
    state.token_generated = generated;
    Step::Done(build_resolved(state))
}

/// Validate the typed/pasted token and finish on success; on failure keep the
/// `TokenSetup` screen open with an inline error.
fn submit_token(state: &mut SetupState) -> Step {
    let token = state.auth_token_input.value().trim().to_string();
    if token.is_empty() {
        state.error = Some(if state.nostr_discovery {
            "Enter the shared auth token.".to_string()
        } else {
            "Enter a token, or select \"Generate new\".".to_string()
        });
        return Step::Continue;
    }
    if let Err(e) = auth::validate_token(&token) {
        state.error = Some(format!("Invalid token: {e}"));
        return Step::Continue;
    }
    // In nostr mode the config declares the expected fingerprint; a token for a
    // different pairing is rejected here rather than failing the connection later.
    if let Some(expected) = &state.expected_token_fingerprint
        && !auth::fingerprint_matches(&token, expected)
    {
        state.error = Some(format!(
            "Token fingerprint {} does not match the config's auth_token_fingerprint ({expected}). This token is for a different pairing.",
            auth::token_fingerprint(&token)
        ));
        return Step::Continue;
    }
    finalize(state, token, false)
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
/// then finish (a config/env token is present), offer generate-or-enter (quick mode),
/// or go straight to token entry (nostr mode). A bad CIDR keeps the screen open with
/// an error.
fn submit_start(state: &mut SetupState) -> Step {
    let allowed = if !allowlist_fields_shown(state) {
        state.config_allowed_sources.clone()
    } else {
        let tcp = match parse_cidr_list(state.allowed_tcp.value()) {
            Ok(list) => list,
            Err(e) => {
                state.focus = StartFocus::AllowedTcp;
                state.error = Some(format!("Invalid TCP CIDR: {e}"));
                return Step::Continue;
            }
        };
        let udp = match parse_cidr_list(state.allowed_udp.value()) {
            Ok(list) => list,
            Err(e) => {
                state.focus = StartFocus::AllowedUdp;
                state.error = Some(format!("Invalid UDP CIDR: {e}"));
                return Step::Continue;
            }
        };
        AllowedSources { tcp, udp }
    };
    state.allowed_sources = allowed;

    if let Some(token) = state.config_auth_token.clone() {
        // A config/env token is used as-is, no further prompt.
        finalize(state, token, false)
    } else {
        // No token: open the token-setup screen. Quick mode focuses its "Generate new"
        // button (the common path; the token is ephemeral); nostr mode has no generate
        // option (the token is a pre-shared secret), so it focuses the entry field.
        state.phase = SetupPhase::TokenSetup;
        state.token_focus = if state.nostr_discovery {
            TokenFocus::Input
        } else {
            TokenFocus::Generate
        };
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
            // Enter activates the focused element: the Exit button quits, anything
            // else (Start button or a CIDR field) submits and starts.
            KeyCode::Enter => match state.focus {
                StartFocus::Exit => Step::Quit,
                _ => submit_start(state),
            },
            // Up/Down (or Tab/BackTab) move between rows: the Start/Exit button group,
            // then the first CIDR field, then the second.
            KeyCode::Down | KeyCode::Tab => {
                move_focus(state, true);
                Step::Continue
            }
            KeyCode::Up | KeyCode::BackTab => {
                move_focus(state, false);
                Step::Continue
            }
            // On the buttons, Left/Right move between Start and Exit. On a CIDR field
            // they fall through to the text input (cursor movement).
            KeyCode::Left | KeyCode::Right if state.focus.is_button() => {
                state.focus = match state.focus {
                    StartFocus::Exit => StartFocus::Start,
                    _ => StartFocus::Exit,
                };
                Step::Continue
            }
            _ => {
                match state.focus {
                    StartFocus::AllowedTcp => {
                        handle_edit(&mut state.allowed_tcp, key, is_cidr_char)
                    }
                    StartFocus::AllowedUdp => {
                        handle_edit(&mut state.allowed_udp, key, is_cidr_char)
                    }
                    // Buttons ignore text keystrokes.
                    StartFocus::Start | StartFocus::Exit => {}
                }
                Step::Continue
            }
        },
        SetupPhase::TokenSetup => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::Start;
                Step::Continue
            }
            // Tab / Up / Down move between the "Generate new" button and the inline
            // entry field. Quick mode only — nostr has no Generate button, so these
            // fall through to the field (where they are no-ops).
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down
                if !state.nostr_discovery =>
            {
                state.token_focus = match state.token_focus {
                    TokenFocus::Generate => TokenFocus::Input,
                    TokenFocus::Input => TokenFocus::Generate,
                };
                Step::Continue
            }
            KeyCode::Enter => match state.token_focus {
                TokenFocus::Generate => finalize(state, auth::generate_token(), true),
                TokenFocus::Input => submit_token(state),
            },
            // On the entry field every other key (Left/Right cursor moves, backspace,
            // paste, characters) edits the input; the Generate button ignores them.
            _ => {
                if state.token_focus == TokenFocus::Input {
                    handle_edit(&mut state.auth_token_input, key, is_token_char);
                }
                Step::Continue
            }
        },
    }
}

/// CIDR entry accepts printable ASCII plus spaces/commas as separators between entries.
fn is_cidr_char(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

/// Token entry accepts printable ASCII with no spaces (tokens are `d` + base64url).
fn is_token_char(c: char) -> bool {
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
            format!(
                "duopipe v{} — {} setup",
                env!("CARGO_PKG_VERSION"),
                if state.nostr_discovery { "nostr" } else { "quick" }
            ),
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
            if let Some(token) = &state.config_auth_token {
                lines.push(Line::from(Span::styled(
                    format!(
                        "  Auth token loaded (fingerprint: {}).",
                        auth::token_fingerprint(token)
                    ),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            // Primary actions, kept above the optional allowlist fields so Start isn't
            // buried below advanced settings the user can safely skip.
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                button_span("Start", state.focus == StartFocus::Start),
                Span::raw("  "),
                button_span("Exit", state.focus == StartFocus::Exit),
            ]));
            if allowlist_fields_shown(state) {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "Optional — leave blank to allow localhost only:",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(choice_line(
                    "Allowed TCP sources the peer may request (CIDR):",
                    state.focus == StartFocus::AllowedTcp,
                ));
                lines.push(field_input_line(
                    &state.allowed_tcp,
                    state.focus == StartFocus::AllowedTcp,
                ));
                lines.push(Line::from(Span::styled(
                    "      space/comma-separated, e.g. 192.168.0.0/16 — blank = localhost (127.0.0.0/8 ::1/128)",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(choice_line(
                    "Allowed UDP sources the peer may request (CIDR):",
                    state.focus == StartFocus::AllowedUdp,
                ));
                lines.push(field_input_line(
                    &state.allowed_udp,
                    state.focus == StartFocus::AllowedUdp,
                ));
                lines.push(Line::from(Span::styled(
                    "      space/comma-separated, e.g. 10.0.0.0/8 — blank = localhost (127.0.0.0/8 ::1/128)",
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        SetupPhase::TokenSetup => {
            let input_active = state.token_focus == TokenFocus::Input;
            if state.nostr_discovery {
                // Nostr: the token is a pre-shared secret — entry only, no generate. One
                // field, always active, so it needs no choice marker.
                lines.push(Line::from("Enter the shared auth token:"));
                // The config declares the token's fingerprint; show it so the user knows
                // what their pasted token must match before they even submit.
                if let Some(expected) = &state.expected_token_fingerprint {
                    lines.push(Line::from(Span::styled(
                        format!("  expected fingerprint: {expected} — your token must match this"),
                        Style::default().fg(Color::Yellow),
                    )));
                }
                lines.push(field_input_line(&state.auth_token_input, input_active));
            } else {
                // Quick: two stacked choices, each marked with `▶` when it has focus —
                // generate a fresh token, or type/paste an existing one.
                lines.push(Line::from("No auth token supplied. Choose one:"));
                lines.push(Line::raw(""));
                lines.push(choice_line(
                    "Generate new token",
                    state.token_focus == TokenFocus::Generate,
                ));
                lines.push(Line::from(Span::styled(
                    "      A fresh token for this run, shown so you can copy it to your other device.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::raw(""));
                lines.push(choice_line("Enter an existing token:", input_active));
                lines.push(field_input_line(&state.auth_token_input, input_active));
            }

            let typed = state.auth_token_input.value().trim();
            if !typed.is_empty() && auth::validate_token(typed).is_ok() {
                let fp = auth::token_fingerprint(typed);
                // When the config pins a fingerprint, show match/mismatch directly against
                // it; otherwise just surface the fingerprint to cross-check by hand.
                let line = match &state.expected_token_fingerprint {
                    Some(expected) if auth::fingerprint_matches(typed, expected) => Span::styled(
                        format!("      fingerprint: {fp} ✓ matches the config"),
                        Style::default().fg(Color::Green),
                    ),
                    Some(expected) => Span::styled(
                        format!("      fingerprint: {fp} ✗ does not match the config ({expected})"),
                        Style::default().fg(Color::Red),
                    ),
                    None => Span::styled(
                        format!("      fingerprint: {fp} — confirm this matches your other device"),
                        Style::default().fg(Color::Green),
                    ),
                };
                lines.push(Line::from(line));
            }
            lines.push(Line::raw(""));
            let hint = if state.nostr_discovery {
                // Nostr has no Generate button: the token is pre-shared, made out of band.
                "Both peers need the same token. First time? Run `duopipe generate-auth-token`, then paste that token here on every device."
            } else {
                // Quick mode: the Generate choice above covers a fresh token; this field
                // is for reusing one shown on the other device.
                "Both peers need the same token: paste the one shown on your other device, or pick \"Generate new token\" above."
            };
            lines.push(Line::from(Span::styled(
                hint,
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
    let footer = match state.phase {
        SetupPhase::Start => "↑/↓ ←/→ move · Enter select · Esc / Ctrl-C quit",
        SetupPhase::TokenSetup if !state.nostr_discovery => {
            "Tab move · Enter generate/confirm · Esc back · Ctrl-C quit"
        }
        SetupPhase::TokenSetup => "Enter confirm · Esc back · Ctrl-C quit",
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

/// A focusable button. The focused one is reverse-highlighted; the rest are dim.
fn button_span(label: &str, focused: bool) -> Span<'static> {
    let style = if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    Span::styled(format!(" {label} "), style)
}

/// Left-margin focus marker for the stacked setup choices: a bold green `▶` on the
/// active choice, blank (same width) otherwise so every label stays aligned.
fn choice_marker(active: bool) -> Span<'static> {
    if active {
        Span::styled(
            "▶ ",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("  ")
    }
}

/// A choice header line: the focus marker plus a label that brightens when active.
fn choice_line(label: &str, active: bool) -> Line<'static> {
    let label_style = if active {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    Line::from(vec![
        choice_marker(active),
        Span::styled(label.to_string(), label_style),
    ])
}

/// The text-input line nested under a [`choice_line`]: indented to clear the marker,
/// with a block cursor at the edit position when `active`.
fn field_input_line(buffer: &Input, active: bool) -> Line<'static> {
    let mut spans = vec![Span::raw("    ")];
    spans.extend(render_field(buffer, Style::default().fg(Color::Cyan), active));
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
        let mut s = SetupState::new(Some(token.clone()), None, from_config(), true, Some("hl".into()));
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
    fn quick_without_token_focuses_generate_and_generates() {
        // Quick mode: no config token -> the token-setup screen, focused on Generate.
        let mut s = SetupState::new(None, None, from_config(), false, None);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        assert_eq!(s.token_focus, TokenFocus::Generate);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert!(r.token_generated);
                assert!(auth::validate_token(&r.auth_token).is_ok());
            }
            _ => panic!("expected Done(Both)"),
        }
    }

    #[test]
    fn quick_can_tab_to_inline_field_and_enter_token() {
        // Tab moves from the Generate button to the inline entry field; typing there
        // and pressing Enter accepts the pasted token (not "generated").
        let token = auth::generate_token();
        let mut s = SetupState::new(None, None, from_config(), false, None);
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup (focus Generate)
        handle_key(key(KeyCode::Tab), &mut s);
        assert_eq!(s.token_focus, TokenFocus::Input);
        type_str(&mut s, &token);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert!(!r.token_generated, "an entered token is not 'generated'");
                assert_eq!(r.auth_token, token);
            }
            _ => panic!("expected Done(Both) with the entered token"),
        }
    }

    #[test]
    fn nostr_without_token_focuses_inline_field() {
        // Nostr mode has no Generate button (its token is a pre-shared secret), so the
        // entry field is focused immediately on the same screen.
        let token = auth::generate_token();
        let mut s = SetupState::new(None, None, from_config(), true, Some("hl".into()));
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        assert_eq!(s.token_focus, TokenFocus::Input);
        type_str(&mut s, &token);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert!(!r.token_generated);
                assert_eq!(r.auth_token, token);
            }
            _ => panic!("expected Done(Both) with the entered token"),
        }
    }

    #[test]
    fn nostr_rejects_token_with_wrong_fingerprint() {
        // A nostr config declares the expected fingerprint; pasting a token from a
        // different pairing is rejected with an inline error rather than accepted.
        let intended = auth::generate_token();
        let other = auth::generate_token();
        let expected = auth::token_fingerprint(&intended);
        let mut s = SetupState::new(None, Some(expected.clone()), from_config(), true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup
        type_str(&mut s, &other);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        assert!(s.error.as_deref().unwrap_or("").contains("fingerprint"));
    }

    #[test]
    fn nostr_accepts_token_matching_fingerprint() {
        let token = auth::generate_token();
        let expected = auth::token_fingerprint(&token);
        let mut s = SetupState::new(None, Some(expected), from_config(), true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup
        type_str(&mut s, &token);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => assert_eq!(r.auth_token, token),
            _ => panic!("expected Done with the matching token"),
        }
    }

    /// Render the setup screen to plain text for assertions.
    fn render_text(state: &SetupState) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("test terminal");
        terminal.draw(|f| render(f, state)).expect("render");
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
    fn nostr_token_screen_shows_expected_fingerprint_and_match_state() {
        let token = auth::generate_token();
        let expected = auth::token_fingerprint(&token);
        let mut s = SetupState::new(
            None,
            Some(expected.clone()),
            from_config(),
            true,
            Some("hl".into()),
        );
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup

        // Before typing: the expected fingerprint is shown up front.
        let empty = render_text(&s);
        assert!(empty.contains("expected fingerprint:"));
        assert!(empty.contains(&expected));

        // A matching token reports ✓; a different one reports ✗.
        type_str(&mut s, &token);
        assert!(render_text(&s).contains('✓'));

        let other = auth::generate_token();
        let mut mismatch = SetupState::new(None, Some(expected), from_config(), true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut mismatch);
        type_str(&mut mismatch, &other);
        assert!(render_text(&mismatch).contains('✗'));
    }

    #[test]
    fn token_setup_esc_returns_to_start() {
        let mut s = SetupState::new(None, None, from_config(), false, None);
        handle_key(key(KeyCode::Enter), &mut s);
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        handle_key(key(KeyCode::Esc), &mut s);
        assert_eq!(s.phase, SetupPhase::Start);
    }

    #[test]
    fn enter_token_rejects_invalid_and_stays_open() {
        let mut s = SetupState::new(None, None, from_config(), false, None);
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup (focus Generate)
        handle_key(key(KeyCode::Tab), &mut s); // focus the inline field
        type_str(&mut s, "not-a-real-token");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        assert!(s.error.is_some());
    }

    #[test]
    fn start_screen_collects_tcp_then_udp_allowlist() {
        // Empty config allowlist -> the two CIDR fields appear below the Start/Exit
        // buttons. Focus starts on Start, so arrow down into the TCP field first.
        let mut s = SetupState::new(
            Some(auth::generate_token()),
            None,
            AllowedSources::default(),
            false,
            None,
        );
        handle_key(key(KeyCode::Down), &mut s); // button row -> AllowedTcp
        assert_eq!(s.focus, StartFocus::AllowedTcp);
        type_str(&mut s, "127.0.0.0/8 192.168.0.0/16");
        handle_key(key(KeyCode::Down), &mut s); // -> AllowedUdp
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
            None,
            AllowedSources::default(),
            false,
            None,
        );
        handle_key(key(KeyCode::Down), &mut s); // button row -> AllowedTcp
        type_str(&mut s, "not-a-cidr");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert!(s.error.is_some());
        assert_eq!(s.phase, SetupPhase::Start);
    }

    #[test]
    fn allowlist_field_supports_cursor_editing() {
        let mut s = SetupState::new(
            Some(auth::generate_token()),
            None,
            AllowedSources::default(),
            false,
            None,
        );
        handle_key(key(KeyCode::Down), &mut s); // button row -> AllowedTcp
        type_str(&mut s, "abcd");
        // On a CIDR field, Left/Right move the text cursor (they only switch buttons
        // when a button is focused).
        handle_key(key(KeyCode::Left), &mut s);
        handle_key(key(KeyCode::Left), &mut s);
        type_str(&mut s, "XY");
        assert_eq!(s.allowed_tcp.value(), "abXYcd");
    }

    #[test]
    fn start_button_focused_first_and_enter_starts() {
        let mut s = SetupState::new(Some(auth::generate_token()), None, from_config(), false, None);
        assert_eq!(s.focus, StartFocus::Start);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Done(_)));
    }

    #[test]
    fn exit_button_is_focusable_and_enter_quits() {
        let mut s = SetupState::new(Some(auth::generate_token()), None, from_config(), false, None);
        // No fields shown -> focus order is just [Start, Exit]; Right reaches Exit.
        handle_key(key(KeyCode::Right), &mut s);
        assert_eq!(s.focus, StartFocus::Exit);
        // Left toggles back, Right again to Exit, then Enter quits.
        handle_key(key(KeyCode::Left), &mut s);
        assert_eq!(s.focus, StartFocus::Start);
        handle_key(key(KeyCode::Right), &mut s);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Quit));
    }

    #[test]
    fn up_down_move_between_button_row_and_fields() {
        let mut s = SetupState::new(
            Some(auth::generate_token()),
            None,
            AllowedSources::default(),
            false,
            None,
        );
        // Down steps row-by-row: button group -> first field -> second field -> wrap.
        assert_eq!(s.focus, StartFocus::Start);
        handle_key(key(KeyCode::Down), &mut s);
        assert_eq!(s.focus, StartFocus::AllowedTcp);
        handle_key(key(KeyCode::Down), &mut s);
        assert_eq!(s.focus, StartFocus::AllowedUdp);
        handle_key(key(KeyCode::Down), &mut s);
        assert_eq!(s.focus, StartFocus::Start, "wraps back to the button row");

        // The button row is one vertical stop: Left/Right pick between Start and Exit,
        // and Down leaves the whole row for the first field (no Start->Exit step).
        handle_key(key(KeyCode::Right), &mut s);
        assert_eq!(s.focus, StartFocus::Exit);
        handle_key(key(KeyCode::Down), &mut s);
        assert_eq!(s.focus, StartFocus::AllowedTcp);
        // Coming back up lands on the primary Start button.
        handle_key(key(KeyCode::Up), &mut s);
        assert_eq!(s.focus, StartFocus::Start);
    }

    #[test]
    fn ctrl_c_quits() {
        let mut s = SetupState::new(None, None, from_config(), false, None);
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(k, &mut s), Step::Quit));
    }
}
