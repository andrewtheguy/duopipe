//! Interactive in-TUI setup: confirm token generation before the runtime starts.
//!
//! There is no role question: every interactive run is always listening, and the
//! single outbound dial session is started on demand from the dashboard (see
//! `super::handle_key`). Setup therefore only resolves the auth token (supplied, or
//! freshly generated).
//!
//! Quick mode always generates a fresh ephemeral token — there is no token screen and
//! no way to supply an existing token. Connect mode shows a single entry field for the
//! pre-shared rendezvous secret (generated out of band with `duopipe
//! generate-auth-token`), validated against the config's declared fingerprint.
//!
//! Pure state machine ([`SetupState`] + [`handle_key`]) plus a pure [`render`]. The
//! driver lives in [`super::run_setup`]. Validation (CRC16 on a supplied token)
//! happens here.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tui_input::Input;

use super::textinput::{INPUT_FIELD_HEIGHT, handle_edit, render_input_field};
use crate::app_state::Role;
use crate::auth;
use crate::peer_params::ResolvedPeer;

/// Which question the setup screen is currently asking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SetupPhase {
    /// Start screen: a summary and Start/Exit buttons. Enter proceeds.
    Start,
    /// Connect mode only: enter the pre-shared auth token (a secret generated out of
    /// band with `duopipe generate-auth-token`). Validated before it is accepted, and
    /// checked against the config's declared fingerprint. Quick mode never reaches this
    /// phase — it always generates its token on Start.
    TokenSetup,
}

/// Which button of the [`SetupPhase::Start`] screen has focus; Enter activates it.
///
/// Connect mode shows the `Start`/`Exit` pair. Quick mode instead shows the two signaling
/// choices `PinStart`/`ManualStart` (each one *is* the start action, picking how to pair)
/// plus `Exit`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StartFocus {
    /// Connect mode: confirm and proceed (resolve the pre-shared token).
    Start,
    Exit,
    /// Quick mode: start with rotating-PIN nostr signaling.
    PinStart,
    /// Quick mode: start with manual node-id copy-paste.
    ManualStart,
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
    /// Expected token fingerprint declared by a connect-mode config (validated in main). When
    /// set, a token pasted here must match it — guarding against a token meant for a
    /// different pairing. `None` in quick mode.
    expected_token_fingerprint: Option<String>,
    /// Currently focused button of the start screen.
    focus: StartFocus,
    /// Whether nostr discovery is active (connect mode) — display only, for the summary.
    nostr_discovery: bool,
    /// This machine's own nostr name (config `name`) — display only, for the summary.
    own_name: Option<String>,
    /// Token typed/pasted on the [`SetupPhase::TokenSetup`] screen (connect mode).
    auth_token_input: Input,
    /// Resolved credential, carried to `Done`.
    auth_token: Option<String>,
    token_generated: bool,
    /// Quick mode: whether the chosen signaling is the rotating nostr PIN (`true`) or
    /// manual copy-paste (`false`). Set when the user activates a choice; ignored in
    /// connect mode.
    quick_pin: bool,
    /// Inline error from the last failed validation; cleared on the next keypress.
    error: Option<String>,
}

impl SetupState {
    pub fn new(
        config_auth_token: Option<String>,
        expected_token_fingerprint: Option<String>,
        nostr_discovery: bool,
        own_name: Option<String>,
    ) -> Self {
        Self {
            phase: SetupPhase::Start,
            config_auth_token,
            expected_token_fingerprint,
            // Connect mode's primary action is Start; quick mode leads with the PIN choice.
            focus: if nostr_discovery {
                StartFocus::Start
            } else {
                StartFocus::PinStart
            },
            nostr_discovery,
            own_name,
            auth_token_input: Input::default(),
            auth_token: None,
            token_generated: false,
            // Quick mode defaults to the rotating-PIN flow (the headline option).
            quick_pin: true,
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
        state.error = Some("Enter the shared auth token.".to_string());
        return Step::Continue;
    }
    if let Err(e) = auth::validate_token(&token) {
        state.error = Some(format!("Invalid token: {e}"));
        return Step::Continue;
    }
    // In connect mode the config declares the expected fingerprint; a token for a
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
        // Quick mode only; connect mode never sets a PIN choice and ignores this.
        quick_pin: !state.nostr_discovery && state.quick_pin,
    }
}

/// The focusable buttons on the start screen, in cycle order. Connect mode confirms with
/// a single Start; quick mode leads with the two signaling choices.
fn start_ring(nostr_discovery: bool) -> &'static [StartFocus] {
    if nostr_discovery {
        &[StartFocus::Start, StartFocus::Exit]
    } else {
        &[StartFocus::PinStart, StartFocus::ManualStart, StartFocus::Exit]
    }
}

fn next_start_focus(cur: StartFocus, nostr_discovery: bool) -> StartFocus {
    let ring = start_ring(nostr_discovery);
    let i = ring.iter().position(|f| *f == cur).unwrap_or(0);
    ring[(i + 1) % ring.len()]
}

fn prev_start_focus(cur: StartFocus, nostr_discovery: bool) -> StartFocus {
    let ring = start_ring(nostr_discovery);
    let i = ring.iter().position(|f| *f == cur).unwrap_or(0);
    ring[(i + ring.len() - 1) % ring.len()]
}

/// Start quick mode with the chosen signaling. Quick mode always mints a fresh ephemeral
/// token; PIN mode delivers it to the dialer over nostr, manual mode surfaces it in the
/// dashboard to copy.
fn start_quick(state: &mut SetupState, pin: bool) -> Step {
    state.quick_pin = pin;
    let token = state
        .config_auth_token
        .clone()
        .unwrap_or_else(auth::generate_token);
    let generated = state.config_auth_token.is_none();
    finalize(state, token, generated)
}

/// Submit the connect-mode start screen: finish with a config/env token, or open the
/// token-entry screen when none is supplied. (Quick mode starts via [`start_quick`].)
fn submit_start(state: &mut SetupState) -> Step {
    if let Some(token) = state.config_auth_token.clone() {
        // A config/env token is used as-is, no further prompt.
        finalize(state, token, false)
    } else {
        // No token supplied: the connect-mode token is a pre-shared secret, so it must be
        // entered on the token screen. Quick mode never reaches here — it is only called
        // from `StartFocus::Start`, which exists only in the connect-mode focus ring;
        // quick mode starts via `start_quick`.
        state.phase = SetupPhase::TokenSetup;
        Step::Continue
    }
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
            // Enter activates the focused button. Connect mode: Start submits. Quick mode:
            // each signaling choice both picks the mode and starts. Exit quits in either.
            KeyCode::Enter => match state.focus {
                StartFocus::Exit => Step::Quit,
                StartFocus::Start => submit_start(state),
                StartFocus::PinStart => start_quick(state, true),
                StartFocus::ManualStart => start_quick(state, false),
            },
            // Arrow keys / Tab cycle the focus ring (its members depend on the mode).
            KeyCode::Left | KeyCode::Up | KeyCode::BackTab => {
                state.focus = prev_start_focus(state.focus, state.nostr_discovery);
                Step::Continue
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Tab => {
                state.focus = next_start_focus(state.focus, state.nostr_discovery);
                Step::Continue
            }
            _ => Step::Continue,
        },
        // Connect-only: a single entry field for the pre-shared token.
        SetupPhase::TokenSetup => match key.code {
            KeyCode::Esc => {
                state.phase = SetupPhase::Start;
                Step::Continue
            }
            KeyCode::Enter => submit_token(state),
            // Every other key (Left/Right cursor moves, backspace, paste, characters)
            // edits the input.
            _ => {
                handle_edit(&mut state.auth_token_input, key, is_token_char);
                Step::Continue
            }
        },
    }
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
    let area = centered(frame.area(), 84, setup_panel_height(state));
    let panel = Block::default().borders(Borders::ALL).title(" setup ");
    frame.render_widget(panel, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    let [title_area, body_area, footer_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(inner);

    render_setup_title(frame, title_area, state);
    match state.phase {
        SetupPhase::Start => render_start_phase(frame, body_area, state),
        SetupPhase::TokenSetup => render_token_phase(frame, body_area, state),
    }
    render_setup_footer(frame, footer_area, state);
}

fn setup_panel_height(state: &SetupState) -> u16 {
    let body = match state.phase {
        SetupPhase::Start => start_summary_lines(state).len() as u16 + error_height(state),
        SetupPhase::TokenSetup => {
            token_intro_lines(state).len() as u16
                + 1
                + INPUT_FIELD_HEIGHT
                + u16::from(token_fingerprint_line(state).is_some())
                + 1
                + 2
                + error_height(state)
        }
    };
    // Outer border + title area + body + footer.
    2 + 2 + body + 1
}

fn error_height(state: &SetupState) -> u16 {
    if state.error.is_some() { 2 } else { 0 }
}

fn render_setup_title(frame: &mut Frame, area: Rect, state: &SetupState) {
    render_lines(
        frame,
        area,
        vec![
            Line::from(Span::styled(
                format!(
                    "duopipe v{} — {} setup",
                    env!("CARGO_PKG_VERSION"),
                    if state.nostr_discovery { "connect" } else { "quick" }
                ),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
        ],
    );
}

fn render_start_phase(frame: &mut Frame, area: Rect, state: &SetupState) {
    let summary = start_summary_lines(state);
    let mut constraints = vec![Constraint::Length(summary.len() as u16)];
    if state.error.is_some() {
        constraints.extend([Constraint::Length(1), Constraint::Length(1)]);
    }
    constraints.push(Constraint::Min(0));

    let chunks = Layout::vertical(constraints).split(area);
    render_lines(frame, chunks[0], summary);

    render_error_if_any(frame, &chunks, 1, state.error.as_deref());
}

fn render_token_phase(frame: &mut Frame, area: Rect, state: &SetupState) {
    let intro = token_intro_lines(state);
    let fingerprint = token_fingerprint_line(state);
    let mut constraints = vec![
        Constraint::Length(intro.len() as u16),
        Constraint::Length(1),
        Constraint::Length(INPUT_FIELD_HEIGHT),
    ];
    if fingerprint.is_some() {
        constraints.push(Constraint::Length(1));
    }
    constraints.extend([Constraint::Length(1), Constraint::Length(2)]);
    if state.error.is_some() {
        constraints.extend([Constraint::Length(1), Constraint::Length(1)]);
    }
    constraints.push(Constraint::Min(0));

    let chunks = Layout::vertical(constraints).split(area);
    let mut i = 0;
    render_lines(frame, chunks[i], intro);
    i += 1;
    i += 1; // spacer between the intro text and the field
    render_input_field(frame, chunks[i], "Auth token", &state.auth_token_input, true);
    i += 1;
    if let Some(line) = fingerprint {
        render_line(frame, chunks[i], line);
        i += 1;
    }
    i += 1; // spacer before the mode-specific hint
    render_line(
        frame,
        chunks[i],
        Line::from(Span::styled(
            token_hint(),
            Style::default().fg(Color::DarkGray),
        )),
    );
    i += 1;

    render_error_if_any(frame, &chunks, i, state.error.as_deref());
}

fn start_summary_lines(state: &SetupState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("This instance will always listen for peers.")];
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
    lines.push(Line::raw(""));

    if state.nostr_discovery {
        // Connect mode: a single confirm action.
        lines.push(Line::from(vec![
            button_span("Start", state.focus == StartFocus::Start),
            Span::raw("  "),
            button_span("Exit", state.focus == StartFocus::Exit),
        ]));
    } else {
        // Quick mode: pick how to share this device with the dialer. Each choice both
        // selects the signaling and starts.
        lines.push(Line::from("Choose how to share this device:"));
        lines.push(Line::from(button_span(
            "Start with PIN",
            state.focus == StartFocus::PinStart,
        )));
        lines.push(Line::from(Span::styled(
            "  shows a short code that refreshes every 60s (over nostr; needs internet).",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(button_span(
            "Start manual",
            state.focus == StartFocus::ManualStart,
        )));
        lines.push(Line::from(Span::styled(
            "  copy the node id + auth token by hand (no nostr/internet).",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::raw(""));
        lines.push(Line::from(button_span("Exit", state.focus == StartFocus::Exit)));
    }
    lines
}

/// Intro lines for the connect-mode token-entry screen. (Quick mode never shows this screen.)
fn token_intro_lines(state: &SetupState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("Enter the shared auth token:")];
    // The config declares the token's fingerprint; show it before submit.
    if let Some(expected) = &state.expected_token_fingerprint {
        lines.push(Line::from(Span::styled(
            format!("  expected fingerprint: {expected} — your token must match this"),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines
}

fn token_fingerprint_line(state: &SetupState) -> Option<Line<'static>> {
    let typed = state.auth_token_input.value().trim();
    if typed.is_empty() || auth::validate_token(typed).is_err() {
        return None;
    }

    let fp = auth::token_fingerprint(typed);
    let span = match &state.expected_token_fingerprint {
        Some(expected) if auth::fingerprint_matches(typed, expected) => Span::styled(
            format!("fingerprint: {fp} ✓ matches the config"),
            Style::default().fg(Color::Green),
        ),
        Some(expected) => Span::styled(
            format!("fingerprint: {fp} ✗ does not match the config ({expected})"),
            Style::default().fg(Color::Red),
        ),
        None => Span::styled(
            format!("fingerprint: {fp} — confirm this matches your other device"),
            Style::default().fg(Color::Green),
        ),
    };
    Some(Line::from(span))
}

/// Hint for the connect-mode token-entry screen. The token is a pre-shared secret made out
/// of band, the same on every device.
fn token_hint() -> &'static str {
    "Both peers need the same token. First time? Run `duopipe generate-auth-token`, then paste that token here on every device."
}

fn render_setup_footer(frame: &mut Frame, area: Rect, state: &SetupState) {
    let footer = match state.phase {
        SetupPhase::Start => "↑/↓ ←/→ move · Enter select · Esc / Ctrl-C quit",
        SetupPhase::TokenSetup => "Enter confirm · Esc back · Ctrl-C quit",
    };
    render_line(
        frame,
        area,
        Line::from(Span::styled(footer, Style::default().fg(Color::DarkGray))),
    );
}

fn render_error_if_any(
    frame: &mut Frame,
    chunks: &[Rect],
    index: usize,
    error: Option<&str>,
) {
    let Some(err) = error else {
        return;
    };
    render_line(
        frame,
        chunks[index + 1],
        Line::from(Span::styled(err.to_string(), Style::default().fg(Color::Red))),
    );
}

fn render_line(frame: &mut Frame, area: Rect, line: Line<'static>) {
    render_lines(frame, area, vec![line]);
}

fn render_lines(frame: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
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
    fn start_with_config_token_finishes_as_both() {
        let token = auth::generate_token();
        let mut s = SetupState::new(Some(token.clone()), None, true, Some("hl".into()));
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert!(r.peer_node_id.is_none());
                assert!(r.peer_identifier.is_none());
                assert!(!r.token_generated);
                assert_eq!(r.auth_token, token);
            }
            _ => panic!("expected Done(Both)"),
        }
    }

    #[test]
    fn quick_start_generates_token_directly() {
        // Quick mode: the PIN choice is focused first; pressing Enter generates a fresh
        // token, selects PIN signaling, and finishes immediately (no token-choice screen).
        let mut s = SetupState::new(None, None, false, None);
        assert_eq!(s.focus, StartFocus::PinStart);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert_eq!(r.role, Role::Both);
                assert!(r.token_generated);
                assert!(r.quick_pin, "PIN choice selects nostr signaling");
                assert!(auth::validate_token(&r.auth_token).is_ok());
            }
            _ => panic!("expected Done(Both) with a generated token"),
        }
    }

    #[test]
    fn quick_manual_choice_disables_pin() {
        // Tab to the manual choice and start: a fresh token is generated, PIN off.
        let mut s = SetupState::new(None, None, false, None);
        handle_key(key(KeyCode::Tab), &mut s);
        assert_eq!(s.focus, StartFocus::ManualStart);
        match handle_key(key(KeyCode::Enter), &mut s) {
            Step::Done(r) => {
                assert!(r.token_generated);
                assert!(!r.quick_pin, "manual choice uses copy-paste, not nostr");
            }
            _ => panic!("expected Done(Both) in manual mode"),
        }
    }

    #[test]
    fn nostr_without_token_opens_entry_field() {
        // Connect mode's token is a pre-shared secret, so Start opens the entry field.
        let token = auth::generate_token();
        let mut s = SetupState::new(None, None, true, Some("hl".into()));
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::TokenSetup);
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
        // A connect-mode config declares the expected fingerprint; pasting a token from a
        // different pairing is rejected with an inline error rather than accepted.
        let intended = auth::generate_token();
        let other = auth::generate_token();
        let expected = auth::token_fingerprint(&intended);
        let mut s = SetupState::new(None, Some(expected.clone()), true, Some("hl".into()));
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
        let mut s = SetupState::new(None, Some(expected), true, Some("hl".into()));
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
        let mut s = SetupState::new(None, Some(expected.clone()), true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup

        // Before typing: the expected fingerprint is shown up front.
        let empty = render_text(&s);
        assert!(empty.contains("expected fingerprint:"));
        assert!(empty.contains(&expected));

        // A matching token reports ✓; a different one reports ✗.
        type_str(&mut s, &token);
        assert!(render_text(&s).contains('✓'));

        let other = auth::generate_token();
        let mut mismatch = SetupState::new(None, Some(expected), true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut mismatch);
        type_str(&mut mismatch, &other);
        assert!(render_text(&mismatch).contains('✗'));
    }

    #[test]
    fn token_setup_esc_returns_to_start() {
        // Connect mode: Esc from the token-entry screen returns to the start screen.
        let mut s = SetupState::new(None, None, true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut s);
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        handle_key(key(KeyCode::Esc), &mut s);
        assert_eq!(s.phase, SetupPhase::Start);
    }

    #[test]
    fn enter_token_rejects_invalid_and_stays_open() {
        // Connect mode: an invalid token keeps the entry screen open with an error.
        let mut s = SetupState::new(None, None, true, Some("hl".into()));
        handle_key(key(KeyCode::Enter), &mut s); // -> TokenSetup (entry field)
        type_str(&mut s, "not-a-real-token");
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Continue));
        assert_eq!(s.phase, SetupPhase::TokenSetup);
        assert!(s.error.is_some());
    }

    #[test]
    fn connect_start_focused_first_and_enter_starts() {
        // Connect mode (with a config token) leads with the Start button.
        let mut s = SetupState::new(Some(auth::generate_token()), None, true, Some("hl".into()));
        assert_eq!(s.focus, StartFocus::Start);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Done(_)));
    }

    #[test]
    fn quick_focus_ring_cycles_and_exit_quits() {
        let mut s = SetupState::new(None, None, false, None);
        // Ring is [PinStart, ManualStart, Exit].
        assert_eq!(s.focus, StartFocus::PinStart);
        handle_key(key(KeyCode::Right), &mut s);
        assert_eq!(s.focus, StartFocus::ManualStart);
        handle_key(key(KeyCode::Right), &mut s);
        assert_eq!(s.focus, StartFocus::Exit);
        // Wraps back to the start of the ring.
        handle_key(key(KeyCode::Right), &mut s);
        assert_eq!(s.focus, StartFocus::PinStart);
        // Left wraps to Exit; Enter there quits.
        handle_key(key(KeyCode::Left), &mut s);
        assert_eq!(s.focus, StartFocus::Exit);
        assert!(matches!(handle_key(key(KeyCode::Enter), &mut s), Step::Quit));
    }

    #[test]
    fn ctrl_c_quits() {
        let mut s = SetupState::new(None, None, false, None);
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(handle_key(k, &mut s), Step::Quit));
    }
}
