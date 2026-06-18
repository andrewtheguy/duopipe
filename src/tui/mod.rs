//! Terminal UI for monitoring a running peer.
//!
//! Runs as a sibling task to the peer runtime, polling [`AppState`] on a tick and
//! handling keyboard input. `q`/`Ctrl-C` cancels the shared shutdown token, which
//! both ends this loop and stops the runtime.

mod ui;

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ratatui::crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app_state::AppState;
use ui::UiState;

/// Refresh interval for the render tick (also bounds key-input latency).
const TICK: Duration = Duration::from_millis(200);

/// Run the TUI until the user quits or the shutdown token is cancelled.
///
/// Initializes the terminal (raw mode + alternate screen + panic hook) and
/// restores it on exit.
pub async fn run_tui(state: Arc<AppState>) {
    let mut terminal = ratatui::init();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    let mut ui_state = UiState::default();

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = state.snapshot();
                let logs = state.logs.snapshot();
                let _ = terminal.draw(|f| ui::render(f, &snap, &logs, &ui_state));
            }
            maybe = events.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        if handle_key(key, &mut ui_state, &state) {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            _ = state.shutdown.cancelled() => break,
        }
    }

    ratatui::restore();
}

/// Handle a key press. Returns `true` when the UI should exit.
fn handle_key(key: KeyEvent, ui: &mut UiState, state: &Arc<AppState>) -> bool {
    let total = state.logs.len();
    match key.code {
        KeyCode::Char('q') => {
            state.shutdown.cancel();
            return true;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.shutdown.cancel();
            return true;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            ui.log_scroll = ui.log_scroll.saturating_add(1).min(total);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            ui.log_scroll = ui.log_scroll.saturating_sub(1);
        }
        KeyCode::PageUp => {
            ui.log_scroll = ui.log_scroll.saturating_add(10).min(total);
        }
        KeyCode::PageDown => {
            ui.log_scroll = ui.log_scroll.saturating_sub(10);
        }
        KeyCode::Char('g') => ui.log_scroll = total,
        KeyCode::Char('G') => ui.log_scroll = 0,
        _ => {}
    }
    false
}
