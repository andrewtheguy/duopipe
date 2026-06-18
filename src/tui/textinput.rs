//! Shared single-line text-input helpers built on [`tui_input::Input`].
//!
//! `Input` already tracks a cursor and understands cursor movement (arrows,
//! Home/End, word jumps) and the usual Emacs-style editing shortcuts. We add two
//! things on top: per-field character filtering (node ids reject spaces, CIDR
//! entry allows them, etc.) and a span renderer that draws a block cursor at the
//! cursor position so editing mid-string is visible.

use ratatui::crossterm::event::{Event, KeyEvent};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use tui_input::backend::crossterm::to_input_request;
use tui_input::{Input, InputRequest};

/// Apply a key press to `input`, dropping inserted characters that `accept`
/// rejects. Cursor movement and deletion always pass through.
pub fn handle_edit(input: &mut Input, key: KeyEvent, accept: impl Fn(char) -> bool) {
    let Some(req) = to_input_request(&Event::Key(key)) else {
        return;
    };
    if let InputRequest::InsertChar(c) = req
        && !accept(c)
    {
        return;
    }
    input.handle(req);
}

/// Render `input`'s value as styled spans with a reversed block cursor at the
/// cursor position. `style` colors the text; the cursor cell adds REVERSED so it
/// shows even mid-string (and as a solid block past the end).
pub fn render_spans(input: &Input, style: Style) -> Vec<Span<'static>> {
    let cursor_style = style.add_modifier(Modifier::REVERSED | Modifier::SLOW_BLINK);
    let chars: Vec<char> = input.value().chars().collect();
    let cursor = input.cursor().min(chars.len());

    let mut spans = Vec::new();
    if cursor > 0 {
        spans.push(Span::styled(chars[..cursor].iter().collect::<String>(), style));
    }
    if cursor < chars.len() {
        spans.push(Span::styled(chars[cursor].to_string(), cursor_style));
        if cursor + 1 < chars.len() {
            spans.push(Span::styled(
                chars[cursor + 1..].iter().collect::<String>(),
                style,
            ));
        }
    } else {
        // Cursor at end: a reversed space reads as a trailing block cursor.
        spans.push(Span::styled(" ".to_string(), cursor_style));
    }
    spans
}
