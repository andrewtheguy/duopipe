//! Shared single-line text-input helpers built on [`tui_input::Input`].
//!
//! `Input` already tracks a cursor and understands cursor movement (arrows,
//! Home/End, word jumps) and the usual Emacs-style editing shortcuts. We add
//! per-field character filtering (node ids reject spaces, CIDR entry allows
//! them, etc.) and a standard bordered text-field renderer.

use ratatui::Frame;
use ratatui::crossterm::event::{Event, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use tui_input::backend::crossterm::to_input_request;
use tui_input::{Input, InputRequest};

/// Height of every single-line input field, including the surrounding border.
pub const INPUT_FIELD_HEIGHT: u16 = 3;

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

/// Render `input` as a standard single-line text field with a rectangular border.
/// The real terminal cursor is placed inside the active field, so `_` is rendered
/// as normal input text rather than being confused with placeholder underlines.
pub fn render_input_field(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    input: &Input,
    active: bool,
) {
    let border_style = if active {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let title_style = if active {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let text_style = if active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Gray)
    };

    let inner_width = area.width.saturating_sub(2) as usize;
    let (visible, cursor_x) = visible_text(input, inner_width);
    let title = Line::from(Span::styled(format!(" {title} "), title_style));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);
    let para = Paragraph::new(Line::from(Span::styled(visible, text_style))).block(block);
    frame.render_widget(para, area);

    if active && inner_width > 0 && area.height >= INPUT_FIELD_HEIGHT {
        frame.set_cursor_position((area.x + 1 + cursor_x, area.y + 1));
    }
}

fn visible_text(input: &Input, width: usize) -> (String, u16) {
    if width == 0 {
        return (String::new(), 0);
    }

    let chars: Vec<char> = input.value().chars().collect();
    let cursor = input.cursor().min(chars.len());
    let cursor_room = width.saturating_sub(1);
    let start = cursor.saturating_sub(cursor_room);
    let visible = chars.iter().skip(start).take(width).collect::<String>();
    let cursor_x = (cursor - start).min(width.saturating_sub(1)) as u16;
    (visible, cursor_x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_text(input: &Input) -> String {
        let mut terminal = Terminal::new(TestBackend::new(32, 5)).expect("test terminal");
        terminal
            .draw(|frame| {
                render_input_field(
                    frame,
                    Rect::new(1, 1, 30, INPUT_FIELD_HEIGHT),
                    "Peer",
                    input,
                    true,
                );
            })
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

    #[test]
    fn visible_text_keeps_underscores_as_content() {
        let input = Input::new("peer_name_1".to_string());

        assert_eq!(visible_text(&input, 20), ("peer_name_1".to_string(), 11));
    }

    #[test]
    fn visible_text_scrolls_to_keep_end_cursor_inside_field() {
        let input = Input::new("abcdefghijklmnopqrstuvwxyz".to_string());

        assert_eq!(visible_text(&input, 8), ("tuvwxyz".to_string(), 7));
    }

    #[test]
    fn rendered_field_uses_box_without_placeholder_underscores() {
        let text = render_text(&Input::new("peer_name".to_string()));

        assert!(text.contains("Peer"));
        assert!(text.contains("peer_name"));
        assert!(text.contains("┌"));
        assert!(!text.contains("__"));
    }
}
