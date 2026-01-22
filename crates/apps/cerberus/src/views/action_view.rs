use crate::core::AppState;
use crate::styles::{self};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, StatefulWidget, Widget};

pub struct ActionView;

impl StatefulWidget for ActionView {
	type State = AppState;

	fn render(self, area: Rect, buf: &mut Buffer, _state: &mut Self::State) {
		Block::new().style(Style::default().bg(Color::Black)).render(area, buf);
		let [actions_a] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints(vec![Constraint::Fill(1)])
			.spacing(1)
			.areas(area);

		let line = Line::from(vec![
			Span::raw("["),
			Span::styled("CTRL+C", styles::STL_TXT_ACTION),
			Span::raw("] Quit  "),
			Span::raw("["),
			Span::styled("X", styles::STL_TXT_ACTION),
			Span::raw("] Clear events  "),
			Span::raw("["),
			Span::styled("S", styles::STL_TXT_ACTION),
			Span::raw("] Summary view  "),
		]);

		Paragraph::new(line).render(actions_a, buf);
	}
}
