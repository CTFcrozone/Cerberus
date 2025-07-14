use crate::core::AppState;
use crate::styles::{self, STL_TXT_LBL};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, StatefulWidget, Widget};

pub struct ActionView;

impl StatefulWidget for ActionView {
	type State = AppState;

	fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
		Block::new().style(Style::default().bg(Color::Black)).render(area, buf);
		let [actions_a, mem_lbl_a, mem_val_a] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints(vec![Constraint::Fill(1), Constraint::Length(5), Constraint::Length(10)])
			.spacing(1)
			.areas(area);

		let line = Line::from(vec![
			Span::raw("["),
			Span::styled("CTRL+C", styles::STL_TXT_ACTION),
			Span::raw("] Quit  "),
			Span::raw("["),
			Span::styled("C", styles::STL_TXT_ACTION),
			Span::raw("] Clear events  "),
		]);

		Paragraph::new(line).render(actions_a, buf);

		Paragraph::new("Mem:").right_aligned().style(STL_TXT_LBL).render(mem_lbl_a, buf);
		Paragraph::new(state.memory_fmt())
			.style(styles::STL_TXT_VAL)
			.render(mem_val_a, buf);
	}
}
