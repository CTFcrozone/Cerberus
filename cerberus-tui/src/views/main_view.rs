use crate::views::ActionView;
use ratatui::{
	layout::{Constraint, Direction, Layout},
	style::{Color, Style},
	widgets::{Block, Paragraph, StatefulWidget, Widget},
};

use crate::{core::AppState, styles};

use super::{EventView, LoadedHooksView};

pub struct MainView;

impl StatefulWidget for MainView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		Block::new()
			.style(Style::default().bg(styles::CLR_BKG_GRAY_DARKER))
			.render(area, buf);

		let [header, main, sys_info] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)])
			.areas(area);

		let title_block = Block::bordered()
			.style(Style::default().fg(Color::Reset))
			.title_alignment(ratatui::layout::Alignment::Center);

		let title = Paragraph::new("[Cerberus]")
			.style(Style::default().fg(Color::LightGreen))
			.alignment(ratatui::layout::Alignment::Center)
			.block(title_block);

		title.render(header, buf);

		let [events_tbl, meta] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
			.areas(main);

		let center = EventView {};
		center.render(events_tbl, buf, state);

		let right = LoadedHooksView {};
		right.render(meta, buf, state);

		let action_v = ActionView {};
		action_v.render(sys_info, buf, state);
	}
}
