use crate::views::ActionView;
use ratatui::{
	layout::{Constraint, Direction, Layout},
	style::{Color, Style},
	widgets::{Block, Paragraph, StatefulWidget, Widget},
};

use crate::{core::AppState, styles};

use super::{splash_view::SplashView, EventView, LoadedHooksView};

pub struct MainView;

impl StatefulWidget for MainView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		Block::new()
			.style(Style::default().bg(styles::CLR_BKG_GRAY_DARKER))
			.render(area, buf);

		if !state.worker_up() {
			let splash = SplashView {};
			splash.render(area, buf, state);
			return;
		}
		let [main, sys_info] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Min(10), Constraint::Length(1)])
			.areas(area);

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
