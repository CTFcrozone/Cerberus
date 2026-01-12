use crate::views::{correlated_event_view::CorrelatedEventView, ActionView};
use ratatui::{
	buffer::Buffer,
	layout::{Constraint, Direction, Layout, Rect},
	style::Style,
	widgets::{Block, Paragraph, StatefulWidget, Widget},
};

use crate::{core::AppState, styles};

use super::{EvaluatedEventView, GeneralEventView, LoadedHooksView, NetworkEventView};

pub struct MainView;

impl StatefulWidget for MainView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		Block::new()
			.style(Style::default().bg(styles::CLR_BKG_GRAY_DARKER))
			.render(area, buf);

		let [tabs_area, main, sys_info] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([
				Constraint::Length(1), // Tabs area
				Constraint::Min(10),   // Main content
				Constraint::Length(1), // Action view
			])
			.areas(area);

		render_tabs(tabs_area, buf, state);

		let [events_tbl, meta] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
			.areas(main);

		match state.current_tab() {
			crate::core::Tab::General => GeneralEventView {}.render(events_tbl, buf, state),
			crate::core::Tab::Network => NetworkEventView {}.render(events_tbl, buf, state),
			crate::core::Tab::MatchedRules => EvaluatedEventView {}.render(events_tbl, buf, state),
			crate::core::Tab::CorrelatedRules => CorrelatedEventView {}.render(events_tbl, buf, state),
		}

		let right = LoadedHooksView {};
		right.render(meta, buf, state);

		let action_v = ActionView {};
		action_v.render(sys_info, buf, state);
	}
}

fn render_tabs(area: Rect, buf: &mut Buffer, state: &AppState) {
	let [_, tab_general_a, _, tab_network_a, _, tab_evaluated_a, _, tabs_correlated_a] = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Length(1),
			Constraint::Length(11),
			Constraint::Length(2),
			Constraint::Length(11),
			Constraint::Length(2),
			Constraint::Length(17),
			Constraint::Length(2),
			Constraint::Length(17),
		])
		.areas(area);

	let current_tab = state.current_tab();

	let tab_general_style = if current_tab.as_index() == 0 {
		styles::STL_TAB_ACTIVE
	} else {
		styles::STL_TAB_DEFAULT
	};

	let tab_network_style = if current_tab.as_index() == 1 {
		styles::STL_TAB_ACTIVE
	} else {
		styles::STL_TAB_DEFAULT
	};

	let tab_eval_style = if current_tab.as_index() == 2 {
		styles::STL_TAB_ACTIVE
	} else {
		styles::STL_TAB_DEFAULT
	};

	let tab_correlated_style = if current_tab.as_index() == 3 {
		styles::STL_TAB_ACTIVE
	} else {
		styles::STL_TAB_DEFAULT
	};

	Paragraph::new("General")
		.centered()
		.style(tab_general_style)
		.render(tab_general_a, buf);

	Paragraph::new("Network")
		.centered()
		.style(tab_network_style)
		.render(tab_network_a, buf);

	Paragraph::new("Matched rules")
		.centered()
		.style(tab_eval_style)
		.render(tab_evaluated_a, buf);

	Paragraph::new("Correlated rules")
		.centered()
		.style(tab_correlated_style)
		.render(tabs_correlated_a, buf);
}
