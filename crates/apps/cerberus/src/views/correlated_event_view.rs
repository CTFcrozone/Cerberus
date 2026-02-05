use crate::core::AppState;
use ratatui::style::{Color, Style};
use ratatui::{
	buffer::Buffer,
	layout::{Constraint, Flex, Layout, Rect},
	text::Line,
	widgets::{Block, Clear, Padding, Paragraph, StatefulWidget, Widget},
};

pub struct CorrelatedEventView;

impl StatefulWidget for CorrelatedEventView {
	type State = AppState;

	fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
		let has_events = state.cerberus_evts_correlated().next().is_some();

		let block = Block::bordered().padding(Padding::left(1));

		if !has_events {
			Paragraph::new("No correlated events yet").block(block).render(area, buf);
		} else {
			render_correlated_events(area, buf, state, block);
		}
	}
}

fn render_correlated_events(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let lines: Vec<Line> = state
		.cerberus_evts_correlated()
		.enumerate()
		.map(|(idx, event)| {
			let mut style = Style::default().fg(Color::Cyan);

			if idx == state.selected_rule() {
				style = style.bg(Color::DarkGray);
			}

			Line::styled(
				format!("Correlation: {} -> {}", event.base_rule_id, event.seq_rule_id),
				style,
			)
		})
		.collect();

	let line_count = lines.len();
	let max_scroll = line_count.saturating_sub(area.height as usize) as u16;

	if state.event_scroll() > max_scroll {
		state.set_event_scroll(max_scroll);
	}

	Paragraph::new(lines)
		.block(block)
		.scroll((state.event_scroll(), 0))
		.render(area, buf);
}

pub fn render_correlation_popup(frame: &mut ratatui::Frame, state: &AppState) {
	if !state.popup_show {
		return;
	}

	let area = popup_area(frame.area(), 60, 40);
	frame.render_widget(Clear, area);

	let selected = state.cerberus_evts_correlated().nth(state.selected_rule());

	if let Some(event) = selected {
		let text = vec![
			Line::from(format!("Base Rule ID: {}", event.base_rule_id)),
			Line::from(format!("Base Rule Hash: {}", event.base_rule_hash)),
			Line::from(""),
			Line::from(format!("Sequence Rule ID: {}", event.seq_rule_id)),
			Line::from(format!("Sequence Rule Hash: {}", event.seq_rule_hash)),
			Line::from(""),
			Line::from(format!("Event PID: {}", event.event_meta.pid)),
			Line::from(format!("Event UID: {}", event.event_meta.uid)),
			Line::from(format!("Command: {}", event.event_meta.comm)),
		];

		let popup = Paragraph::new(text)
			.block(Block::bordered().title("Correlation Details"))
			.wrap(ratatui::widgets::Wrap { trim: true });

		frame.render_widget(popup, area);
	}
}

fn popup_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
	let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
	let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
	let [area] = vertical.areas(area);
	let [area] = horizontal.areas(area);
	area
}
