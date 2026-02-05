use ratatui::{
	buffer::Buffer,
	layout::{Constraint, Direction, Layout, Rect},
	style::{Color, Style},
	widgets::{BarChart, Block, Paragraph, StatefulWidget, Widget},
};

use crate::core::AppState;

pub struct SummaryView;

impl StatefulWidget for SummaryView {
	type State = AppState;
	fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
		let [top_row, bottom_row] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
			.areas(area);

		let [rules_area, chart1_area, chart2_area] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([
				Constraint::Percentage(20),
				Constraint::Percentage(40),
				Constraint::Percentage(40),
			])
			.areas(top_row);

		render_loaded_rules_count(rules_area, buf, state);
		render_rule_type_chart(chart1_area, buf, state);
		render_severity_chart(chart2_area, buf, state);

		let [last_event_area, hooks_area] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
			.areas(bottom_row);

		render_last_event_meta(last_event_area, buf, state);
		render_loaded_hooks(hooks_area, buf, state, Block::bordered().title("Loaded Hooks"));
	}
}

fn render_loaded_hooks(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let hooks = state.loaded_hooks();
	let items: Vec<_> = hooks.iter().map(|hook| hook.as_str()).collect();

	let paragraph = Paragraph::new(items.join("\n"))
		.block(block)
		.style(Style::default().fg(Color::White));
	paragraph.render(area, buf);
}

pub fn render_loaded_rules_count(area: Rect, buf: &mut Buffer, state: &AppState) {
	let count = state.rule_engine.as_ref().map_or(0, |engine| engine.rule_count());

	let paragraph = Paragraph::new(format!("Loaded Rules: {}", count))
		.block(Block::bordered().title("Rules"))
		.style(Style::default().fg(Color::Cyan));

	paragraph.render(area, buf);
}

fn render_last_event_meta(area: Rect, buf: &mut Buffer, state: &AppState) {
	let last_meta = state
		.cerberus_evts_matched()
		.last()
		.map(|evt| {
			format!(
				"Rule: {}\nSeverity: {}\nType: {}\nPID: {} \nUID: {} \nCOMM: {}",
				evt.event.rule_id,
				evt.event.severity,
				evt.event.rule_type,
				evt.event.event_meta.pid,
				evt.event.event_meta.uid,
				evt.event.event_meta.comm
			)
		})
		.unwrap_or("No events yet".to_string());

	let paragraph = Paragraph::new(last_meta)
		.block(Block::bordered().title("Last Event"))
		.style(Style::default().fg(Color::Green));

	paragraph.render(area, buf);
}

fn render_severity_chart(area: Rect, buf: &mut Buffer, state: &AppState) {
	let data = state.barchart_severity();

	let chart = BarChart::default()
		.block(Block::bordered().title("Detections by Severity"))
		.data(&data)
		.bar_width(8)
		.bar_gap(2)
		.bar_style(Style::default().fg(Color::Yellow))
		.value_style(Style::default().fg(Color::White))
		.label_style(Style::default().fg(Color::Gray));

	chart.render(area, buf);
}

fn render_rule_type_chart(area: Rect, buf: &mut Buffer, state: &AppState) {
	let data = state.barchart_rule_type();

	let chart = BarChart::default()
		.block(Block::bordered().title("Detections by Rule Type"))
		.data(&data)
		.bar_width(8)
		.bar_gap(2)
		.bar_style(Style::default().fg(Color::Red))
		.value_style(Style::default().fg(Color::White))
		.label_style(Style::default().fg(Color::Gray));

	chart.render(area, buf);
}
