use crate::core::AppState;
use lib_rules::Severity;
use ratatui::{
	buffer::Buffer,
	layout::{Constraint, Flex, Layout, Rect},
	text::Line,
	widgets::{Block, Clear, Padding, Paragraph, StatefulWidget, Widget},
};

use ratatui::style::{Color, Style};

fn severity_style(sev: Severity) -> Style {
	match sev {
		Severity::Critical => Style::default().fg(Color::Rgb(255, 64, 64)),

		Severity::High => Style::default().fg(Color::Rgb(255, 140, 0)),

		Severity::Medium => Style::default().fg(Color::Rgb(255, 215, 0)),

		Severity::Low => Style::default().fg(Color::Rgb(80, 200, 120)),

		Severity::VeryLow => Style::default().fg(Color::Rgb(120, 220, 160)),

		Severity::Info => Style::default().fg(Color::Rgb(100, 180, 255)),
	}
}

pub struct EvaluatedEventView;

impl StatefulWidget for EvaluatedEventView {
	type State = AppState;

	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		let show_hooks = state.cerberus_evts_matched().next().is_some();

		let block = Block::bordered().padding(Padding::left(1));

		if !show_hooks {
			let p = Paragraph::new("No events yet").block(block);
			p.render(area, buf);
		} else {
			render_evaluated_events(area, buf, state, block);
		}
	}
}

fn render_evaluated_events(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let lines: Vec<Line> = state
		.cerberus_evts_matched()
		.enumerate()
		.map(|(idx, entry)| {
			let mut style = severity_style(entry.event.severity);

			if idx == state.selected_rule() {
				style = style.bg(Color::DarkGray);
			}

			Line::styled(format!("[{}x] Rule: {}", entry.count, entry.event.rule_id,), style)
		})
		.collect();

	let line_count = lines.len();
	let max_scroll = line_count.saturating_sub(area.height as usize) as u16;

	if state.event_scroll() > max_scroll {
		state.set_event_scroll(max_scroll);
	}

	let paragraph = Paragraph::new(lines).block(block).scroll((state.event_scroll(), 0));
	paragraph.render(area, buf);
}

pub fn render_rule_popup(frame: &mut ratatui::Frame, state: &AppState) {
	if !state.popup_show {
		return;
	}

	let area = popup_area(frame.area(), 60, 40);
	frame.render_widget(Clear, area);

	let selected = state.cerberus_evts_matched().nth(state.selected_rule());

	if let Some(entry) = selected {
		let text = vec![
			Line::from(format!("Rule ID: {}", entry.event.rule_id)),
			Line::from(format!("Severity: {}", entry.event.severity.as_str())),
			Line::from(format!("Type: {}", entry.event.rule_type)),
			Line::from(format!("Matches: {}", entry.count)),
			Line::from(""),
			Line::from(format!("Hash: {}", entry.event.rule_hash)),
		];

		let popup = Paragraph::new(text)
			.block(Block::bordered().title("Rule Details"))
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
