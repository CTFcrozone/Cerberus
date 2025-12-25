use crate::core::AppState;
use ratatui::{
	buffer::Buffer,
	layout::Rect,
	text::Line,
	widgets::{Block, Padding, Paragraph, StatefulWidget, Widget},
};

use ratatui::style::{Color, Style};

fn severity_style(sev: &str) -> Style {
	match sev {
		"critical" => Style::default().fg(Color::Red),
		"high" => Style::default().fg(Color::LightRed),
		"medium" => Style::default().fg(Color::Yellow),
		"low" => Style::default().fg(Color::Green),
		_ => Style::default().fg(Color::Gray),
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
		.map(|entry| {
			let style = severity_style(&entry.event.severity);

			Line::styled(
				format!(
					"Rule: {} | Severity: {} | Type: {} | PID: {} | UID: {} | COMM: {}",
					entry.event.rule_id,
					entry.event.severity,
					entry.event.rule_type,
					entry.event.event_meta.pid,
					entry.event.event_meta.uid,
					entry.event.event_meta.comm
				),
				style,
			)
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
