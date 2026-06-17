use crate::core::AppState;
use lib_rules::CorrelationEvent;
use ratatui::style::{Color, Style};
use ratatui::text::Span;
use ratatui::widgets::Wrap;
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
	let mut groups = state.correlated_groups();

	groups.sort_by(|a, b| a.root_rule_id.cmp(&b.root_rule_id).then(a.seq_id.cmp(&b.seq_id)));

	let mut lines: Vec<Line> = Vec::new();

	for (group_idx, group) in groups.iter().enumerate() {
		let is_selected = group_idx == state.selected_rule();

		let expanded = state.is_correlation_expanded(&group.root_rule_id, &group.seq_id);

		let icon = if expanded { "▼" } else { "▶" };

		let header_style = if is_selected {
			Style::default().fg(Color::Cyan).bg(Color::DarkGray)
		} else {
			Style::default().fg(Color::Gray)
		};

		lines.push(Line::styled(
			format!("{icon} {} :: {}", group.root_rule_id, group.seq_id),
			header_style,
		));

		if !expanded {
			continue;
		}

		let mut events = group.events.clone();
		events.sort_by(|a, b| {
			let rank = |e: &CorrelationEvent| match e {
				CorrelationEvent::Step { step_idx, .. } => *step_idx as i32,
				CorrelationEvent::Completed { .. } => i32::MAX,
			};

			rank(a).cmp(&rank(b))
		});

		for evt in events {
			match evt {
				CorrelationEvent::Step {
					step_idx,
					matched_rule_id,
					..
				} => {
					let idx = format!("[{}]", step_idx + 1);

					lines.push(Line::from(vec![
						Span::styled("   │ ", Style::default().fg(Color::DarkGray)),
						Span::styled(idx, Style::default().fg(Color::Gray)),
						Span::raw(" "),
						Span::styled(matched_rule_id.to_string(), Style::default().fg(Color::White)),
						Span::styled(" ✓", Style::default().fg(Color::DarkGray)),
					]));
				}

				CorrelationEvent::Completed { steps, path, .. } => {
					lines.push(Line::from(vec![
						Span::styled("   └─ ", Style::default().fg(Color::DarkGray)),
						Span::styled(format!("completed ({steps} steps)"), Style::default().fg(Color::Cyan)),
					]));

					lines.push(Line::from(vec![
						Span::raw("      "),
						Span::styled(
							path.iter().map(|p| p.as_ref()).collect::<Vec<_>>().join(" → "),
							Style::default().fg(Color::DarkGray),
						),
					]));
				}
			}
		}

		lines.push(Line::from(""));
	}

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
		let mut text = vec![];

		match event {
			CorrelationEvent::Step {
				root_rule_id,
				seq_id,
				step_idx,
				matched_rule_id,
				..
			} => {
				text.push(Line::from(format!("Root: {}", root_rule_id)));
				text.push(Line::from(format!("Sequence: {}", seq_id)));
				text.push(Line::from(""));
				text.push(Line::from(format!("Step: {}", step_idx + 1)));
				text.push(Line::from(format!("Rule: {}", matched_rule_id)));
			}

			CorrelationEvent::Completed {
				root_rule_id,
				seq_id,
				steps,
				path,
				..
			} => {
				text.push(Line::from(format!("Root: {}", root_rule_id)));
				text.push(Line::from(format!("Sequence: {}", seq_id)));
				text.push(Line::from(""));
				text.push(Line::from(format!("Steps: {}", steps)));
				text.push(Line::from("Path:"));
				text.push(Line::from(
					path.iter().map(|p| p.as_ref()).collect::<Vec<_>>().join(" → "),
				));
			}
		}

		let popup = Paragraph::new(text)
			.block(Block::bordered().title("Correlation Details"))
			.wrap(Wrap { trim: true });

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
