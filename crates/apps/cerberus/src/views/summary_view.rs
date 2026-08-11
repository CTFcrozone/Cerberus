use ratatui::{
	buffer::Buffer,
	layout::{Constraint, Direction, Layout, Rect},
	style::{Color, Modifier, Style},
	text::{Line, Span},
	widgets::{BarChart, Block, Paragraph, StatefulWidget, Widget},
};

use crate::{
	core::{AppState, ResponseStatus, ScrollIden},
	hook_registry::HookState,
};

pub struct SummaryView;

impl SummaryView {
	const HOOK_SCROLL_IDEN: ScrollIden = ScrollIden::LoadedHookScroll;
}

impl StatefulWidget for SummaryView {
	type State = AppState;
	fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
		const SCROLL_IDEN: ScrollIden = SummaryView::HOOK_SCROLL_IDEN;

		let [top_row, middle_row, bottom_row] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([
				Constraint::Percentage(55),
				Constraint::Percentage(30),
				Constraint::Percentage(15),
			])
			.areas(area);

		let [rules_area, chart1_area] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
			.areas(top_row);

		render_loaded_rules_count(rules_area, buf, state);
		render_severity_chart(chart1_area, buf, state);

		let [last_event_area, hooks_area] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
			.areas(bottom_row);

		state.set_scroll_area(SCROLL_IDEN, hooks_area);

		render_last_event_meta(last_event_area, buf, state);
		render_loaded_hooks(hooks_area, buf, state, Block::bordered().title("Loaded Hooks"));
	}
}

fn render_loaded_hooks(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	const SCROLL_IDEN: ScrollIden = SummaryView::HOOK_SCROLL_IDEN;
	let scroll = state.clamp_scroll(SCROLL_IDEN, state.loaded_hooks().len());

	let hooks: Vec<Line> = state
		.loaded_hooks()
		.iter()
		.enumerate()
		.map(|(i, h)| {
			let status = match h.state {
				HookState::Disabled => "disabled",
				HookState::Enabled => "enabled",
			};

			let base_style = if i == state.selected_hook as usize {
				Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
			} else {
				Style::default().fg(Color::White)
			};

			Line::from(vec![
				Span::styled(h.name.as_ref(), base_style),
				Span::styled(format!(" [{}]", status), base_style),
			])
		})
		.collect();

	Paragraph::new(hooks).block(block).scroll((scroll, 0)).render(area, buf);
}

pub fn render_loaded_rules_count(area: Rect, buf: &mut Buffer, state: &AppState) {
	let rules = state.loaded_rules();

	let paragraph = Paragraph::new(rules.join("\n"))
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
				"Rule: {}\nSeverity: {}\nPID: {} \nUID: {} \nCOMM: {}",
				evt.event.rule_id,
				evt.event.severity.as_str(),
				evt.event.event_meta.pid,
				evt.event.event_meta.uid,
				evt.event.event_meta.comm
			)
		})
		.unwrap_or("No events yet".to_string());

	let paragraph = Paragraph::new(last_meta)
		.block(Block::bordered().title("Last Rule Match"))
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

fn render_response_queue(area: Rect, buf: &mut Buffer, state: &AppState) {
	let block = Block::bordered().title("Response Queue");

	let max_items = area.height.saturating_sub(2) as usize;
	if max_items == 0 {
		block.render(area, buf);
		return;
	}

	let items: Vec<Line> = state
		.response_evts()
		.take(max_items)
		.map(|item| {
			let (tag, tag_color) = match item.status {
				ResponseStatus::Done => ("OK", Color::Green),
				ResponseStatus::Failed => ("ERR", Color::Red),
			};

			let time_str = match item.completed {
				Some(completed) => {
					let dur = completed.duration_since(item.created);
					format!("{:>5.1}s", dur.as_secs_f32())
				}
				None => {
					let dur = item.created.elapsed();
					format!("{:>5.1}s", dur.as_secs_f32())
				}
			};

			Line::from(vec![
				Span::styled(
					format!("[{}]", tag),
					Style::default().fg(tag_color).add_modifier(Modifier::BOLD),
				),
				Span::raw(" "),
				Span::styled(time_str, Style::default().fg(Color::DarkGray)),
				Span::raw("  "),
				Span::styled(item.rule_id.as_ref(), Style::default().fg(Color::Indexed(250))),
				Span::raw("  "),
				Span::styled(item.summary.as_ref(), Style::default().fg(Color::White)),
			])
		})
		.collect();

	if items.is_empty() {
		Paragraph::new("No responses")
			.block(block)
			.style(Style::default().fg(Color::DarkGray))
			.render(area, buf);
	} else {
		Paragraph::new(items).block(block).render(area, buf);
	}
}
