use ratatui::{
	buffer::Buffer,
	layout::Rect,
	text::{Line, Span},
	widgets::{
		Block, List, ListItem, ListState, Padding, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
		StatefulWidget, Widget,
	},
};

use crate::{core::AppState, styles};

pub struct EventView;

impl StatefulWidget for EventView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		let show_hooks = !state.cerberus_evts().is_empty();

		let block = Block::bordered().title("Events").padding(Padding::left(1));

		if !show_hooks {
			let p = Paragraph::new("No events yet").block(block.clone());
			p.render(area, buf);
		} else {
			render_events(area, buf, state, block);
		}
	}
}

fn render_events(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let events = state.cerberus_evts();

	// Build lines for each event (no ListItems)
	let lines: Vec<Line> = events
		.iter()
		.map(|evt| {
			let spans = vec![
				Span::styled(format!("[{}]", evt.name), styles::STL_TXT_ACTION),
				Span::raw(" | "),
				Span::styled(format!("UID: {}", evt.uid), styles::STL_TXT_LBL_DARK),
				Span::raw(" | "),
				Span::styled(format!("PID: {}", evt.pid), styles::STL_TXT_VAL),
				Span::raw(" | "),
				Span::styled(format!("TGID: {}", evt.tgid), styles::STL_TXT_VAL_DARK),
				Span::raw(" | "),
				Span::styled(format!("CMD: {}", evt.comm), styles::STL_TXT_ACT),
				Span::raw(" | "),
				Span::styled(format!("META: {}", evt.meta), styles::STL_TXT_SEL),
			];
			Line::from(spans)
		})
		.collect();

	let line_count = lines.len();

	let max_scroll = line_count.saturating_sub(area.height as usize) as u16;
	if state.event_scroll > max_scroll {
		state.event_scroll = max_scroll;
	}

	let paragraph = Paragraph::new(lines).block(block).scroll((state.event_scroll, 0));
	paragraph.render(area, buf);

	if line_count as u16 > area.height {
		let mut scrollbar_state = ScrollbarState::new(line_count as usize).position(state.event_scroll as usize);
		let scrollbar = Scrollbar::default()
			.orientation(ScrollbarOrientation::VerticalRight)
			.begin_symbol(Some("▲"))
			.end_symbol(Some("▼"));
		scrollbar.render(area, buf, &mut scrollbar_state);
	}
}
