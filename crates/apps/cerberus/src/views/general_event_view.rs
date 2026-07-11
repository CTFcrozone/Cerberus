use crate::{
	core::{AppState, ScrollIden},
	views::support::render::line_from_event,
};
use ratatui::{
	buffer::Buffer,
	layout::Rect,
	text::Line,
	widgets::{Block, Padding, Paragraph, StatefulWidget, Widget},
};

pub struct GeneralEventView;

impl GeneralEventView {
	const SCROLL_IDEN: ScrollIden = ScrollIden::GenericEventScroll;
}

impl StatefulWidget for GeneralEventView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		const SCROLL_IDEN: ScrollIden = GeneralEventView::SCROLL_IDEN;
		let show_hooks = state.cerberus_evts_general().next().is_some();

		let block = Block::bordered().padding(Padding::left(1));

		state.set_scroll_area(SCROLL_IDEN, area);

		if !show_hooks {
			let p = Paragraph::new("No events yet").block(block);
			p.render(area, buf);
		} else {
			render_events(area, buf, state, block);
		}
	}
}

fn render_events(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	const SCROLL_IDEN: ScrollIden = GeneralEventView::SCROLL_IDEN;

	let lines: Vec<Line> = state.cerberus_evts_general().map(line_from_event).collect();

	let scroll = state.clamp_scroll(SCROLL_IDEN, lines.len());

	let paragraph = Paragraph::new(lines).block(block).scroll((scroll, 0));

	paragraph.render(area, buf);
}
