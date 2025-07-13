use ratatui::{
	buffer::Buffer,
	layout::Rect,
	widgets::{Block, List, ListItem, ListState, Padding, Paragraph, StatefulWidget, Widget},
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
	let evts = state.cerberus_evts();

	let items: Vec<ListItem> = evts
		.iter()
		.rev()
		.take(20)
		.map(|evt| {
			let line = format!(
				"[{}] UID: {} TGID: {} CMD: {} META: {}",
				evt.name, evt.uid, evt.tgid, evt.comm, evt.meta
			);
			ListItem::new(line)
		})
		.collect();

	let list = List::new(items)
		.block(block)
		.highlight_style(styles::STL_NAV_ITEM_HIGHLIGHT)
		.highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

	let mut list_s = ListState::default();

	StatefulWidget::render(list, area, buf, &mut list_s);
}
