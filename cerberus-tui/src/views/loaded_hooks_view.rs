use ratatui::{
	buffer::Buffer,
	layout::Rect,
	widgets::{Block, List, ListItem, ListState, Padding, Paragraph, StatefulWidget, Widget},
};

use crate::{core::AppState, styles};

pub struct LoadedHooksView;

impl StatefulWidget for LoadedHooksView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		let show_hooks = !state.loaded_hooks().is_empty();

		let block = Block::bordered().title("Loaded Hooks").padding(Padding::left(1));

		if !show_hooks {
			let p = Paragraph::new("No eBPF hooks loaded").block(block.clone());
			p.render(area, buf);
		} else {
			render_loaded_hooks_block(area, buf, state, block);
		}
	}
}

fn render_loaded_hooks_block(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let hooks = state.loaded_hooks();

	let items: Vec<ListItem> = hooks.iter().map(|hook| ListItem::new(hook.to_string())).collect();

	let list = List::new(items)
		.block(block)
		.highlight_style(styles::STL_NAV_ITEM_HIGHLIGHT)
		.highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

	let mut list_s = ListState::default();

	StatefulWidget::render(list, area, buf, &mut list_s);
}
