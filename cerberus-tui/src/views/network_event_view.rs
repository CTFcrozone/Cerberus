use crate::{core::AppState, event::CerberusEvent};
use ratatui::{
	buffer::Buffer,
	layout::Rect,
	text::Line,
	widgets::{Block, Padding, Paragraph, StatefulWidget, Widget},
};

pub struct NetworkEventView;

impl StatefulWidget for NetworkEventView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		let show_hooks = !state.cerberus_evts_network().is_empty();

		let block = Block::bordered().padding(Padding::left(1));

		if !show_hooks {
			let p = Paragraph::new("No events yet").block(block);
			p.render(area, buf);
		} else {
			render_events(area, buf, state, block);
		}
	}
}

fn render_events(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let events = state.cerberus_evts_network();

	let lines: Vec<Line> = events
		.iter()
		.filter_map(|evt| match evt {
			CerberusEvent::InetSock(n) => Some(Line::raw(format!(
				"[INET_SOCK] {}:{} → {}:{} | Proto: {} | {} → {}",
				ip_to_string(n.saddr),
				n.sport,
				ip_to_string(n.daddr),
				n.dport,
				n.protocol,
				n.old_state,
				n.new_state
			))),
			_ => None,
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

fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_be_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}
