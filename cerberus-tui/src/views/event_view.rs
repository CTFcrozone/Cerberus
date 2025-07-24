use ratatui::{
	buffer::Buffer,
	layout::{Constraint, Direction, Layout, Rect},
	style::{Color, Style, Stylize},
	symbols::border::PROPORTIONAL_WIDE,
	text::{Line, Span},
	widgets::{Block, Padding, Paragraph, StatefulWidget, Tabs, Widget},
};

use crate::{core::AppState, event::CerberusEvent, styles};

pub struct EventView;

impl StatefulWidget for EventView {
	type State = AppState;
	fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer, state: &mut Self::State) {
		let show_hooks = !state.cerberus_evts_general().is_empty();

		let [_space_1, tabs_a, content_a] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Max(1), Constraint::Length(1), Constraint::Fill(1)])
			.areas(area);

		let [_, tab_general_a, _, tab_network_a] = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([
				Constraint::Length(1),  // gap
				Constraint::Length(11), // "General"
				Constraint::Length(2),  // gap
				Constraint::Length(11), // "Network"
			])
			.areas(tabs_a);

		let current_tab = state.current_tab();

		let tab_general_style = if current_tab.as_index() == 0 {
			styles::STL_TAB_ACTIVE
		} else {
			styles::STL_TAB_DEFAULT
		};

		let tab_network_style = if current_tab.as_index() == 1 {
			styles::STL_TAB_ACTIVE
		} else {
			styles::STL_TAB_DEFAULT
		};

		Paragraph::new("General")
			.centered()
			.style(tab_general_style)
			.render(tab_general_a, buf);

		Paragraph::new("Network")
			.centered()
			.style(tab_network_style)
			.render(tab_network_a, buf);

		// let repeated = "▔".repeat(tabs_line.width as usize);
		// let line = Line::default().spans(vec![Span::raw(repeated)]).fg(styles::CLR_BKG_TAB_ACT);
		// line.render(tabs_line, buf);

		let block = Block::bordered().padding(Padding::left(1));

		if !show_hooks {
			let p = Paragraph::new("No events yet").block(block.clone());
			p.render(content_a, buf);
		} else {
			render_events(content_a, buf, state, block);
		}
	}
}

fn render_events(area: Rect, buf: &mut Buffer, state: &mut AppState, block: Block) {
	let events = state.cerberus_evts_general();
	let lines: Vec<Line> = events
		.iter()
		.map(|evt| match evt {
			CerberusEvent::Generic(g) => Line::raw(format!(
				"[{}] UID:{} | PID:{} | TGID:{} | CMD:{} | META:{}",
				g.name, g.uid, g.pid, g.tgid, g.comm, g.meta
			)),
			CerberusEvent::InetSock(n) => Line::raw(format!(
				"[INET_SOCK] {}:{} → {}:{} | Proto: {} | {} → {}",
				ip_to_string(n.saddr),
				n.sport,
				ip_to_string(n.daddr),
				n.dport,
				n.protocol,
				n.old_state,
				n.new_state
			)),
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
