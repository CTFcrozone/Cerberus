use ratatui::{
	buffer::Buffer,
	layout::{Alignment, Constraint, Direction, Layout, Rect},
	text::{Line, Span},
	widgets::{Block, Paragraph, StatefulWidget, Widget},
};

use crate::{core::AppState, styles};

pub struct SplashView;

impl StatefulWidget for SplashView {
	type State = AppState;

	fn render(self, area: Rect, buf: &mut Buffer, _state: &mut Self::State) {
		let [_, center] = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Percentage(10), Constraint::Fill(1)])
			.areas(area);

		let ascii = vec![
			Line::from(" ▄████▄  ▓█████  ██▀███   ▄▄▄▄   ▓█████  ██▀███   █    ██   ██████ "),
			Line::from("▒██▀ ▀█  ▓█   ▀ ▓██ ▒ ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒ ██  ▓██▒▒██    ▒ "),
			Line::from("▒▓█    ▄ ▒███   ▓██ ░▄█ ▒▒██▒ ▄██▒███   ▓██ ░▄█ ▒▓██  ▒██░░ ▓██▄   "),
			Line::from("▒▓▓▄ ▄██▒▒▓█  ▄ ▒██▀▀█▄  ▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ▓▓█  ░██░  ▒   ██▒"),
			Line::from("▒ ▓███▀ ░░▒████▒░██▓ ▒██▒░▓█  ▀█▓░▒████▒░██▓ ▒██▒▒▒█████▓ ▒██████▒▒"),
			Line::from("░ ░▒ ▒  ░░░ ▒░ ░░ ▒▓ ░▒▓░░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░"),
			Line::from("  ░  ▒    ░ ░  ░  ░▒ ░ ▒░▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░░░▒░ ░ ░ ░ ░▒  ░ ░"),
			Line::from("░           ░     ░░   ░  ░    ░    ░     ░░   ░  ░░░ ░ ░ ░  ░  ░  "),
			Line::from("░ ░         ░  ░   ░      ░         ░  ░   ░        ░           ░  "),
			Line::from("░                              ░                                   "),
			Line::from(""),
			Line::from(Span::styled("[Enter] Start", styles::STL_TXT_ACTION_SELECTED)),
		];

		let paragraph = Paragraph::new(ascii).block(Block::default()).alignment(Alignment::Center);

		paragraph.render(center, buf);
	}
}
