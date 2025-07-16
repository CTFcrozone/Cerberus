mod app_state;
mod event_handler;
mod state_process;
mod sys_state;
mod term_reader;
mod tui_impl;
mod tui_loop;

pub use app_state::{AppState, View};
pub use state_process::*;
pub use tui_impl::*;

pub fn format_size_xfixed(size_in_bytes: u64) -> String {
	const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
	let mut size = size_in_bytes as f64;
	let mut unit = 0;

	while size >= 1000.0 && unit < UNITS.len() - 1 {
		size /= 1000.0;
		unit += 1;
	}

	let unit_str = UNITS[unit];

	if unit == 0 {
		let number_str = format!("{size_in_bytes:>6}");
		format!("{number_str} {unit_str} ")
	} else {
		let width = if unit <= 2 { 6 } else { 5 };
		let number_str = format!("{size:>width$.2}");
		format!("{number_str} {unit_str}")
	}
}
