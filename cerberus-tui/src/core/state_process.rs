use crossterm::event::{KeyCode, MouseEventKind};

use super::AppState;

pub fn process_app_state(state: &mut AppState) {
	state.refresh_sys_state();

	if let Some(KeyCode::Char('c')) = state.last_app_event().as_key_code() {
		state.cerberus_evts.clear();
		state.event_scroll = 0;
	}

	let hooks: Vec<String> = state.ebpf.programs().map(|(name, _)| name.to_string()).collect();

	state.loaded_hooks = hooks;

	if let Some(mouse_evt) = state.last_app_event().as_mouse_event() {
		match mouse_evt.kind {
			MouseEventKind::ScrollUp => {
				state.event_scroll = state.event_scroll.saturating_sub(3);
			}
			MouseEventKind::ScrollDown => {
				state.event_scroll = state.event_scroll.saturating_add(3);
			}
			_ => (),
		}
	}
}
