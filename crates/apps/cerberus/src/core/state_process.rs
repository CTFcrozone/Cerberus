use crossterm::event::{KeyCode, MouseEventKind};

use super::{app_state::View, AppState};

const MAX_SCROLL: u16 = 10_000;

pub fn process_app_state(state: &mut AppState) {
	match state.current_view() {
		View::Main | View::Summary => handle_main_view(state),
	}
}

fn handle_main_view(state: &mut AppState) {
	handle_main_input(state);
	handle_scroll(state);
}

fn handle_main_input(state: &mut AppState) {
	let Some(key) = state.last_app_event().as_key_code() else {
		return;
	};
	match key {
		KeyCode::Char('s') | KeyCode::Char('S') => state.toggle_view(),

		KeyCode::Enter => {
			if state.active_event_rule_count() > 0 {
				state.toggle_rule_popup();
			}
		}

		KeyCode::Up => state.prev_rule(),

		KeyCode::Down => state.next_rule(),

		KeyCode::Char('x') => state.clear_current_tab(),
		KeyCode::Tab => {
			state.set_tab(state.current_tab().next());
		}

		_ => {}
	}
}

fn handle_scroll(state: &mut AppState) {
	let Some(mouse_evt) = state.last_app_event().as_mouse_event() else {
		return;
	};
	let new_scroll = match mouse_evt.kind {
		MouseEventKind::ScrollUp => Some(state.event_scroll().saturating_sub(1)),
		MouseEventKind::ScrollDown => Some(state.event_scroll().saturating_add(1).min(MAX_SCROLL)),
		_ => None,
	};

	if let Some(scroll) = new_scroll {
		state.set_event_scroll(scroll);
	}
}
