use crossterm::event::{KeyCode, MouseEventKind};

use super::Tab;
use super::{app_state::View, AppState};

pub fn process_app_state(state: &mut AppState) {
	match state.current_view() {
		View::Main | View::Summary => handle_main_view(state),
	}
}

fn handle_main_view(state: &mut AppState) {
	handle_main_input(state);
	update_loaded_hooks(state);
	handle_scroll(state);
}

fn handle_main_input(state: &mut AppState) {
	if let Some(key) = state.last_app_event().as_key_code() {
		match key {
			KeyCode::Char('s') | KeyCode::Char('S') => match state.current_view() {
				View::Main => state.set_view(View::Summary),
				View::Summary => state.set_view(View::Main),
			},

			KeyCode::Enter => match state.current_tab() {
				Tab::MatchedRules => state.toggle_rule_popup(),
				Tab::CorrelatedRules => state.toggle_rule_popup(),

				_ => {}
			},

			KeyCode::Up => match state.current_tab() {
				Tab::MatchedRules => state.next_rule(state.cerberus_evts_matched().count()),
				Tab::CorrelatedRules => state.next_rule(state.cerberus_evts_correlated().count()),
				_ => {}
			},

			KeyCode::Down => match state.current_tab() {
				Tab::MatchedRules => state.prev_rule(state.cerberus_evts_matched().count()),
				Tab::CorrelatedRules => state.prev_rule(state.cerberus_evts_correlated().count()),

				_ => {}
			},

			KeyCode::Char('x') => match state.current_tab() {
				Tab::General => {
					state.cerberus_evts_general.clear();
					state.set_event_scroll(0);
				}
				Tab::Network => {
					state.cerberus_evts_network.clear();
					state.set_event_scroll(0);
				}
				Tab::MatchedRules => {
					state.cerberus_evts_matched.clear();
					state.set_event_scroll(0);
				}
				Tab::CorrelatedRules => {
					state.cerberus_evts_correlated.clear();
					state.set_event_scroll(0);
				}
			},
			KeyCode::Tab => {
				state.set_tab(state.current_tab().next());
			}

			_ => {}
		}
	}
}

fn update_loaded_hooks(state: &mut AppState) {
	let hooks: Vec<String> = state.ebpf.programs().map(|(name, _)| name.to_string()).collect();

	state.loaded_hooks = hooks;
}

fn handle_scroll(state: &mut AppState) {
	if let Some(mouse_evt) = state.last_app_event().as_mouse_event() {
		let new_scroll = match mouse_evt.kind {
			MouseEventKind::ScrollUp => Some(state.event_scroll().saturating_sub(3)),
			MouseEventKind::ScrollDown => Some(state.event_scroll().saturating_add(3)),
			_ => None,
		};

		if let Some(scroll) = new_scroll {
			state.set_event_scroll(scroll);
		}
	}
}
