use crate::load_hooks;
use lib_event::app_evt_types::AppEvent;

use crossterm::event::{KeyCode, MouseEventKind};

use super::{app_state::View, AppState};
use super::{AppTx, Tab};

pub fn process_app_state(state: &mut AppState, app_tx: &AppTx) {
	match state.current_view() {
		View::Main => handle_main_view(state),
		View::Splash => handle_splash_view(state, app_tx),
	}
}

fn handle_main_view(state: &mut AppState) {
	state.refresh_sys_state();
	handle_main_input(state);
	update_loaded_hooks(state);
	handle_scroll(state);
}

fn handle_main_input(state: &mut AppState) {
	if let Some(key) = state.last_app_event().as_key_code() {
		match key {
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

fn handle_splash_view(state: &mut AppState, app_tx: &AppTx) {
	if let Some(KeyCode::Enter) = state.last_app_event().as_key_code() {
		match load_hooks(&mut state.ebpf) {
			Ok(fd) => {
				state.hooks_loaded = true;
				state.ringbuf_fd = Some(fd);
				let _ = app_tx.send_sync(AppEvent::LoadedHooks);
			}
			Err(err) => {
				eprintln!("Error while loading hooks: {err}");
			}
		}
	}
}
