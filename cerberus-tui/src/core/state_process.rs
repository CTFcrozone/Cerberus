use crate::event::AppEvent;
use crate::load_hooks;

use crossterm::event::{KeyCode, MouseEventKind};

use super::AppTx;
use super::{app_state::View, AppState};

pub fn process_app_state(state: &mut AppState, app_tx: &AppTx) {
	match state.current_view() {
		View::Main => {
			state.refresh_sys_state();

			if let Some(KeyCode::Char('x')) = state.last_app_event().as_key_code() {
				state.cerberus_evts.clear();
				state.event_scroll = 0;
			}

			let hooks: Vec<String> = state.ebpf.programs().map(|(name, _)| name.to_string()).collect();

			state.loaded_hooks = hooks;

			let current_event_scroll = state.event_scroll();
			if let Some(mouse_evt) = state.last_app_event().as_mouse_event() {
				let event_scroll = match mouse_evt.kind {
					MouseEventKind::ScrollUp => Some(current_event_scroll.saturating_sub(3)),
					MouseEventKind::ScrollDown => Some(current_event_scroll.saturating_add(3)),
					_ => None,
				};
				if let Some(event_scroll) = event_scroll {
					state.set_event_scroll(event_scroll);
				}
			}
		}
		View::Splash => {
			if let Some(code) = state.last_app_event().as_key_code() {
				match code {
					KeyCode::Enter => {
						let res = load_hooks(&mut state.ebpf);
						match res {
							Ok(fd) => {
								state.hooks_loaded = true;

								state.ringbuf_fd = Some(fd);
								let _ = app_tx.send_sync(AppEvent::LoadedHooks);
							}
							Err(ex) => println!("Error while loading hooks: {ex}"),
						}
					}

					_ => {}
				}
			}
		}
	}
}
