use crossterm::event::{KeyCode, MouseEventKind};

use crate::core::{ScrollIden, Tab};

use super::{AppState, app_state::View};

pub fn process_app_state(state: &mut AppState) {
	match state.current_view() {
		View::Main => handle_main_view(state),
		View::Summary => handle_summary_view(state),
	}
}

fn handle_summary_view(state: &mut AppState) {
	handle_summary_input(state);
	handle_scroll(state);
}

fn handle_main_view(state: &mut AppState) {
	handle_main_input(state);
	handle_scroll(state);
}

fn handle_summary_input(state: &mut AppState) {
	let Some(key) = state.last_app_event().as_key_code() else {
		return;
	};

	match key {
		KeyCode::Char('s') | KeyCode::Char('S') => state.toggle_view(),

		KeyCode::Down => {
			let len = state.loaded_hooks.len();
			if len > 0 {
				state.selected_hook = (state.selected_hook + 1) % len;
			}
		}

		KeyCode::Up => {
			let len = state.loaded_hooks.len();
			if len > 0 {
				state.selected_hook = (state.selected_hook + len - 1) % len;
			}
		}

		_ => {}
	}
}

fn handle_main_input(state: &mut AppState) {
	let Some(key) = state.last_app_event().as_key_code() else {
		return;
	};
	match key {
		KeyCode::Char('s') | KeyCode::Char('S') => state.toggle_view(),

		KeyCode::Enter => {
			if let Some(group) = state.correlated_groups().values().nth(state.selected_rule()) {
				state.toggle_correlation_group(group.root_rule_id.clone(), group.seq_id.clone());
			}
		}

		KeyCode::Char('i') => {
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

	let iden = match state.current_view() {
		View::Summary => ScrollIden::LoadedHookScroll,

		View::Main => match state.current_tab() {
			Tab::General => ScrollIden::GenericEventScroll,
			Tab::Network => ScrollIden::NetworkEventScroll,
			Tab::MatchedRules => ScrollIden::EvaluatedEventScroll,
			Tab::CorrelatedRules => ScrollIden::CorrelatedEventScroll,
		},
	};

	match mouse_evt.kind {
		MouseEventKind::ScrollUp => {
			state.dec_scroll(iden, 1);
		}
		MouseEventKind::ScrollDown => {
			state.inc_scroll(iden, 1);
		}
		_ => {}
	}
}
