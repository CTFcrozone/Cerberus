use std::sync::Arc;
use std::time::Duration;

use crate::Result;
use crate::core::event_handler::_handle_app_event;
use crate::core::{Tab, View};
use crate::event::AppEvent;
use crate::event::LastAppEvent;
use crate::hook_registry::HookView;
use crate::hook_registry::event::HookCommand;
use crate::views::correlated_event_view::render_correlation_popup;
use crate::views::{MainView, SummaryView, render_rule_popup};
use lib_event::unbound::{Rx, Tx};
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// use super::event_handler::handle_app_event;
use super::{AppState, process_app_state};

pub struct UiRuntime {
	pub ui_handle: JoinHandle<()>,
}

pub fn run_ui_loop(
	mut term: DefaultTerminal,
	hooks: Vec<HookView>,
	rules: Arc<[Arc<str>]>,
	mut app_rx: Rx<AppEvent>,
	hook_tx: Tx<HookCommand>,
	shutdown: CancellationToken,
) -> Result<UiRuntime> {
	let mut appstate = AppState::new(rules, hooks, LastAppEvent::default())?;
	// let mut ticker = tokio::time::interval(Duration::from_millis(100));
	// ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	let handle = tokio::spawn(async move {
		loop {
			tokio::select! {
				_ = shutdown.cancelled() => break,

				maybe_event = app_rx.recv() => {
					let Ok(event) = maybe_event else {
						break;
					};

					let _ = _handle_app_event(
						&event,
						&mut appstate,
						&hook_tx,
						shutdown.clone()
					).await;

					appstate.last_app_event = event.into();

					process_app_state(&mut appstate);
					let _ = terminal_draw(&mut term, &mut appstate);
				}
				// _ = ticker.tick() => {
				// 	let _ = terminal_draw(&mut term, &mut appstate);
				// }
			}
		}

		let _ = term.clear();
	});

	Ok(UiRuntime { ui_handle: handle })
}

fn terminal_draw(terminal: &mut DefaultTerminal, app_state: &mut AppState) -> Result<()> {
	terminal.draw(|frame| {
		let area = frame.area();

		match app_state.current_view() {
			View::Main => {
				frame.render_stateful_widget(MainView {}, area, app_state);
			}
			View::Summary => {
				frame.render_stateful_widget(SummaryView {}, area, app_state);
			}
		}

		if app_state.popup_show {
			match app_state.current_tab() {
				Tab::MatchedRules => render_rule_popup(frame, app_state),
				Tab::CorrelatedRules => render_correlation_popup(frame, app_state),
				_ => {}
			}
		}
	})?;

	Ok(())
}
