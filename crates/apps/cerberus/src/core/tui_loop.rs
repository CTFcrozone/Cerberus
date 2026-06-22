use std::sync::Arc;
use std::time::Duration;

use crate::core::event_handler::_handle_app_event;
use crate::core::{Tab, View};
use crate::event::AppEvent;
use crate::event::LastAppEvent;
use crate::hook_registry::event::HookCommand;
use crate::hook_registry::HookView;
use crate::views::correlated_event_view::render_correlation_popup;
use crate::views::{render_rule_popup, MainView, SummaryView};
use crate::Result;
use lib_event::unbound::{Rx, Tx};
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

// use super::event_handler::handle_app_event;
use super::{process_app_state, AppState};

const FRAME_TIME: Duration = Duration::from_millis(16);

pub struct UiRuntime {
	pub ui_handle: JoinHandle<()>,
}

pub fn run_ui_loop(
	mut term: DefaultTerminal,
	hooks: Vec<HookView>,
	rules: Arc<[String]>,
	mut app_rx: Rx<AppEvent>,
	hook_tx: Tx<HookCommand>,
	shutdown: CancellationToken,
) -> Result<UiRuntime> {
	let mut appstate = AppState::new(rules, hooks, LastAppEvent::default())?;

	let handle = tokio::spawn(async move {
		let mut tick = interval(FRAME_TIME);
		let mut dirty = true;

		loop {
			tokio::select! {
				_ = shutdown.cancelled() => break,

				maybe_event = app_rx.recv() => {
					let Ok(event) = maybe_event else {
						break;
					};
					let _ = _handle_app_event(&event, &mut appstate, &hook_tx, shutdown.clone()).await;
					appstate.last_app_event = event.into();
					dirty = true;
				}

				_ = tick.tick() => {
					if dirty {
						process_app_state(&mut appstate);
						let _ = terminal_draw(&mut term, &mut appstate);
						dirty = false;
					}
				}
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
