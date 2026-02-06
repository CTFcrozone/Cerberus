use std::sync::Arc;
use std::time::Duration;

use crate::core::event_handler::_handle_app_event;
use crate::core::{Tab, View};
use crate::event::AppEvent;
use crate::event::LastAppEvent;
use crate::views::correlated_event_view::render_correlation_popup;
use crate::views::{render_rule_popup, MainView, SummaryView};
use crate::Result;
use aya::Ebpf;
use lib_event::trx::Rx;
use lib_rules::RuleEngine;
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;

// use super::event_handler::handle_app_event;
use super::{process_app_state, AppState};

const FRAME_TIME: Duration = Duration::from_millis(16);

pub struct UiRuntime {
	pub ui_handle: JoinHandle<()>,
}

pub fn run_ui_loop(
	mut term: DefaultTerminal,
	ebpf: Ebpf,
	rule_engine: Arc<RuleEngine>,
	app_rx: Rx<AppEvent>,
	shutdown: CancellationToken,
) -> Result<UiRuntime> {
	let mut appstate = AppState::new(ebpf, LastAppEvent::default())?;

	appstate.rule_engine = Some(rule_engine.clone());

	let handle = tokio::spawn(async move {
		loop {
			if shutdown.is_cancelled() {
				let _ = term.clear();
				break;
			}

			let frame_start = Instant::now();

			process_app_state(&mut appstate);
			let _ = terminal_draw(&mut term, &mut appstate);

			let app_event = match app_rx.recv().await {
				Ok(r) => r,
				Err(_) => break,
			};

			let _ = _handle_app_event(&app_event, &mut appstate, shutdown.clone()).await;
			appstate.last_app_event = app_event.into();
			let elapsed = frame_start.elapsed();
			if elapsed < FRAME_TIME {
				sleep(FRAME_TIME - elapsed).await;
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
