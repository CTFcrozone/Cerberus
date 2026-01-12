use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::core::event_handler::_handle_app_event;
use crate::core::{Tab, View};
use crate::event::LastAppEvent;
use crate::views::correlated_event_view::render_correlation_popup;
use crate::views::{render_rule_popup, MainView, SummaryView};
use crate::Result;
use aya::Ebpf;
use lib_event::app_evt_types::{ActionEvent, AppEvent, RuleWatchEvent};
use lib_event::trx::{new_channel, Rx, Tx};
use lib_rules::engine::RuleEngine;
use notify::{INotifyWatcher, RecursiveMode};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, Debouncer, NoCache};
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::event_handler::handle_app_event;
use super::{process_app_state, AppState, AppTx, ExitTx};

pub struct UiRuntime {
	pub ui_handle: JoinHandle<()>,
	pub _rule_watcher: Debouncer<INotifyWatcher, NoCache>,
}

const RULES_DIR: &str = "/home/voidbyte/.cerberus/rules/";

pub fn rule_watcher(dir: impl AsRef<Path>, tx: Tx<RuleWatchEvent>) -> Result<Debouncer<INotifyWatcher, NoCache>> {
	let mut debouncer = new_debouncer(Duration::from_secs(1), None, move |res: DebounceEventResult| {
		if res.is_ok() {
			let _ = tx.send_sync(RuleWatchEvent::Reload);
		}
	})?;
	debouncer.watch(dir.as_ref(), RecursiveMode::Recursive)?;

	Ok(debouncer)
}

pub async fn rule_watch_worker(rx: Rx<RuleWatchEvent>, engine: Arc<RuleEngine>) -> Result<()> {
	while let Ok(_) = rx.recv().await {
		engine.reload_ruleset(RULES_DIR)?;
	}
	Ok(())
}

pub async fn _rule_watch_worker(
	rx: Rx<RuleWatchEvent>,
	engine: Arc<RuleEngine>,
	shutdown: CancellationToken,
) -> Result<()> {
	loop {
		tokio::select! {
			_ = shutdown.cancelled() => {
				break;
			},
			evt = rx.recv() => {
				if let Ok(_) = evt {
					engine.reload_ruleset(RULES_DIR)?;
				}
			}
		}
	}
	Ok(())
}

pub fn run_ui_loop(
	mut term: DefaultTerminal,
	ebpf: Ebpf,
	app_tx: AppTx,
	rule_engine: Arc<RuleEngine>,
	app_rx: Rx<AppEvent>,
	exit_tx: ExitTx,
) -> Result<UiRuntime> {
	let mut appstate = AppState::new(ebpf, LastAppEvent::default())?;

	appstate.rule_engine = Some(rule_engine.clone());

	let handle = tokio::spawn(async move {
		loop {
			process_app_state(&mut appstate);
			let _ = terminal_draw(&mut term, &mut appstate);

			let app_event = match app_rx.recv().await {
				Ok(r) => r,
				Err(err) => {
					println!("UI LOOP ERROR. Cause: {err}");
					continue;
				}
			};

			if let AppEvent::Action(ActionEvent::Quit) = &app_event {
				let _ = term.clear();
				let _ = exit_tx.send(()).await;
				break;
			}

			let _ = handle_app_event(&mut term, &app_tx, &exit_tx, &app_event, &mut appstate).await;

			appstate.last_app_event = app_event.into();
		}
	});

	let (rule_tx, rule_rx) = new_channel::<RuleWatchEvent>("rules");
	let _watcher = rule_watcher(RULES_DIR, rule_tx)?;
	tokio::spawn(rule_watch_worker(rule_rx, rule_engine));

	Ok(UiRuntime {
		ui_handle: handle,
		_rule_watcher: _watcher,
	})
}

pub fn _run_ui_loop(
	mut term: DefaultTerminal,
	ebpf: Ebpf,
	// app_tx: AppTx,
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

			process_app_state(&mut appstate);
			let _ = terminal_draw(&mut term, &mut appstate);

			let app_event = tokio::select! {
				_ = shutdown.cancelled() => {
						break;
				},
				evt = app_rx.recv() => match evt {
					Ok(r) => r,
					Err(_) => break,
				},
			};

			// if let AppEvent::Action(ActionEvent::Quit) = &app_event {
			// 	let _ = term.clear();
			// 	info!("tui loop cancel 3");

			// 	shutdown.cancel();
			// 	break;
			// }

			let _ = _handle_app_event(
				&mut term,
				// &app_tx,
				&app_event,
				&mut appstate,
				shutdown.clone(),
			)
			.await;
			appstate.last_app_event = app_event.into();
		}
	});

	let (rule_tx, rule_rx) = new_channel::<RuleWatchEvent>("rules");
	let _watcher = rule_watcher(RULES_DIR, rule_tx)?;
	tokio::spawn(rule_watch_worker(rule_rx, rule_engine));

	Ok(UiRuntime {
		ui_handle: handle,
		_rule_watcher: _watcher,
	})
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
