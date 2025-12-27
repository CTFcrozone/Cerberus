use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::core::View;
use crate::event::LastAppEvent;
use crate::views::{MainView, SummaryView};
use crate::Result;
use aya::Ebpf;
use lib_event::app_evt_types::{ActionEvent, AppEvent, RuleWatchEvent};
use lib_event::trx::{new_channel, Rx, Tx};
use lib_rules::engine::RuleEngine;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;

use super::event_handler::handle_app_event;
use super::{process_app_state, AppState, AppTx, ExitTx};

const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rules/");

pub fn rule_watcher(dir: String, tx: Tx<RuleWatchEvent>) -> Result<()> {
	std::thread::spawn(move || {
		let (ntx, nrx) = std::sync::mpsc::channel();

		let mut watcher =
			notify::RecommendedWatcher::new(ntx, notify::Config::default()).expect("failed to create watcher");

		watcher
			.watch(dir.as_ref(), notify::RecursiveMode::Recursive)
			.expect("failed to watch rules dir");

		for res in nrx {
			if res.is_ok() {
				let _ = tx.send_sync(RuleWatchEvent::Reload);
			}
		}
	});

	Ok(())
}

pub async fn rule_watch_worker(rx: Rx<RuleWatchEvent>, engine: Arc<RuleEngine>) -> Result<()> {
	while let Ok(_) = rx.recv().await {
		engine.reload_ruleset(RULES_DIR)?;
	}
	Ok(())
}

pub fn run_ui_loop(
	mut term: DefaultTerminal,
	ebpf: Ebpf,
	app_tx: AppTx,
	app_rx: Rx<AppEvent>,
	exit_tx: ExitTx,
) -> Result<JoinHandle<()>> {
	let mut appstate = AppState::new(ebpf, LastAppEvent::default())?;

	let rule_engine = Arc::new(RuleEngine::new(RULES_DIR)?);
	appstate.rule_engine = Some(rule_engine.clone());

	let handle = tokio::spawn(async move {
		loop {
			process_app_state(&mut appstate, &app_tx);
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
	rule_watcher(RULES_DIR.to_string(), rule_tx)?;
	tokio::spawn(rule_watch_worker(rule_rx, rule_engine));

	Ok(handle)
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
			View::Splash => {
				// Splash is rendered internally by MainView
				frame.render_stateful_widget(MainView {}, area, app_state);
			}
		}
	})?;

	Ok(())
}
