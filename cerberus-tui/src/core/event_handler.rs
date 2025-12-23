use std::sync::Arc;

use super::{AppState, AppTx, ExitTx};
use crate::{
	core::app_state::{EvaluatedEntry, EvaluatedKey},
	worker::RingBufWorker,
	Result,
};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use lib_event::app_evt_types::{ActionEvent, AppEvent, CerberusEvent, EvaluatedEvent};
use ratatui::DefaultTerminal;

const MAX_EVENTS: usize = 250; // Reduced from 1000

pub async fn handle_app_event(
	terminal: &mut DefaultTerminal,
	app_tx: &AppTx,
	exit_tx: &ExitTx,
	app_event: &AppEvent,
	app_state: &mut AppState,
) -> Result<()> {
	match app_event {
		AppEvent::Term(term_event) => {
			handle_term_event(&term_event, app_tx).await?;
		}
		AppEvent::Action(action_event) => {
			handle_action_event(&action_event, terminal, exit_tx).await?;
		}
		AppEvent::Cerberus(cerberus_evt) => {
			handle_cerberus_event(cerberus_evt, app_state);
		}
		AppEvent::CerberusEvaluated(evt) => handle_cerberus_eval_event(evt, app_state),
		AppEvent::LoadedHooks => {
			handle_hooks_loaded(app_state, app_tx).await?;
		}
	};

	Ok(())
}

async fn handle_hooks_loaded(app_state: &mut AppState, app_tx: &AppTx) -> Result<()> {
	if let Some(fd) = app_state.ringbuf_fd() {
		if let Some(engine) = &app_state.rule_engine {
			RingBufWorker::start(fd, engine.clone(), app_tx.clone()).await?;
			app_state.worker_up = true;
			app_state.set_view(crate::core::View::Main);
		}
	}

	Ok(())
}

fn handle_cerberus_event(event: &CerberusEvent, app_state: &mut AppState) {
	let events = match event {
		CerberusEvent::Generic(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::Module(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::InetSock(_) => &mut app_state.cerberus_evts_network,
	};

	if events.len() >= MAX_EVENTS {
		events.pop_front();
	}
	events.push_back(event.clone());
}

fn handle_cerberus_eval_event(event: &EvaluatedEvent, app_state: &mut AppState) {
	let key = EvaluatedKey {
		rule_id: Arc::clone(&event.rule_id),
		rule_type: event.rule_type,
	};

	match app_state.cerberus_evts_matched.get_mut(&key) {
		Some(entry) => {
			entry.count += 1;
			entry.event.event_meta = event.event_meta.clone();
		}
		None => {
			app_state.cerberus_evts_matched.insert(
				key,
				EvaluatedEntry {
					event: event.clone(),
					count: 1,
				},
			);
		}
	}
}

async fn handle_term_event(term_event: &Event, app_tx: &AppTx) -> Result<()> {
	if let Event::Key(key) = term_event {
		if let KeyEventKind::Press = key.kind {
			let mod_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
			match (key.code, mod_ctrl) {
				(KeyCode::Char('c'), true) => app_tx.send(ActionEvent::Quit).await?,
				_ => (),
			}
		}
	}
	Ok(())
}

async fn handle_action_event(
	action_event: &ActionEvent,
	_terminal: &mut DefaultTerminal,
	_exit_tx: &ExitTx,
) -> Result<()> {
	match action_event {
		ActionEvent::Quit => {
			// Handled at the main loop
		}
	}
	Ok(())
}
