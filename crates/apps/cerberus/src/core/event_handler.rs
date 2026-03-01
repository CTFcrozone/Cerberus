use std::{collections::VecDeque, sync::Arc};

use super::AppState;
use crate::event::AppEvent;
use crate::{
	core::app_state::{EvaluatedEntry, EvaluatedKey},
	Result,
};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use lib_common::event::CerberusEvent;
use lib_rules::{CorrelatedEvent, EngineEvent, EvaluatedEvent};
use tokio_util::sync::CancellationToken;

const MAX_EVENTS: usize = 250; // Reduced from 1000

// pub async fn handle_app_event(
// 	app_tx: &AppTx,
// 	exit_tx: &ExitTx,
// 	app_event: &AppEvent,
// 	app_state: &mut AppState,
// ) -> Result<()> {
// 	match app_event {
// 		AppEvent::Term(term_event) => {
// 			handle_term_event(&term_event, app_tx).await?;
// 		}
// 		AppEvent::Cerberus(cerberus_evt) => {
// 			handle_cerberus_event(cerberus_evt, app_state);
// 		}
// 		AppEvent::Engine(evt) => handle_engine_event(evt, app_state),

// 		_ => {}
// 	};

// 	Ok(())
// }

fn handle_engine_event(event: &EngineEvent, app_state: &mut AppState) {
	match event {
		EngineEvent::Matched(evt) => {
			handle_cerberus_eval_event(evt, app_state);
		}

		EngineEvent::Correlated(evt) => {
			handle_correlation_event(evt, app_state);
		}
		_ => {}
	}
}

pub async fn _handle_app_event(
	// app_tx: &AppTx,
	app_event: &AppEvent,
	app_state: &mut AppState,
	shutdown: CancellationToken,
) -> Result<()> {
	match app_event {
		AppEvent::Term(term_event) => {
			_handle_term_event(&term_event, shutdown).await?;
		}
		AppEvent::Cerberus(cerberus_evt) => {
			handle_cerberus_event(cerberus_evt, app_state);
		}
		AppEvent::Engine(evt) => handle_engine_event(evt, app_state),

		_ => {}
	};

	Ok(())
}

fn handle_cerberus_event(event: &CerberusEvent, app_state: &mut AppState) {
	let events = match event {
		CerberusEvent::Generic(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::Bprm(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::Module(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::InetSock(_) => &mut app_state.cerberus_evts_network,
		CerberusEvent::Socket(_) => &mut app_state.cerberus_evts_network,
		CerberusEvent::BpfProgLoad(_) => &mut app_state.cerberus_evts_general,
	};

	push_bounded(events, event);
}

fn handle_correlation_event(event: &CorrelatedEvent, app_state: &mut AppState) {
	push_bounded(&mut app_state.cerberus_evts_correlated, event);
}

fn handle_cerberus_eval_event(event: &EvaluatedEvent, app_state: &mut AppState) {
	let key = EvaluatedKey {
		rule_id: Arc::clone(&event.rule_id),
		rule_type: Arc::clone(&event.rule_type),
	};

	*app_state.rule_type_counts.entry(Arc::clone(&event.rule_type)).or_insert(0) += 1;

	*app_state.severity_counts.entry(Arc::clone(&event.severity)).or_insert(0) += 1;

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

// async fn handle_term_event(term_event: &Event, app_tx: &AppTx) -> Result<()> {
// 	if let Event::Key(key) = term_event {
// 		if let KeyEventKind::Press = key.kind {
// 			let mod_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
// 			match (key.code, mod_ctrl) {
// 				(KeyCode::Char('c'), true) => app_tx.send(ActionEvent::Quit).await?,
// 				_ => (),
// 			}
// 		}
// 	}
// 	Ok(())
// }

async fn _handle_term_event(term_event: &Event, shutdown: CancellationToken) -> Result<()> {
	if let Event::Key(key) = term_event {
		if let KeyEventKind::Press = key.kind {
			let mod_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
			match (key.code, mod_ctrl) {
				(KeyCode::Char('q'), false) => {
					shutdown.cancel();
				}
				_ => (),
			}
		}
	}
	Ok(())
}

fn push_bounded<T: Clone>(buf: &mut VecDeque<T>, item: &T) {
	if buf.len() >= MAX_EVENTS {
		buf.pop_front();
	}
	buf.push_back(item.clone());
}
