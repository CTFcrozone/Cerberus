use std::{collections::VecDeque, sync::Arc};

use super::AppState;
use crate::core::View;
use crate::core::app_state::{ResponseItem, ResponseStatus};
use crate::event::AppEvent;
use crate::hook_registry::HookState;
use crate::hook_registry::event::HookCommand;
use crate::{Result, core::app_state::EvaluatedEntry};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use lib_common::event::CerberusEvent;
use lib_event::unbound::Tx;
use lib_rules::{CorrelationEvent, EngineEvent, EvaluatedEvent};
use tokio_util::sync::CancellationToken;

const MAX_EVENTS: usize = 250; // Reduced from 1000

fn handle_engine_event(event: &EngineEvent, app_state: &mut AppState) {
	match event {
		EngineEvent::Matched(evt) => {
			handle_cerberus_eval_event(evt, app_state);
		}

		EngineEvent::Correlation(evt) => {
			handle_correlation_event(evt, app_state);
		}

		_ => {}
	}
}

pub async fn _handle_app_event(
	// app_tx: &AppTx,
	app_event: &AppEvent,
	app_state: &mut AppState,
	hook_tx: &Tx<HookCommand>,
	shutdown: CancellationToken,
) -> Result<()> {
	match app_event {
		AppEvent::Term(term_event) => {
			_handle_term_event(app_state, &term_event, hook_tx, shutdown).await?;
		}
		AppEvent::Cerberus(cerberus_evt) => {
			handle_cerberus_event(cerberus_evt, app_state);
		}
		AppEvent::Engine(evt) => handle_engine_event(evt, app_state),

		AppEvent::HookEnabled { hook } => {
			if let Some(&idx) = app_state.hook_index.get(hook) {
				if let Some(h) = app_state.loaded_hooks.get_mut(idx as usize) {
					h.state = HookState::Enabled;
				}
			}
		}

		AppEvent::HookDisabled { hook } => {
			if let Some(&idx) = app_state.hook_index.get(hook) {
				if let Some(h) = app_state.loaded_hooks.get_mut(idx as usize) {
					h.state = HookState::Disabled;
				}
			}
		}

		AppEvent::RuleReload { rules } => {
			app_state.loaded_rules = rules.clone();
		}

		AppEvent::ResponseExecuted {
			rule_id,
			actions,
			time,
			success,
		} => {
			push_bounded(
				&mut app_state.response_evts,
				&ResponseItem {
					rule_id: Arc::clone(rule_id),
					actions: Arc::clone(actions),
					status: if *success {
						ResponseStatus::Done
					} else {
						ResponseStatus::Failed
					},
					completed: *time,
				},
			);
		}

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
		CerberusEvent::Inode(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::BpfMap(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::InodeMutation(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::PtraceAccessCheck(_) => &mut app_state.cerberus_evts_general,
		CerberusEvent::Tamper(_) => &mut app_state.cerberus_evts_general,
	};

	push_bounded(events, event);
}

fn handle_correlation_event(event: &CorrelationEvent, app_state: &mut AppState) {
	app_state.push_correlation_event(event.clone());
}

fn handle_cerberus_eval_event(event: &EvaluatedEvent, app_state: &mut AppState) {
	app_state.severity_counts[event.severity.index()] += 1;

	if let Some(entry) = app_state.cerberus_evts_matched.get_mut(&event.rule_id) {
		entry.count += 1;
		entry.event.event_meta = event.event_meta.clone();
	} else {
		app_state.cerberus_evts_matched.insert(
			Arc::clone(&event.rule_id),
			EvaluatedEntry {
				event: event.clone(),
				count: 1,
			},
		);
	}
}

async fn _handle_term_event(
	state: &mut AppState,
	term_event: &Event,
	hook_tx: &Tx<HookCommand>,
	shutdown: CancellationToken,
) -> Result<()> {
	if let Event::Key(key) = term_event {
		if let KeyEventKind::Press = key.kind {
			let mod_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
			let view = state.current_view();
			match (key.code, mod_ctrl) {
				(KeyCode::Char('q'), false) => {
					shutdown.cancel();
				}
				(KeyCode::Char('e'), false) => {
					if matches!(view, View::Summary) {
						if let Some(hook) = state.loaded_hooks.get(state.selected_hook as usize) {
							hook_tx.send(HookCommand::Enable(hook.name.clone()))?;
						}
					}
				}
				(KeyCode::Char('d'), false) => {
					if matches!(view, View::Summary) {
						if let Some(hook) = state.loaded_hooks.get(state.selected_hook as usize) {
							hook_tx.send(HookCommand::Disable(hook.name.clone()))?;
						}
					}
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
