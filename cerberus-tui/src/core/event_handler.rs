use super::{AppState, AppTx, ExitTx};
use crate::event::CerberusEvent;
use crate::{
	event::{ActionEvent, AppEvent},
	worker::RingBufWorker,
	Result,
};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

const MAX_EVENTS: usize = 500; // Reduced from 1000

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
		AppEvent::LoadedHooks => {
			handle_hooks_loaded(app_state, app_tx).await?;
		}
	};

	Ok(())
}

async fn handle_hooks_loaded(app_state: &mut AppState, app_tx: &AppTx) -> Result<()> {
	if let Some(fd) = app_state.ringbuf_fd() {
		RingBufWorker::start(fd, app_tx.clone()).await?;
		app_state.worker_up = true;
		app_state.set_view(crate::core::View::Main);
	}

	Ok(())
}

fn handle_cerberus_event(event: &CerberusEvent, app_state: &mut AppState) {
	if app_state.cerberus_evts.len() >= MAX_EVENTS {
		app_state.cerberus_evts.remove(0);
	}
	app_state.cerberus_evts.push(event.clone());
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
