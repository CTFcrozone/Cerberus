use super::{AppState, AppTx, ExitTx};
use crate::{
	event::{ActionEvent, AppEvent, RingBufEvent},
	Result,
};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

pub async fn handle_app_event(
	terminal: &mut DefaultTerminal,
	app_tx: &AppTx,
	exit_tx: &ExitTx,
	app_event: &AppEvent,
	app_state: &mut AppState,
) -> Result<()> {
	// println!("APP EVENT HANDLER - {app_event:?}");

	match app_event {
		AppEvent::Term(term_event) => {
			handle_term_event(term_event, app_tx).await?;
		}
		AppEvent::Action(action_event) => {
			handle_action_event(action_event, terminal, exit_tx).await?;
		}
		AppEvent::Cerberus(cerberus_evt) => {
			handle_cerberus_event(cerberus_evt, app_state);
		}
	};

	Ok(())
}

fn handle_cerberus_event(event: &RingBufEvent, app_state: &mut AppState) {
	app_state.cerberus_evts.push(event.clone());
	if app_state.cerberus_evts.len() > 1000 {
		let excess = app_state.cerberus_evts.len() - 100;
		app_state.cerberus_evts.drain(0..excess);
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
