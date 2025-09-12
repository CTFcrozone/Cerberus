use crate::event::LastAppEvent;
use crate::views::MainView;
use crate::Result;
use aya::Ebpf;
use lib_event::app_evt_types::{ActionEvent, AppEvent};
use lib_event::trx::Rx;
use ratatui::DefaultTerminal;
use tokio::task::JoinHandle;

use super::event_handler::handle_app_event;
use super::{process_app_state, AppState, AppTx, ExitTx};

pub fn run_ui_loop(
	mut term: DefaultTerminal,
	ebpf: Ebpf,
	app_tx: AppTx,
	app_rx: Rx<AppEvent>,
	exit_tx: ExitTx,
) -> Result<JoinHandle<()>> {
	let mut appstate = AppState::new(ebpf, LastAppEvent::default())?;

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

	Ok(handle)
}

fn terminal_draw(terminal: &mut DefaultTerminal, app_state: &mut AppState) -> Result<()> {
	terminal.draw(|frame| {
		let area = frame.area();

		let main_view = MainView {};
		frame.render_stateful_widget(main_view, area, app_state);
	})?;

	Ok(())
}
