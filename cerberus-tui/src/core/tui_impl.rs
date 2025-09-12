use std::io::stdout;

use crate::Result;
use aya::Ebpf;
use crossterm::{
	cursor,
	event::{DisableMouseCapture, EnableMouseCapture},
	execute,
	terminal::{DisableLineWrap, EnterAlternateScreen, LeaveAlternateScreen},
};
use derive_more::{Deref, From};
use ratatui::DefaultTerminal;

use lib_event::app_evt_types::AppEvent;
use lib_event::trx::{Rx, Tx};

use super::{term_reader::run_term_read, tui_loop::run_ui_loop};

#[derive(Clone, From, Deref)]
pub struct ExitTx(Tx<()>);

#[derive(Clone, From, Deref)]
pub struct AppTx(Tx<AppEvent>);

pub async fn start_tui(ebpf: Ebpf, app_tx: AppTx, app_rx: Rx<AppEvent>, exit_tx: ExitTx) -> Result<()> {
	let terminal = ratatui::init();

	execute!(
		stdout(),
		EnterAlternateScreen,
		EnableMouseCapture,
		cursor::Hide,
		DisableLineWrap
	)?;

	let _ = exec_app(terminal, ebpf, app_tx, app_rx, exit_tx).await;

	ratatui::restore();
	execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, cursor::Show)?;
	Ok(())
}

async fn exec_app(
	mut terminal: DefaultTerminal,
	ebpf: Ebpf,
	app_tx: AppTx,
	app_rx: Rx<AppEvent>,
	exit_tx: ExitTx,
) -> Result<()> {
	terminal.clear()?;

	let _tin_read_handle = run_term_read(app_tx.clone())?;
	let _tui_handle = run_ui_loop(terminal, ebpf, app_tx, app_rx, exit_tx)?;

	_tui_handle.await?;

	Ok(())
}
