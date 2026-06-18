use std::{io::stdout, sync::Arc};

use crate::{
	core::{term_reader::run_term_read, tui_loop::run_ui_loop},
	hook_registry::registry::HookRegistry,
	Result,
};
use crossterm::{
	cursor,
	event::{DisableMouseCapture, EnableMouseCapture},
	execute,
	terminal::{DisableLineWrap, EnterAlternateScreen, LeaveAlternateScreen},
};
use lib_event::unbound::{Rx, Tx};
use ratatui::DefaultTerminal;

use crate::event::AppEvent;
use tokio_util::sync::CancellationToken;

pub async fn start_tui(
	hooks: Vec<String>,
	rules: Arc<[String]>,
	app_tx: Tx<AppEvent>,
	app_rx: Rx<AppEvent>,
	shutdown: CancellationToken,
) -> Result<()> {
	let terminal = ratatui::init();

	execute!(
		stdout(),
		EnterAlternateScreen,
		EnableMouseCapture,
		cursor::Hide,
		DisableLineWrap
	)?;

	let result = exec_app(terminal, hooks, rules, app_tx, app_rx, shutdown).await;

	ratatui::restore();
	execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, cursor::Show)?;

	result
}

async fn exec_app(
	mut terminal: DefaultTerminal,
	hooks: Vec<String>,
	rules: Arc<[String]>,
	app_tx: Tx<AppEvent>,
	app_rx: Rx<AppEvent>,
	shutdown: CancellationToken,
) -> Result<()> {
	terminal.clear()?;

	let term_handle = run_term_read(app_tx)?;
	let ui = run_ui_loop(terminal, hooks, rules, app_rx, shutdown.clone())?;

	let _ = ui.ui_handle.await;

	term_handle.abort();
	let _ = term_handle.await;

	Ok(())
}
