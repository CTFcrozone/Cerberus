use std::{io::stdout, sync::Arc};

use crate::{
	core::{term_reader::run_term_read, tui_loop::run_ui_loop},
	Result,
};
use aya::Ebpf;
use crossterm::{
	cursor,
	event::{DisableMouseCapture, EnableMouseCapture},
	execute,
	terminal::{DisableLineWrap, EnterAlternateScreen, LeaveAlternateScreen},
};
use derive_more::{Deref, From};
use lib_rules::RuleEngine;
use ratatui::DefaultTerminal;

use crate::event::AppEvent;
use lib_event::trx::{Rx, Tx};
use tokio_util::sync::CancellationToken;

#[derive(Clone, From, Deref)]
pub struct ExitTx(Tx<()>);

#[derive(Clone, From, Deref)]
pub struct AppTx(Tx<AppEvent>);

pub async fn start_tui(
	ebpf: Ebpf,
	rule_engine: Arc<RuleEngine>,
	app_tx: AppTx,
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

	let result = exec_app(terminal, ebpf, app_tx, rule_engine, app_rx, shutdown).await;

	ratatui::restore();
	execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, cursor::Show)?;

	result
}

async fn exec_app(
	mut terminal: DefaultTerminal,
	ebpf: Ebpf,
	app_tx: AppTx,
	rule_engine: Arc<RuleEngine>,
	app_rx: Rx<AppEvent>,
	shutdown: CancellationToken,
) -> Result<()> {
	terminal.clear()?;

	let term_handle = run_term_read(app_tx.clone())?;
	let ui = run_ui_loop(terminal, ebpf, rule_engine, app_rx, shutdown.clone())?;

	let _ = ui.ui_handle.await;

	term_handle.abort();
	let _ = term_handle.await;

	Ok(())
}
