use std::{io::stdout, sync::Arc};

use crate::{
	core::{term_reader::_run_term_read, tui_loop::_run_ui_loop},
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

use lib_event::app_evt_types::AppEvent;
use lib_event::trx::{Rx, Tx};
use tokio_util::sync::CancellationToken;

#[derive(Clone, From, Deref)]
pub struct ExitTx(Tx<()>);

#[derive(Clone, From, Deref)]
pub struct AppTx(Tx<AppEvent>);

// pub async fn start_tui(
// 	ebpf: Ebpf,
// 	rule_engine: Arc<RuleEngine>,
// 	app_tx: AppTx,
// 	app_rx: Rx<AppEvent>,
// 	exit_tx: ExitTx,
// ) -> Result<()> {
// 	let terminal = ratatui::init();

// 	execute!(
// 		stdout(),
// 		EnterAlternateScreen,
// 		EnableMouseCapture,
// 		cursor::Hide,
// 		DisableLineWrap
// 	)?;

// 	let _ = exec_app(terminal, ebpf, app_tx, rule_engine, app_rx, exit_tx).await;

// 	ratatui::restore();
// 	execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, cursor::Show)?;
// 	Ok(())
// }

pub async fn _start_tui(
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

	let _ = _exec_app(terminal, ebpf, app_tx, rule_engine, app_rx, shutdown).await;

	ratatui::restore();
	execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, cursor::Show)?;
	Ok(())
}

async fn _exec_app(
	mut terminal: DefaultTerminal,
	ebpf: Ebpf,
	app_tx: AppTx,
	rule_engine: Arc<RuleEngine>,
	app_rx: Rx<AppEvent>,
	shutdown: CancellationToken,
) -> Result<()> {
	terminal.clear()?;

	let _tin_read_handle = _run_term_read(app_tx.clone(), shutdown.clone())?;
	let _tui_handle = _run_ui_loop(terminal, ebpf, /* app_tx, */ rule_engine, app_rx, shutdown.clone())?;

	tokio::select! {
		_ = _tui_handle.ui_handle => {},
		_ = shutdown.cancelled() => {
		},
	}

	Ok(())
}

// async fn exec_app(
// 	mut terminal: DefaultTerminal,
// 	ebpf: Ebpf,
// 	app_tx: AppTx,
// 	rule_engine: Arc<RuleEngine>,
// 	app_rx: Rx<AppEvent>,
// 	exit_tx: ExitTx,
// ) -> Result<()> {
// 	terminal.clear()?;

// 	let _tin_read_handle = run_term_read(app_tx.clone())?;
// 	let _tui_handle = run_ui_loop(terminal, ebpf, app_tx, rule_engine, app_rx, exit_tx)?;

// 	_tui_handle.ui_handle.await?;

// 	Ok(())
// }
