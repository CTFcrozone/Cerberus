use std::{fs::File, path::Path, sync::Arc, time::Duration};

use crate::{
	core::{AppTx, ExitTx},
	error::Result,
	load_hooks,
	worker::RingBufWorker,
	Error,
};
use aya::Ebpf;
use daemonize::Daemonize;
use lib_event::{app_evt_types::AppEvent, trx::Rx};
use lib_rules::engine::RuleEngine;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::EnvFilter;

pub async fn run_daemon_sink(rx: Rx<AppEvent>) -> Result<()> {
	while let Ok(evt) = rx.recv().await {
		match evt {
			AppEvent::CerberusEvaluated(alert) => {
				info!(target: "Matched rule", "{:?}", alert);
			}
			AppEvent::Cerberus(evt) => {
				info!(target: "event", "{:?}", evt);
			}
			_ => {}
		}
	}
	Ok(())
}

pub async fn _run_daemon_sink(rx: Rx<AppEvent>, shutdown: CancellationToken) -> Result<()> {
	loop {
		tokio::select! {
			_ = shutdown.cancelled() => {
				info!("Daemon sink shutting down");
				break;
			}

			evt = rx.recv() => {
				match evt {
					Ok(evt) => {
						match evt {
							AppEvent::CerberusEvaluated(e) => {
								info!(target: "matched_rule", "{:?}", e);
							}
							AppEvent::Cerberus(e) => {
								info!(target: "event", "{:?}", e);
							}
							_ => {}
						}
					}
					Err(e) => {
						info!("Event channel closed: {:?}", e);
						break;
					}
				}
			}
		}
	}

	Ok(())
}

pub async fn install_signal_handlers(token: CancellationToken) -> Result<()> {
	let t = token.clone();
	tokio::spawn(async move {
		let _ = tokio::signal::ctrl_c().await;
		t.cancel();
	});

	#[cfg(unix)]
	{
		use tokio::signal::unix::{signal, SignalKind};

		let t = token.clone();
		tokio::spawn(async move {
			let mut sigterm = signal(SignalKind::terminate()).unwrap();
			sigterm.recv().await;
			t.cancel();
		});
	}
	Ok(())
}

pub fn daemonize_process(log_path: &str) -> Result<()> {
	let log_file = File::create(Path::new(log_path))?;

	let daemonize = Daemonize::new()
		.working_directory("/")
		.umask(0o027)
		.stdout(log_file.try_clone()?)
		.stderr(log_file);

	daemonize
		.start()
		.map_err(|err| Error::DaemonStartFail { cause: err.to_string() })?;

	Ok(())
}

pub fn init_tracing(log_path: &str) -> WorkerGuard {
	let path = Path::new(log_path);

	let dir = path.parent().unwrap_or(Path::new("/var/log"));
	let file = path.file_name().unwrap_or_default();

	let file_appender = rolling::daily(dir, file);
	let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);

	tracing_subscriber::fmt()
		.with_writer(non_blocking_writer)
		.with_target(false)
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	guard
}

pub async fn start_daemon(app_rx: Rx<AppEvent>, shutdown: CancellationToken, run_time: Duration) -> Result<()> {
	tokio::select! {
		_ = tokio::time::sleep(run_time) => {
			shutdown.cancel();
		}
		result = _run_daemon_sink(app_rx, shutdown.clone()) => {
			result?;
		}
	}
	Ok(())
}
