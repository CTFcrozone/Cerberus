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
use lib_event::{
	app_evt_types::{AppEvent, CerberusEvent, EvaluatedEvent},
	trx::Rx,
};
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
				break;
			}

			evt = rx.recv() => {
				match evt {
					Ok(evt) => {
						match evt {
							AppEvent::CerberusEvaluated(e) => {
								print_alert(&e);
							}
							AppEvent::Cerberus(e) => {
								print_event(&e);
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

pub fn init_tracing(log_path: &str) -> (WorkerGuard, WorkerGuard) {
	let path = Path::new(log_path);

	let dir = path.parent().unwrap_or(Path::new("."));
	let file = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("cerberus.log"));

	let file_appender = rolling::daily(dir, file);
	let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);

	let (non_blocking_stdout, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());

	let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

	tracing_subscriber::fmt()
		.with_writer(non_blocking_writer)
		.with_writer(non_blocking_stdout)
		.with_target(true)
		.with_thread_names(true)
		.with_env_filter(env_filter)
		.init();

	(guard, stdout_guard)
}
pub async fn start_daemon(app_rx: Rx<AppEvent>, shutdown: CancellationToken, run_time: Duration) -> Result<()> {
	let sink_shutdown = shutdown.clone();
	let sink_handle = tokio::spawn(async move {
		let _ = _run_daemon_sink(app_rx, sink_shutdown).await;
	});

	tokio::time::sleep(run_time).await;
	shutdown.cancel();
	let _ = sink_handle.await;

	Ok(())
}

fn print_alert(e: &EvaluatedEvent) {
	info!(
		"[{}] {} (PID: {}, UID: {})",
		e.rule_type, e.rule_id, e.event_meta.pid, e.event_meta.uid
	);
}

fn print_event(e: &CerberusEvent) {
	match e {
		CerberusEvent::Generic(g) => {
			info!("{}: {} (PID: {}, UID: {})", g.name, g.comm, g.pid, g.uid);
		}
		CerberusEvent::InetSock(i) => {
			info!(
				"{} → {} ({}:{} → {}:{})",
				i.old_state,
				i.new_state,
				ip_to_string(i.saddr),
				i.sport,
				ip_to_string(i.daddr),
				i.dport
			);
		}
		CerberusEvent::Module(m) => {
			info!("{} loaded by {} (PID: {})", m.module_name, m.comm, m.pid);
		}
		CerberusEvent::Bprm(b) => {
			info!("{} executed {} (PID: {})", b.comm, b.filepath, b.pid);
		}
	}
}

pub fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_le_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}
