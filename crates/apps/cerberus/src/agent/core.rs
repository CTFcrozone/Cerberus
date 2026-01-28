use std::time::Duration;

use crate::{error::Result, event::AppEvent};

use lib_common::event::CerberusEvent;
use lib_event::trx::Rx;
use lib_rules::EngineEvent;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn _run_agent_sink(rx: Rx<AppEvent>, shutdown: CancellationToken) -> Result<()> {
	loop {
		tokio::select! {
			_ = shutdown.cancelled() => {
				break;
			}

			evt = rx.recv() => {
				match evt {
					Ok(evt) => {
						match evt {
							AppEvent::Engine(e) => {
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

pub async fn start_agent(app_rx: Rx<AppEvent>, shutdown: CancellationToken, run_time: Duration) -> Result<()> {
	let sink_shutdown = shutdown.clone();
	let sink_handle = tokio::spawn(async move {
		let _ = _run_agent_sink(app_rx, sink_shutdown).await;
	});

	tokio::time::sleep(run_time).await;
	shutdown.cancel();
	let _ = sink_handle.await;

	Ok(())
}

fn print_alert(e: &EngineEvent) {
	match e {
		EngineEvent::Matched(ev) => {
			warn!(
				"[{}] {} (PID: {}, UID: {})",
				ev.rule_type, ev.rule_id, ev.event_meta.pid, ev.event_meta.uid
			);
		}
		EngineEvent::Correlated(ev) => {
			warn!(
				"[{} -> {}] {} (PID: {}, UID: {})",
				ev.base_rule_id, ev.seq_rule_id, ev.base_rule_hash, ev.event_meta.pid, ev.event_meta.uid
			);
		}
		_ => {}
	}
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
		_ => {}
	}
}

pub fn ip_to_string(ip: u32) -> String {
	let octets = ip.to_le_bytes();
	format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}
