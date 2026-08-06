use crate::{
	error::Result,
	event::AppEvent,
	log_line::{
		alert::{alert_from_engine_event, severity_from_engine_event},
		format::{severity_to_level, string_from_event},
	},
};

use humantime::Duration;
use lib_event::unbound::Rx;
use lib_rules::EngineEvent;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub async fn _run_agent_sink(mut rx: Rx<AppEvent>, shutdown: CancellationToken) -> Result<()> {
	info!("Agent sink started, waiting for events...");
	loop {
		tokio::select! {
			_ = shutdown.cancelled() => {
				info!("Shutdown signal received, stopping agent sink...");
				break;
			}
			maybe_event = rx.recv() => {
				let Ok(event) = maybe_event else {
					info!("AppEvent channel closed");
					break;
				};

				match event {
					AppEvent::Engine(e) => print_alert(&e),
					AppEvent::Cerberus(e) => debug!("{}", string_from_event(&e)),
					_ => {}
				}
			}

		}
	}

	Ok(())
}

pub async fn start_agent(app_rx: Rx<AppEvent>, shutdown: CancellationToken, run_time: Option<Duration>) -> Result<()> {
	let sink_shutdown = shutdown.clone();
	let sink_handle = tokio::spawn(async move {
		let _ = _run_agent_sink(app_rx, sink_shutdown).await;
	});

	if let Some(run_time) = run_time {
		tokio::time::sleep(run_time.into()).await;
		shutdown.cancel();
	}

	let _ = sink_handle.await;

	Ok(())
}

fn print_alert(e: &EngineEvent) {
	let msg = alert_from_engine_event(e);

	match severity_from_engine_event(e) {
		Some(sev) => match severity_to_level(sev) {
			tracing::Level::ERROR => tracing::error!("{}", msg),
			tracing::Level::WARN => tracing::warn!("{}", msg),
			tracing::Level::INFO => tracing::info!("{}", msg),
			tracing::Level::DEBUG => tracing::debug!("{}", msg),
			tracing::Level::TRACE => tracing::trace!("{}", msg),
		},

		None => {
			tracing::warn!("{}", msg);
		}
	}
}
