use std::{
	num::NonZeroU32,
	sync::{
		Arc,
		atomic::{AtomicU64, Ordering},
	},
};

use crate::{
	error::{Error, Result},
	event::AppEvent,
	log_line::log_engine_event,
};

use governor::{DefaultDirectRateLimiter, Quota};
use lib_common::event::CerberusEvent;

use lib_event::unbound::{Rx, Tx};
use lib_rules::{EngineEvent, ResponseRequest, RuleEngine};
use tokio_util::sync::CancellationToken;

pub struct RuleEngineWorker {
	tx: Tx<AppEvent>,
	ringbuf_rx: Rx<CerberusEvent>,
	rule_engine: Arc<RuleEngine>,
	response_tx: Tx<ResponseRequest>,
	response_id: AtomicU64,
	limiter: DefaultDirectRateLimiter,
	dropped: AtomicU64,
	token: CancellationToken,
}

impl RuleEngineWorker {
	pub fn start(
		rule_engine: Arc<RuleEngine>,
		tx: Tx<AppEvent>,
		response_tx: Tx<ResponseRequest>,
		ringbuf_rx: Rx<CerberusEvent>,
		token: CancellationToken,
	) -> Result<Self> {
		let rate = NonZeroU32::new(10).ok_or(Error::InvalidRate)?;
		let burst = NonZeroU32::new(50).ok_or(Error::InvalidRate)?;

		let limiter = DefaultDirectRateLimiter::direct(Quota::per_second(rate).allow_burst(burst));

		Ok(RuleEngineWorker {
			tx,
			ringbuf_rx,
			rule_engine,
			limiter,
			response_tx,
			response_id: AtomicU64::new(0),
			dropped: AtomicU64::new(0),
			token,
		})
	}

	fn dispatch(&self, alert: EngineEvent) {
		match alert {
			EngineEvent::Response(req) => {
				if let Err(e) = self.tx.send(AppEvent::Engine(EngineEvent::Response(req.clone()))) {
					tracing::error!(
						error.message = %e,
						error.type = "app_event_send_failed",
						"Failed to send engine event to app"
					);
				}

				if let Err(e) = self.response_tx.send(req) {
					tracing::error!(
						error.message = %e,
						error.type = "executor_send_failed",
						"Failed to send response request to executor"
					);
				}
			}

			other => {
				if let Err(e) = self.tx.send(AppEvent::Engine(other)) {
					tracing::error!(
						error.message = %e,
						error.type = "app_event_send_failed",
						"Failed to send engine event to app"
					);
				}
			}
		}
	}

	pub async fn run(mut self, logging: bool) -> Result<()> {
		loop {
			tokio::select! {
				biased;

				_ = self.token.cancelled() => {
					tracing::info!("[RuleEngineWorker]: shutting down");
					break;
				}

				res = self.ringbuf_rx.recv() => {
					match res {
						Ok(evt) => {
							for mut alert in self.rule_engine.process_event(&evt) {
								if let EngineEvent::Response(req) = &mut alert {
									req.id = self.response_id.fetch_add(1, Ordering::Relaxed);
								}

								if logging {
									log_engine_event(&alert);
								}

								self.dispatch(alert);
							}

							if self.limiter.check().is_err() {
								self.dropped.fetch_add(1, Ordering::Relaxed);
								continue;
							}

							if let Err(e) = self.tx.send(AppEvent::Cerberus(evt)) {
								tracing::error!("Failed to send Cerberus event: {e}");
							}
						}
						Err(_) => {
							tracing::info!("[RuleEngineWorker]: input channel closed");
							break;
						}
					}
				}
			}
		}
		Ok(())
	}
}
