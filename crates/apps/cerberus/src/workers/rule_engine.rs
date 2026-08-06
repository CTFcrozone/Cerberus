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
	log_line::{log_cerberus_event, log_engine_event},
};

use governor::{DefaultDirectRateLimiter, Quota};
use lib_common::event::CerberusEvent;

use lib_event::unbound::{Rx, Tx};
use lib_rules::{EngineEvent, ResponseRequest, RuleEngine};

pub struct RuleEngineWorker {
	tx: Tx<AppEvent>,
	ringbuf_rx: Rx<CerberusEvent>,
	rule_engine: Arc<RuleEngine>,
	response_tx: Tx<ResponseRequest>,

	limiter: DefaultDirectRateLimiter,
	dropped: AtomicU64,
}

impl RuleEngineWorker {
	pub fn start(
		rule_engine: Arc<RuleEngine>,
		tx: Tx<AppEvent>,
		response_tx: Tx<ResponseRequest>,
		ringbuf_rx: Rx<CerberusEvent>,
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
			dropped: AtomicU64::new(0),
		})
	}

	pub async fn run(mut self, logging: bool) -> Result<()> {
		while let Ok(evt) = self.ringbuf_rx.recv().await {
			for alert in self.rule_engine.process_event(&evt) {
				if logging {
					log_engine_event(&alert);
				}
				if let Err(e) = self.tx.send(AppEvent::Engine(alert.clone())) {
					tracing::error!(
						error.message = %e,
						error.type = "app_event_send_failed",
						"Failed to send engine event to app"
					);
				}
				if let EngineEvent::Response(req) = alert {
					if let Err(e) = self.response_tx.send(req) {
						tracing::error!(
							error.message = %e,
							error.type = "executor_send_failed",
							"Failed to send response request to executor"
						);
					}
				}
			}

			if self.limiter.check().is_err() {
				self.dropped.fetch_add(1, Ordering::Relaxed);
				continue;
			}
			if logging {
				log_cerberus_event(&evt);
			}
			self.tx.send(AppEvent::Cerberus(evt))?;
		}
		Ok(())
	}
}
