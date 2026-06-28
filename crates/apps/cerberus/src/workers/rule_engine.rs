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
use lib_rules::RuleEngine;

pub struct RuleEngineWorker {
	pub tx: Tx<AppEvent>,
	pub ringbuf_rx: Rx<CerberusEvent>,
	pub rule_engine: Arc<RuleEngine>,
	limiter: DefaultDirectRateLimiter,
	dropped: AtomicU64,
}

// TODO: make it shutdown aware
impl RuleEngineWorker {
	pub fn start(rule_engine: Arc<RuleEngine>, tx: Tx<AppEvent>, ringbuf_rx: Rx<CerberusEvent>) -> Result<Self> {
		let rate = NonZeroU32::new(10).ok_or(Error::InvalidRate)?;
		let burst = NonZeroU32::new(50).ok_or(Error::InvalidRate)?;

		let limiter = DefaultDirectRateLimiter::direct(Quota::per_second(rate).allow_burst(burst));

		Ok(RuleEngineWorker {
			tx,
			ringbuf_rx,
			rule_engine,
			limiter,
			dropped: AtomicU64::new(0),
		})
	}

	pub async fn run(mut self) -> Result<()> {
		while let Ok(evt) = self.ringbuf_rx.recv().await {
			for alert in self.rule_engine.process_event(&evt) {
				log_engine_event(&alert);
				self.tx.send(AppEvent::Engine(alert))?;
			}

			if self.limiter.check().is_err() {
				self.dropped.fetch_add(1, Ordering::Relaxed);
				continue;
			}
			log_cerberus_event(&evt);
			self.tx.send(AppEvent::Cerberus(evt))?;
		}
		Ok(())
	}
}
