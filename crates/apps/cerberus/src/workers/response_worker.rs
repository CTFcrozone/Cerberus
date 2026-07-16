use std::{
	collections::HashMap,
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

pub struct ResponseWorker;

// TODO: make it shutdown aware
impl ResponseWorker {
	pub async fn run(mut self) -> Result<()> {
		Ok(())
	}
}
