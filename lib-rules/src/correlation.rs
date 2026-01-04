use std::{
	collections::{HashMap, VecDeque},
	hash::Hash,
	sync::Arc,
	time::Instant,
	usize,
};

use lib_event::app_evt_types::EvaluatedEvent;

use crate::{
	rule::{self, Rule, RuleInner},
	sequence::{Sequence, SequenceProgress},
};

pub struct CorrelationEngine {
	// root rule_id -> progress sequence
	active: HashMap<String, Vec<SequenceProgress>>,
}

#[derive(Debug, Clone)]
pub struct CorrelatedMatch {
	pub root_rule_id: String,
	pub steps: usize,
}

impl CorrelationEngine {
	pub fn new() -> Self {
		Self { active: HashMap::new() }
	}

	pub fn on_root_match(&mut self, root_rule_id: &str, seq: &Sequence, now: Instant) -> Option<CorrelatedMatch> {
		None
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;
}

// endregion: --- Tests
