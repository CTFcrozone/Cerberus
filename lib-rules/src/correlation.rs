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
		let entries = self.active.entry(root_rule_id.to_string()).or_default();

		// advance existing seqs
		for progress in entries.iter_mut() {
			if let Some(step) = seq.steps.get(progress.step_idx) {
				if now.duration_since(progress.last_match) <= step.within {
					progress.step_idx += 1;
					progress.last_match = now;

					if progress.step_idx == seq.steps.len() {
						return Some(CorrelatedMatch {
							root_rule_id: root_rule_id.to_string(),
							steps: seq.steps.len(),
						});
					}
				}
			}
		}

		// start new seq

		entries.push(SequenceProgress {
			step_idx: 0,
			last_match: now,
		});

		// cleanup expired
		entries.retain(|p| {
			let idx = p.step_idx.saturating_sub(1);
			seq.steps
				.get(idx)
				.map(|s| now.duration_since(p.last_match) <= s.within)
				.unwrap_or(false)
		});

		None
	}
}
