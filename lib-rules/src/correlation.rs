use std::{
	collections::{HashMap, VecDeque},
	hash::Hash,
	time::Instant,
	usize,
};

use lib_event::app_evt_types::EvaluatedEvent;

use crate::{
	rule::{self, Rule, RuleInner},
	sequence::{Sequence, SequenceProgress},
};

pub struct CorrelationEngine {
	// root rule_id -> rule sequence
	pub active: HashMap<String, VecDeque<SequenceProgress>>,
	// rule_id -> rules (all)
	pub reverse_index: HashMap<String, Vec<Rule>>,
}

impl CorrelationEngine {
	pub fn new(rules: &[Rule]) -> Self {
		let mut reverse_index: HashMap<String, Vec<Rule>> = HashMap::new();
		for rule in rules {
			if let Some(seq) = &rule.inner.sequence {
				for step in &seq.steps {
					reverse_index.entry(step.rule_id.clone()).or_default().push(rule.clone());
				}
			}
		}

		Self {
			active: HashMap::new(),
			reverse_index,
		}
	}

	pub fn process_rule_sequence(&mut self, rule_id: &str, now: Instant) -> Vec<String> {
		let mut completed = Vec::new();

		let Some(dependent_rules) = self.reverse_index.get(rule_id) else {
			return completed;
		};

		for rule in dependent_rules {
			let Some(seq) = &rule.inner.sequence else {
				continue;
			};

			let queue = self.active.entry(rule.inner.id.clone()).or_default();

			// advance old sequences
			for progress in queue.iter_mut() {
				let Some(step) = seq.steps.get(progress.step_idx) else {
					continue;
				};

				if step.rule_id == rule_id && now.duration_since(progress.last_match) <= step.within {
					progress.step_idx += 1;
					progress.last_match = now;

					if progress.step_idx == seq.steps.len() {
						completed.push(rule.inner.id.clone());
						progress.step_idx = usize::MAX;
					}
				}
			}

			// start new seq
			if let Some(first) = seq.steps.first() {
				if first.rule_id == rule_id {
					queue.push_back(SequenceProgress {
						step_idx: 1,
						last_match: now,
					});
				}
			}

			// delete expired
			queue.retain(|p| {
				let Some(prev) = seq.steps.get(p.step_idx.saturating_sub(1)) else {
					return false;
				};
				now.duration_since(p.last_match) <= prev.within
			});
		}

		completed
	}
}
