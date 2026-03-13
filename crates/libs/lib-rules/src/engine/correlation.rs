use std::{collections::HashMap, sync::Arc, time::Instant, usize};

use crate::rule::{Sequence, SequenceProgress};

pub struct Correlator {
	// root rule_id -> progress sequence
	// active: HashMap<Arc<str>, Vec<SequenceProgress>>,

	// root_rule_id -> next_step_rule_id -> Vec<SequenceProgress>
	active: HashMap<Arc<str>, HashMap<Arc<str>, Vec<SequenceProgress>>>,
}

#[derive(Debug, Clone)]
pub struct CorrelatedMatch {
	pub root_rule_id: Arc<str>,
	pub steps: usize,
}

impl Correlator {
	pub fn new() -> Self {
		Self { active: HashMap::new() }
	}

	pub fn on_root_match(&mut self, root_rule_id: &str, seq: &Sequence, now: Instant) {
		let first = match seq.steps.first() {
			Some(f) => f,
			None => return,
		};

		let root = self.active.entry(root_rule_id.into()).or_insert_with(HashMap::new);
		let first_rule_id: Arc<str> = first.rule_id.clone().into();

		root.entry(first_rule_id.into()).or_default().push(SequenceProgress {
			step_idx: 0,
			last_match: now,
			expiry: now + first.within,
		});
	}

	pub fn on_rule_match(
		&mut self,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
	) -> Option<CorrelatedMatch> {
		let root = self.active.get_mut(root_rule_id)?;

		let mut queue = root.remove(matched_rule_id)?;

		for prog in queue.iter_mut() {
			if now > prog.expiry {
				prog.step_idx = usize::MAX;
				continue;
			}

			prog.step_idx += 1;
			prog.last_match = now;

			if prog.step_idx == seq.steps.len() {
				return Some(CorrelatedMatch {
					root_rule_id: root_rule_id.into(),
					steps: seq.steps.len(),
				});
			}

			if let Some(next_step) = seq.steps.get(prog.step_idx) {
				let next_rule_id: Arc<str> = next_step.rule_id.clone().into();
				prog.expiry = now + next_step.within;
				root.entry(next_rule_id).or_default().push(prog.clone());
			}
		}

		queue.retain(|p| p.step_idx != usize::MAX && now <= p.expiry);

		if queue.is_empty() {
			self.active.remove(root_rule_id);
		}

		None
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use std::time::Duration;

	use crate::rule::{SequenceKind, Step};

	use super::*;

	fn mk_seq() -> Sequence {
		Sequence {
			kind: SequenceKind::Rule,
			steps: vec![
				Step {
					rule_id: "port-scan".into(),
					within: Duration::from_secs(10),
				},
				Step {
					rule_id: "service-probe".into(),
					within: Duration::from_secs(15),
				},
			],
		}
	}
	#[test]
	fn rule_sequence_completes() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();
		// -- Exec

		corr.on_root_match("kernel-module-loader", &seq, t0);
		let res = corr.on_rule_match("port-scan", &seq, "kernel-module-loader", t0 + Duration::from_secs(5));
		assert!(res.is_none());
		let res = corr.on_rule_match(
			"service-probe",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(10),
		);

		// -- Check
		let alert = res.expect("correlation should complete");
		assert_eq!(alert.root_rule_id, "kernel-module-loader".into());
		assert_eq!(alert.steps, 2);

		Ok(())
	}

	#[test]
	fn rule_sequence_expires() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		// -- Exec
		corr.on_root_match("kernel-module-loader", &seq, t0);
		let res = corr.on_rule_match("port-scan", &seq, "kernel-module-loader", t0 + Duration::from_secs(20));

		// -- Check
		assert!(res.is_none());
		assert!(corr.active.is_empty());

		Ok(())
	}

	#[test]
	fn wrong_rule_does_not_advance_sequence() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match("kernel-module-loader", &seq, t0);

		let res = corr.on_rule_match(
			"unrelated-rule",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(2),
		);

		assert!(res.is_none());

		let root_map = &corr.active["kernel-module-loader"];
		for queue in root_map.values() {
			for prog in queue {
				assert_eq!(prog.step_idx, 0);
			}
		}

		Ok(())
	}

	#[test]
	fn steps_must_be_ordered() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match("kernel-module-loader", &seq, t0);

		let res = corr.on_rule_match(
			"service-probe",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(2),
		);

		assert!(res.is_none());

		let root_map = &corr.active["kernel-module-loader"];
		for queue in root_map.values() {
			for prog in queue {
				assert_eq!(prog.step_idx, 0);
			}
		}

		Ok(())
	}

	#[test]
	fn multiple_concurrent_sequences() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match("kernel-module-loader", &seq, t0);
		corr.on_root_match("kernel-module-loader", &seq, t0 + Duration::from_secs(1));

		let _ = corr.on_rule_match("port-scan", &seq, "kernel-module-loader", t0 + Duration::from_secs(3));

		let root_map = &corr.active["kernel-module-loader"];
		let mut all_progress: Vec<&SequenceProgress> = vec![];
		for queue in root_map.values() {
			all_progress.extend(queue.iter());
		}

		assert_eq!(all_progress.len(), 2);
		assert!(all_progress.iter().all(|p| p.step_idx == 1));

		Ok(())
	}
	#[test]
	fn root_match_without_steps_does_nothing() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let t0 = Instant::now();
		let seq = Sequence {
			kind: SequenceKind::Rule,
			steps: vec![],
		};
		// -- Exec
		corr.on_root_match("tmp-exec", &seq, t0);

		// -- Check
		assert!(corr.active.is_empty());

		Ok(())
	}
}

// endregion: --- Tests
