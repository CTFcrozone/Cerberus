use std::{collections::HashMap, sync::Arc, time::Instant, usize};

use crate::rule::{Sequence, SequenceProgress};

pub struct Correlator {
	// root rule_id -> progress sequence
	active: HashMap<Arc<str>, Vec<SequenceProgress>>,
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
		if seq.steps.is_empty() {
			return;
		}

		self.active.entry(root_rule_id.into()).or_default().push(SequenceProgress {
			step_idx: 0,
			last_match: now,
		});
	}

	pub fn on_rule_match(
		&mut self,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
	) -> Option<CorrelatedMatch> {
		if !self.active.contains_key(root_rule_id) {
			return None;
		}

		let queue = self.active.get_mut(root_rule_id)?;

		for prog in queue.iter_mut() {
			let step = match seq.steps.get(prog.step_idx) {
				Some(s) => s,
				None => continue,
			};

			if now.duration_since(prog.last_match) > step.within {
				prog.step_idx = usize::MAX;
				continue;
			}
			if step.rule_id == matched_rule_id {
				prog.step_idx += 1;
				prog.last_match = now;

				if prog.step_idx == seq.steps.len() {
					return Some(CorrelatedMatch {
						root_rule_id: root_rule_id.into(),
						steps: seq.steps.len(),
					});
				}
			}
		}

		queue.retain(|p| p.step_idx != usize::MAX);

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
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		// -- Exec
		corr.on_root_match("kernel-module-loader", &seq, t0);
		let res = corr.on_rule_match(
			"unrelated-rule",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(2),
		);

		// -- Check
		assert!(res.is_none());
		assert_eq!(corr.active["kernel-module-loader"][0].step_idx, 0);

		Ok(())
	}

	#[test]
	fn steps_must_be_ordered() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		// -- Exec
		corr.on_root_match("kernel-module-loader", &seq, t0);
		let res = corr.on_rule_match(
			"service-probe",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(2),
		);

		// -- Check
		assert!(res.is_none());
		assert_eq!(corr.active["kernel-module-loader"][0].step_idx, 0);

		Ok(())
	}

	#[test]
	fn multiple_concurrent_sequences() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();
		// -- Exec
		corr.on_root_match("kernel-module-loader", &seq, t0);
		corr.on_root_match("kernel-module-loader", &seq, t0 + Duration::from_secs(1));
		let _ = corr.on_rule_match("port-scan", &seq, "kernel-module-loader", t0 + Duration::from_secs(3));

		// -- Check
		let queue = &corr.active["kernel-module-loader"];
		assert_eq!(queue.len(), 2);
		assert!(queue.iter().all(|p| p.step_idx == 1));

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
