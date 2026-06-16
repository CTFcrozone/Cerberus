use std::{collections::HashMap, sync::Arc, time::Instant, usize};

use lib_common::event::EventMeta;
use uuid::Uuid;

use crate::{engine::CorrelationEvent, rule::Sequence};

//todo: 	// for pid scoping
// active: HashMap<Arc<str>, HashMap<Option<u32>, HashMap<Arc<str>, Vec<SequenceProgress>>>>,
pub struct Correlator {
	// root rule_id -> progress sequence
	// active: HashMap<Arc<str>, Vec<SequenceProgress>>,

	// root_rule_id -> <seq_instance_id, progress>
	active: HashMap<Arc<str>, HashMap<Arc<str>, SequenceProgress>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CorrelatedMatch {
	pub root_rule_id: Arc<str>,
	pub steps: usize,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Clone)]
pub struct SequenceProgress {
	pub seq_id: Arc<str>,
	pub step_idx: usize,
	pub path: Vec<Arc<str>>,
	pub last_match: Instant,
	pub expiry: Instant,
}

impl Correlator {
	pub fn new() -> Self {
		Self { active: HashMap::new() }
	}

	pub fn on_root_match(&mut self, root_rule_id: &str, seq: &Sequence, now: Instant) {
		if seq.steps.is_empty() {
			return;
		}

		let root = self.active.entry(root_rule_id.into()).or_insert_with(HashMap::new);
		let instance_id: Arc<str> = Uuid::new_v4().to_string().into();

		root.insert(
			instance_id.clone(),
			SequenceProgress {
				seq_id: seq.id.clone().into(),
				path: Vec::new(),
				step_idx: 0,
				last_match: now,
				expiry: now + seq.steps[0].within,
			},
		);
	}

	pub fn on_rule_match(
		&mut self,
		matched_rule_id: &str,
		seq: &Sequence,
		root_rule_id: &str,
		now: Instant,
		event_meta: &EventMeta,
	) -> Vec<CorrelationEvent> {
		let Some(root) = self.active.get_mut(root_rule_id) else {
			return Vec::new();
		};

		let mut out = Vec::new();

		for (instance_id, prog) in root.iter_mut() {
			if prog.seq_id.as_ref() != seq.id {
				continue;
			}

			if now > prog.expiry {
				continue;
			}
			let expected = match seq.steps.get(prog.step_idx) {
				Some(s) => s,
				None => continue,
			};

			if expected.rule_id != matched_rule_id {
				continue;
			}

			let prev_idx = prog.step_idx;
			prog.step_idx += 1;
			prog.last_match = now;
			prog.path.push(matched_rule_id.into());
			let seq_id = prog.seq_id.clone();

			out.push(CorrelationEvent::Step {
				root_rule_id: root_rule_id.into(),
				seq_id: seq_id.clone(),
				seq_instance_id: instance_id.clone(),
				step_idx: prev_idx,
				matched_rule_id: matched_rule_id.into(),
			});

			if prog.step_idx == seq.steps.len() {
				out.push(CorrelationEvent::Completed {
					root_rule_id: root_rule_id.into(),
					seq_id,
					seq_instance_id: instance_id.clone(),
					path: prog.path.clone(),
					steps: seq.steps.len(),
					event_meta: event_meta.clone(),
				});
			} else {
				prog.expiry = now + seq.steps[prog.step_idx].within;
			}
		}

		root.retain(|_, p| now <= p.expiry && p.step_idx < seq.steps.len());

		if root.is_empty() {
			self.active.remove(root_rule_id);
		}

		out
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use std::{panic, time::Duration};

	use crate::rule::{SequenceKind, Step};

	use super::*;

	fn mk_seq() -> Sequence {
		Sequence {
			id: "test".into(),
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
			scope: None,
		}
	}

	fn mk_meta() -> EventMeta {
		EventMeta {
			uid: 0,
			pid: 0,
			comm: "DDD".into(),
		}
	}
	#[test]
	fn rule_sequence_completes() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match("kernel-module-loader", &seq, t0);

		let res = corr.on_rule_match(
			"port-scan",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(5),
			&mk_meta(),
		);

		assert_eq!(res.len(), 1);

		match &res[0] {
			CorrelationEvent::Step {
				root_rule_id, step_idx, ..
			} => {
				assert_eq!(root_rule_id.as_ref(), "kernel-module-loader");
				assert_eq!(*step_idx, 0);
			}
			_ => panic!("expected Step"),
		}

		let res = corr.on_rule_match(
			"service-probe",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(10),
			&mk_meta(),
		);

		assert_eq!(res.len(), 2);

		match &res[0] {
			CorrelationEvent::Step {
				root_rule_id, step_idx, ..
			} => {
				assert_eq!(root_rule_id.as_ref(), "kernel-module-loader");
				assert_eq!(*step_idx, 1);
			}
			_ => panic!("expected Step"),
		}

		match &res[1] {
			CorrelationEvent::Completed {
				root_rule_id, steps, ..
			} => {
				assert_eq!(root_rule_id.as_ref(), "kernel-module-loader");
				assert_eq!(*steps, 2);
			}
			_ => panic!("expected Completed"),
		}

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
		let res = corr.on_rule_match(
			"port-scan",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(20),
			&mk_meta(),
		);

		// -- Check
		assert!(res.is_empty());
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
			&mk_meta(),
		);

		assert!(res.is_empty());

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
			&mk_meta(),
		);

		assert!(res.is_empty());

		Ok(())
	}

	#[test]
	fn multiple_concurrent_sequences() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match("kernel-module-loader", &seq, t0);
		corr.on_root_match("kernel-module-loader", &seq, t0 + Duration::from_secs(1));

		let res = corr.on_rule_match(
			"port-scan",
			&seq,
			"kernel-module-loader",
			t0 + Duration::from_secs(3),
			&mk_meta(),
		);

		// Should affect BOTH instances → so multiple Step events
		assert_eq!(res.len(), 2);

		assert!(matches!(res[0], CorrelationEvent::Step { .. }));
		assert!(matches!(res[1], CorrelationEvent::Step { .. }));

		Ok(())
	}
	#[test]
	fn root_match_without_steps_does_nothing() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let t0 = Instant::now();
		let seq = Sequence {
			id: "test".into(),
			kind: SequenceKind::Rule,
			steps: vec![],
			scope: None,
		};
		// -- Exec
		corr.on_root_match("tmp-exec", &seq, t0);

		// -- Check
		assert!(corr.active.is_empty());

		Ok(())
	}
}

// endregion: --- Tests
