use std::{sync::Arc, time::Instant, usize};

use lib_common::event::EventMeta;

use crate::{
	engine::CorrelationEvent,
	hash_utils::{FastMap, new_fast_map},
	rule::{Scope, compiled::sequence::CompiledSequence},
};

pub struct Correlator {
	// root_rule_id -> <seq_instance_id, progress>
	active: FastMap<Arc<str>, FastMap<u64, SequenceProgress>>,
	next_instance_id: u64,
}

const MAX_INSTANCES_PER_ROOT: usize = 256;

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
	pub scope_pid: Option<u32>,
}

impl Correlator {
	pub fn new() -> Self {
		Self {
			active: new_fast_map(),
			next_instance_id: 0,
		}
	}

	pub fn on_root_match(&mut self, root_rule_id: &Arc<str>, seq: &CompiledSequence, now: Instant, pid: u32) {
		if seq.steps.is_empty() {
			return;
		}

		let root = self.active.entry(root_rule_id.clone()).or_insert_with(new_fast_map);

		root.retain(|_, p| now <= p.expiry);

		if root.len() >= MAX_INSTANCES_PER_ROOT {
			if let Some(oldest) = root.keys().copied().min() {
				root.remove(&oldest);
			}
		}

		self.next_instance_id += 1;
		let instance_id = self.next_instance_id;

		root.insert(
			instance_id,
			SequenceProgress {
				seq_id: seq.id.clone(),
				path: Vec::new(),
				step_idx: 0,
				last_match: now,
				expiry: now + seq.steps[0].within,
				scope_pid: matches!(seq.scope, Some(Scope::Pid)).then_some(pid),
			},
		);

		// if root.is_empty() {
		// 	self.active.remove(root_rule_id);
		// }
	}

	pub fn on_rule_match(
		&mut self,
		matched_rule_id: &Arc<str>,
		seq: &CompiledSequence,
		root_rule_id: &Arc<str>,
		now: Instant,
		event_meta: &EventMeta,
	) -> Vec<CorrelationEvent> {
		let Some(root) = self.active.get_mut(root_rule_id) else {
			return Vec::new();
		};

		let mut out = Vec::new();

		for (instance_id, prog) in root.iter_mut() {
			if prog.seq_id.as_ref() != seq.id.as_ref() {
				continue;
			}

			if let Some(scope_pid) = prog.scope_pid {
				if scope_pid != event_meta.pid {
					continue;
				}
			}

			if now > prog.expiry {
				continue;
			}
			let expected = match seq.steps.get(prog.step_idx) {
				Some(s) => s,
				None => continue,
			};

			if expected.rule_id.as_ref() != matched_rule_id.as_ref() {
				continue;
			}

			let prev_idx = prog.step_idx;
			prog.step_idx += 1;
			prog.last_match = now;
			prog.path.push(matched_rule_id.clone());
			let seq_id = prog.seq_id.clone();

			out.push(CorrelationEvent::Step {
				root_rule_id: root_rule_id.clone(),
				seq_id: seq_id.clone(),
				seq_instance_id: *instance_id,
				step_idx: prev_idx,
				matched_rule_id: matched_rule_id.clone(),
			});

			match seq.steps.get(prog.step_idx) {
				Some(next_step) => {
					prog.expiry = now + next_step.within;
				}

				None => {
					out.push(CorrelationEvent::Completed {
						root_rule_id: root_rule_id.clone(),
						seq_id,
						seq_instance_id: *instance_id,
						path: core::mem::take(&mut prog.path),
						steps: seq.steps.len(),
						event_meta: event_meta.clone(),
					});
				}
			}
		}

		root.retain(|_, p| now <= p.expiry && p.step_idx < seq.steps.len());

		if root.is_empty() {
			self.active.remove(root_rule_id);
		}

		out
	}

	#[allow(dead_code)]
	pub fn instance_count(&self) -> usize {
		self.active.values().map(|r| r.len()).sum()
	}

	#[inline]
	pub fn is_empty(&self) -> bool {
		self.active.is_empty()
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use std::{panic, time::Duration};

	use crate::rule::{SequenceKind, compiled::sequence::CompiledStep};

	use super::*;

	fn mk_seq() -> CompiledSequence {
		CompiledSequence {
			id: "test".into(),
			kind: SequenceKind::Rule,
			steps: vec![
				CompiledStep {
					rule_id: "port-scan".into(),
					within: Duration::from_secs(10),
				},
				CompiledStep {
					rule_id: "service-probe".into(),
					within: Duration::from_secs(15),
				},
			],
			scope: None,
		}
	}

	fn mk_scoped_seq() -> CompiledSequence {
		CompiledSequence {
			scope: Some(Scope::Pid),
			..mk_seq()
		}
	}

	fn meta_for(pid: u32) -> EventMeta {
		EventMeta {
			uid: 0,
			pid,
			comm: "test".into(),
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

		corr.on_root_match(&Arc::<str>::from("kernel-module-loader"), &seq, t0, 0);

		let res = corr.on_rule_match(
			&Arc::<str>::from("port-scan"),
			&seq,
			&Arc::<str>::from("kernel-module-loader"),
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
			&Arc::<str>::from("service-probe"),
			&seq,
			&Arc::<str>::from("kernel-module-loader"),
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
	fn pid_scoped_sequence_ignores_other_processes() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_scoped_seq();
		let t0 = Instant::now();
		let root = Arc::<str>::from("kernel-module-loader");

		corr.on_root_match(&root, &seq, t0, 100);

		// -- Exec: step fires, but from a different process
		let res = corr.on_rule_match(
			&Arc::<str>::from("port-scan"),
			&seq,
			&root,
			t0 + Duration::from_secs(1),
			&meta_for(999),
		);

		// -- Check
		assert!(res.is_empty(), "a different pid must not advance a pid-scoped sequence");

		// same pid does advance it
		let res = corr.on_rule_match(
			&Arc::<str>::from("port-scan"),
			&seq,
			&root,
			t0 + Duration::from_secs(2),
			&meta_for(100),
		);
		assert_eq!(res.len(), 1);

		Ok(())
	}

	#[test]
	fn unscoped_sequence_advances_from_any_process() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq(); // scope: None
		let t0 = Instant::now();
		let root = Arc::<str>::from("kernel-module-loader");

		corr.on_root_match(&root, &seq, t0, 100);

		let res = corr.on_rule_match(
			&Arc::<str>::from("port-scan"),
			&seq,
			&root,
			t0 + Duration::from_secs(1),
			&meta_for(999),
		);

		assert_eq!(res.len(), 1, "unscoped sequences must not filter by pid");

		Ok(())
	}

	#[test]
	fn rule_sequence_expires() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match(&Arc::<str>::from("kernel-module-loader"), &seq, t0, 0);
		let res = corr.on_rule_match(
			&Arc::<str>::from("port-scan"),
			&seq,
			&Arc::<str>::from("kernel-module-loader"),
			t0 + Duration::from_secs(20),
			&mk_meta(),
		);

		assert!(res.is_empty());
		assert!(corr.active.is_empty());

		Ok(())
	}

	#[test]
	fn wrong_rule_does_not_advance_sequence() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();

		corr.on_root_match(&Arc::<str>::from("kernel-module-loader"), &seq, t0, 0);

		let res = corr.on_rule_match(
			&Arc::<str>::from("unrelated-rule"),
			&seq,
			&Arc::<str>::from("kernel-module-loader"),
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

		corr.on_root_match(&Arc::<str>::from("kernel-module-loader"), &seq, t0, 0);

		let res = corr.on_rule_match(
			&Arc::<str>::from("service-probe"),
			&seq,
			&Arc::<str>::from("kernel-module-loader"),
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

		corr.on_root_match(&Arc::<str>::from("kernel-module-loader"), &seq, t0, 0);
		corr.on_root_match(
			&Arc::<str>::from("kernel-module-loader"),
			&seq,
			t0 + Duration::from_secs(1),
			0,
		);

		let res = corr.on_rule_match(
			&Arc::<str>::from("port-scan"),
			&seq,
			&Arc::<str>::from("kernel-module-loader"),
			t0 + Duration::from_secs(3),
			&mk_meta(),
		);

		assert_eq!(res.len(), 2);
		assert!(matches!(res[0], CorrelationEvent::Step { .. }));
		assert!(matches!(res[1], CorrelationEvent::Step { .. }));

		Ok(())
	}
	#[test]
	fn root_match_without_steps_does_nothing() -> Result<()> {
		let mut corr = Correlator::new();
		let t0 = Instant::now();
		let seq = CompiledSequence {
			id: "test".into(),
			kind: SequenceKind::Rule,
			steps: vec![],
			scope: None,
		};

		corr.on_root_match(&Arc::<str>::from("tmp-exec"), &seq, t0, 0);

		assert!(corr.active.is_empty());

		Ok(())
	}

	// region:    --- regressions

	#[test]
	fn expired_instances_are_swept_on_root_match() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();
		let root = Arc::<str>::from("noisy-root");

		// -- Exec: a root that fires repeatedly, with step rules that never fire.
		// Every match is past the previous instance's 10s window.
		for i in 0..50 {
			corr.on_root_match(&root, &seq, t0 + Duration::from_secs(i * 11), 0);
		}

		// -- Check: only the newest instance survives, not 50.
		assert_eq!(corr.instance_count(), 1);

		Ok(())
	}

	#[test]
	fn instances_per_root_are_capped() -> Result<()> {
		// -- Setup & Fixtures
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();
		let root = Arc::<str>::from("very-noisy-root");

		// -- Exec: all within the first step's window, so the sweep can't reclaim them.
		for i in 0..(MAX_INSTANCES_PER_ROOT * 3) {
			corr.on_root_match(&root, &seq, t0 + Duration::from_millis(i as u64), 0);
		}

		// -- Check
		assert_eq!(corr.instance_count(), MAX_INSTANCES_PER_ROOT);

		Ok(())
	}

	#[test]
	fn instance_ids_are_monotonic() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_seq();
		let t0 = Instant::now();
		let root = Arc::<str>::from("kernel-module-loader");

		corr.on_root_match(&root, &seq, t0, 0);
		corr.on_root_match(&root, &seq, t0, 0);

		let mut ids: Vec<u64> = corr.active.get(&root).expect("root missing").keys().copied().collect();
		ids.sort_unstable();

		assert_eq!(ids, vec![1, 2]);

		Ok(())
	}
}

// endregion: --- Tests
