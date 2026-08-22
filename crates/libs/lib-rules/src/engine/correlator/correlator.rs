use std::{
	collections::VecDeque,
	sync::Arc,
	time::{Duration, Instant},
	usize,
};

use lib_common::event::EventMeta;

use crate::{
	engine::CorrelationEvent,
	hash_utils::{FastMap, new_fast_map},
	rule::{Scope, SequenceKind, compiled::sequence::CompiledSequence},
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
	pub hits: Option<VecDeque<Instant>>,
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

		let is_threshold = matches!(seq.kind, SequenceKind::Threshold);

		root.insert(
			instance_id,
			SequenceProgress {
				seq_id: seq.id.clone(),
				path: Vec::new(),
				step_idx: 0,
				last_match: now,
				expiry: now + seq.steps[0].within,
				scope_pid: match seq.scope {
					Some(Scope::Pid) => Some(pid),
					None => None,
				},
				hits: if is_threshold { Some(VecDeque::new()) } else { None },
			},
		);

		// if root.is_empty() {
		// 	self.active.remove(root_rule_id);
		// }
	}

	fn instance_alive(
		prog: &SequenceProgress,
		seq: &CompiledSequence,
		now: Instant,
		step0_within: Option<Duration>,
	) -> bool {
		match seq.kind {
			SequenceKind::Rule => now <= prog.expiry && prog.step_idx < seq.steps.len(),
			SequenceKind::Threshold => match step0_within {
				Some(w) => now.saturating_duration_since(prog.last_match) <= w,
				None => false,
			},
		}
	}

	fn advance_threshold(
		prog: &mut SequenceProgress,
		seq: &CompiledSequence,
		matched_rule_id: &Arc<str>,
		root_rule_id: &Arc<str>,
		instance_id: u64,
		now: Instant,
		event_meta: &EventMeta,
		out: &mut Vec<CorrelationEvent>,
	) {
		let step = &seq.steps[0];
		if step.rule_id.as_ref() != matched_rule_id.as_ref() {
			return;
		}
		let threshold = seq.threshold.unwrap_or(u32::MAX);

		let hits = prog.hits.get_or_insert_with(VecDeque::new);
		hits.push_back(now);
		prog.last_match = now;

		if let Some(cutoff) = now.checked_sub(step.within) {
			while hits.front().is_some_and(|&t| t < cutoff) {
				hits.pop_front();
			}
		}
		let cap = (threshold as usize).saturating_mul(4).max(8);
		while hits.len() > cap {
			hits.pop_front();
		}

		if hits.len() as u32 >= threshold {
			out.push(CorrelationEvent::Completed {
				root_rule_id: root_rule_id.clone(),
				seq_id: prog.seq_id.clone(),
				seq_instance_id: instance_id,
				path: Vec::new(),
				steps: hits.len(),
				event_meta: event_meta.clone(),
			});
			hits.clear();
		}
	}

	fn advance_sequence(
		prog: &mut SequenceProgress,
		seq: &CompiledSequence,
		matched_rule_id: &Arc<str>,
		root_rule_id: &Arc<str>,
		instance_id: u64,
		now: Instant,
		event_meta: &EventMeta,
		out: &mut Vec<CorrelationEvent>,
	) {
		if now > prog.expiry {
			return;
		}
		let Some(expected) = seq.steps.get(prog.step_idx) else {
			return;
		};
		if expected.rule_id.as_ref() != matched_rule_id.as_ref() {
			return;
		}

		let prev_idx = prog.step_idx;
		prog.step_idx += 1;
		prog.last_match = now;
		prog.path.push(matched_rule_id.clone());

		out.push(CorrelationEvent::Step {
			root_rule_id: root_rule_id.clone(),
			seq_id: prog.seq_id.clone(),
			seq_instance_id: instance_id,
			step_idx: prev_idx,
			matched_rule_id: matched_rule_id.clone(),
		});

		match seq.steps.get(prog.step_idx) {
			Some(next) => prog.expiry = now + next.within,
			None => out.push(CorrelationEvent::Completed {
				root_rule_id: root_rule_id.clone(),
				seq_id: prog.seq_id.clone(),
				seq_instance_id: instance_id,
				path: core::mem::take(&mut prog.path),
				steps: seq.steps.len(),
				event_meta: event_meta.clone(),
			}),
		}
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

			match seq.kind {
				SequenceKind::Rule => Self::advance_sequence(
					prog,
					seq,
					matched_rule_id,
					root_rule_id,
					*instance_id,
					now,
					event_meta,
					&mut out,
				),
				SequenceKind::Threshold => Self::advance_threshold(
					prog,
					seq,
					matched_rule_id,
					root_rule_id,
					*instance_id,
					now,
					event_meta,
					&mut out,
				),
			}
		}

		let step0_within = seq.steps.first().map(|s| s.within);
		root.retain(|_, p| Self::instance_alive(p, seq, now, step0_within));

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
			threshold: None,
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

	fn mk_threshold_seq() -> CompiledSequence {
		CompiledSequence {
			id: "test".into(),
			kind: SequenceKind::Threshold,
			steps: vec![CompiledStep {
				rule_id: "failed-login".into(),
				within: Duration::from_secs(10),
			}],
			threshold: Some(3),
			scope: None,
		}
	}

	#[test]
	fn threshold_fires_on_nth_hit_within_window() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_threshold_seq();
		let t0 = Instant::now();
		let root = Arc::<str>::from("brute-force");

		corr.on_root_match(&root, &seq, t0, 0);

		// two hits - not enough
		for i in 1..=2 {
			let res = corr.on_rule_match(
				&Arc::<str>::from("failed-login"),
				&seq,
				&root,
				t0 + Duration::from_secs(i),
				&mk_meta(),
			);
			assert!(res.is_empty(), "fired early at hit {i}");
		}
		// third hit within window - fires
		let res = corr.on_rule_match(
			&Arc::<str>::from("failed-login"),
			&seq,
			&root,
			t0 + Duration::from_secs(3),
			&mk_meta(),
		);
		assert_eq!(res.len(), 1);
		assert!(matches!(res[0], CorrelationEvent::Completed { .. }));
		Ok(())
	}

	#[test]
	fn threshold_slides_stale_hits_out_of_window() -> Result<()> {
		let mut corr = Correlator::new();
		let seq = mk_threshold_seq(); // 3 within 10s
		let t0 = Instant::now();
		let root = Arc::<str>::from("brute-force");
		corr.on_root_match(&root, &seq, t0, 0);

		// hits at 1s, 7s - instance stays alive (gaps < 10s)
		corr.on_rule_match(
			&Arc::<str>::from("failed-login"),
			&seq,
			&root,
			t0 + Duration::from_secs(1),
			&mk_meta(),
		);
		corr.on_rule_match(
			&Arc::<str>::from("failed-login"),
			&seq,
			&root,
			t0 + Duration::from_secs(7),
			&mk_meta(),
		);
		// hit at 13s: gap from 7s is 6s (< 10s, instance alive), but the 1s hit is now
		// 12s old - outside the 10s window, so it ages out. Deque = {7s, 13s} = 2, no fire.
		let res = corr.on_rule_match(
			&Arc::<str>::from("failed-login"),
			&seq,
			&root,
			t0 + Duration::from_secs(13),
			&mk_meta(),
		);
		assert!(
			res.is_empty(),
			"the 1s hit should have aged out, leaving only 2 in window"
		);
		Ok(())
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
			threshold: None,
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
