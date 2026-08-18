use lib_common::event::CerberusEvent;
use lib_event_schema::Field;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

use crate::rule::compiled::ruleset::CompiledRuleSet;

const COMMON: u64 = Field::ProcessUid.mask()
	| Field::ProcessPid.mask()
	| Field::ProcessTgid.mask()
	| Field::ProcessComm.mask()
	| Field::ProcessParentComm.mask();

pub const fn kind_fields(kind: EventKind) -> u64 {
	use Field::*;
	COMMON
		| match kind {
			EventKind::Generic => 0,
			EventKind::Bprm => ProcessFilepath.mask(),
			EventKind::InetSock => {
				NetworkSport.mask()
					| NetworkDport.mask()
					| NetworkSaddr.mask()
					| NetworkDaddr.mask()
					| NetworkProtocol.mask()
					| SocketOldState.mask()
					| SocketNewState.mask()
			}
			EventKind::Socket => SocketPort.mask() | SocketFamily.mask() | SocketOp.mask(),
			EventKind::Module => ModuleName.mask() | ModuleOp.mask(),
			EventKind::Inode => InodeFilename.mask() | InodeOp.mask(),
			EventKind::InodeMutate => InodeNewFilename.mask() | InodeOldFilename.mask() | InodeMutationType.mask(),
			EventKind::PtraceAccessCheck => {
				ProcessTargetPid.mask()
					| ProcessTargetTgid.mask()
					| ProcessTargetUid.mask()
					| ProcessTargetComm.mask()
					| PtraceMode.mask()
					| PtraceStage.mask()
			}
			EventKind::BpfProgLoad => BpfProgType.mask() | BpfProgAttachType.mask() | BpfProgFlags.mask(),
			EventKind::BpfMap => BpfMapName.mask() | BpfMapType.mask() | BpfMapId.mask(),
		}
}

#[inline]
pub const fn kind_chars(kind: EventKind) -> u64 {
	kind_fields(kind) & !COMMON
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumCount, EnumIter)]
pub enum EventKind {
	Generic,
	InetSock,
	Socket,
	Module,
	BpfProgLoad,
	PtraceAccessCheck,
	BpfMap,
	Inode,
	InodeMutate,
	Bprm,
}

impl From<&CerberusEvent> for EventKind {
	fn from(value: &CerberusEvent) -> Self {
		match value {
			CerberusEvent::Generic(_) => EventKind::Generic,
			CerberusEvent::Bprm(_) => EventKind::Bprm,
			CerberusEvent::InetSock(_) => EventKind::InetSock,
			CerberusEvent::Module(_) => EventKind::Module,
			CerberusEvent::Socket(_) => EventKind::Socket,
			CerberusEvent::BpfProgLoad(_) => EventKind::BpfProgLoad,
			CerberusEvent::Inode(_) => EventKind::Inode,
			CerberusEvent::BpfMap(_) => EventKind::BpfMap,
			CerberusEvent::InodeMutation(_) => EventKind::InodeMutate,
			CerberusEvent::PtraceAccessCheck(_) => EventKind::PtraceAccessCheck,
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
	pub idx: u32,
}

pub struct RuleIndex {
	// Event kind -> candidates, kind-specific first then universal.
	candidates: [Vec<Candidate>; EventKind::COUNT],

	// Dense: one slot per rule, empty for the common case.
	seq_listeners: Vec<Vec<u32>>,

	// Rules that could not be narrowed to a kind. Kept for introspection.
	universal: Vec<Candidate>,
}

impl RuleIndex {
	pub fn build(ruleset: &CompiledRuleSet) -> Self {
		let rules = ruleset.rules();

		let mut per_kind: [Vec<Candidate>; EventKind::COUNT] = core::array::from_fn(|_| Vec::new());
		let mut universal: Vec<Candidate> = Vec::new();
		let mut seq_listeners: Vec<Vec<u32>> = vec![Vec::new(); rules.len()];

		for (i, rule) in rules.iter().enumerate() {
			let idx = i as u32;
			let used = rule.inner.required_mask;
			let cand = Candidate { idx };
			let mut placed = false;
			for kind in EventKind::iter() {
				let discriminates = used & kind_chars(kind) != 0;
				let satisfiable = used & !kind_fields(kind) == 0;

				if discriminates && satisfiable {
					per_kind[kind as usize].push(cand);
					placed = true;
				}
			}

			if !placed {
				universal.push(cand);
			}

			// A rule whose fields no single kind can supply is evaluated against every
			// event and can never match. Almost always a typo.
			// if used != 0 && !EventKind::iter().any(|k| used & !kind_fields(k) == 0) {
			// 	tracing::warn!(
			// 		rule.id = %rule.inner.id,
			// 		"rule references fields that no single event kind provides; it can never match"
			// 	);
			// }

			if let Some(seq) = &rule.inner.sequence {
				for step in &seq.steps {
					// CompiledRuleSet::new rejects unknown step ids, so this always resolves
					let Some(step_idx) = ruleset.index_of(&step.rule_id) else {
						continue;
					};

					seq_listeners[step_idx].push(idx);
				}
			}
		}

		for roots in seq_listeners.iter_mut() {
			roots.sort_unstable();
			roots.dedup();
		}

		let mut candidates = per_kind;
		for bucket in candidates.iter_mut() {
			bucket.extend_from_slice(&universal);
			bucket.shrink_to_fit();
		}

		Self {
			candidates,
			seq_listeners,
			universal,
		}
	}

	#[inline]
	pub fn candidates(&self, kind: EventKind) -> &[Candidate] {
		&self.candidates[kind as usize]
	}

	/// Root rules whose sequences list `rule_idx` as a step. Empty for most rules.
	#[inline]
	pub fn seq_roots(&self, rule_idx: u32) -> &[u32] {
		self.seq_listeners.get(rule_idx as usize).map(|v| v.as_slice()).unwrap_or(&[])
	}

	#[inline]
	pub fn universal(&self) -> &[Candidate] {
		&self.universal
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use std::{sync::Arc, time::Duration};

	use lib_common::event::*;
	use lib_event_schema::FieldValue;
	use strum::EnumCount;
	use toml::Value;

	use crate::rule::{
		Condition, SequenceKind,
		compiled::{
			condition::compile_condition,
			rule::{CompiledRule, CompiledRuleInner},
			sequence::{CompiledSequence, CompiledStep},
		},
	};

	use super::*;

	fn mask_of(fields: &[Option<FieldValue>; Field::COUNT]) -> u64 {
		fields
			.iter()
			.enumerate()
			.fold(0u64, |acc, (i, slot)| acc | ((slot.is_some() as u64) << i))
	}

	fn hdr() -> EventHeader {
		EventHeader {
			container: None,
			comm: Arc::from("test"),
			ts: 0,
			cgroup_id: 0,
			mnt_ns: 0,
			pid: 1,
			ppid: 1,
			uid: 0,
			tgid: 1,
			parent_comm: Arc::from("test"),
		}
	}

	fn dummy_event(kind: EventKind) -> CerberusEvent {
		match kind {
			EventKind::Generic => CerberusEvent::Generic(RingBufEvent {
				header: hdr(),
				name: "TEST",
				meta: 0,
				meta_type: 0,
			}),
			EventKind::InetSock => CerberusEvent::InetSock(InetSockEvent {
				header: hdr(),
				old_state: Arc::from("TCP_SYN_SENT"),
				new_state: Arc::from("TCP_ESTABLISHED"),
				protocol: Arc::from("TCP"),
				saddr: 0,
				daddr: 0,
				sport: 0,
				dport: 0,
			}),
			EventKind::Socket => CerberusEvent::Socket(SocketEvent {
				header: hdr(),
				addr: 0,
				port: 0,
				family: 0,
				op: 0,
			}),
			EventKind::Module => CerberusEvent::Module(ModuleEvent {
				header: hdr(),
				module_name: Arc::from("mod"),
				op: 0,
			}),
			EventKind::BpfProgLoad => CerberusEvent::BpfProgLoad(BpfProgLoadEvent {
				header: hdr(),
				tag: Arc::from("tag"),
				prog_type: 0,
				attach_type: 0,
				flags: 0,
			}),
			EventKind::PtraceAccessCheck => CerberusEvent::PtraceAccessCheck(PtraceAccessCheckEvent {
				header: hdr(),
				target_pid: 0,
				target_tgid: 0,
				target_uid: 0,
				mode: 0,
				stage: 0,
				target_comm: Arc::from("target"),
			}),
			EventKind::BpfMap => CerberusEvent::BpfMap(BpfMapEvent {
				header: hdr(),
				map_name: Arc::from("map"),
				map_type: Arc::from("hash"),
				map_id: 0,
			}),
			EventKind::Inode => CerberusEvent::Inode(InodeEvent {
				header: hdr(),
				filename: Arc::from("/tmp/f"),
				filename_len: 6,
				op: 0,
			}),
			EventKind::InodeMutate => CerberusEvent::InodeMutation(InodeMutationEvent {
				header: hdr(),
				new_filename: Arc::from("/tmp/b"),
				old_filename: Arc::from("/tmp/a"),
				new_filename_len: 6,
				old_filename_len: 6,
				mutation: 0,
			}),
			EventKind::Bprm => CerberusEvent::Bprm(BprmSecurityEvent {
				header: hdr(),
				filepath: Arc::from("/bin/sh"),
				path_len: 7,
			}),
		}
	}

	fn mk_rule(id: &str, sequence: Option<CompiledSequence>) -> CompiledRule {
		CompiledRule {
			inner: CompiledRuleInner {
				id: id.into(),
				description: "test".into(),
				severity: crate::rule::Severity::Medium,
				conditions: vec![],
				sequence,
				response_chain: None,
				required_mask: 0,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
		}
	}

	fn mk_rule_with(id: &str, conds: Vec<Condition>) -> Result<CompiledRule> {
		let conditions = conds
			.into_iter()
			.map(compile_condition)
			.collect::<core::result::Result<Vec<_>, _>>()?;

		let required_mask = conditions.iter().fold(0u64, |acc, c| acc | c.field.mask());

		Ok(CompiledRule {
			inner: CompiledRuleInner {
				id: id.into(),
				description: "test".into(),
				severity: crate::rule::Severity::Medium,
				conditions,
				sequence: None,
				response_chain: None,
				required_mask,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
		})
	}

	fn cond(field: &str, op: &str, value: Value) -> Condition {
		Condition {
			field: field.into(),
			op: op.into(),
			value,
		}
	}

	fn mk_seq() -> CompiledSequence {
		CompiledSequence {
			id: "test".into(),
			kind: SequenceKind::Rule,
			steps: vec![
				CompiledStep {
					rule_id: "failed-login".into(),
					within: Duration::from_secs(10),
				},
				CompiledStep {
					rule_id: "failed-login".into(),
					within: Duration::from_secs(15),
				},
				CompiledStep {
					rule_id: "success-login".into(),
					within: Duration::from_secs(15),
				},
			],
			threshold: None,
			scope: None,
		}
	}

	#[test]
	fn sequence_listener_is_deduplicated_for_repeated_steps() -> Result<()> {
		// -- Setup & Fixtures
		// The step rules must exist: CompiledRuleSet::new rejects sequences that
		// reference unknown rule ids.
		let ruleset = CompiledRuleSet::new(vec![
			mk_rule("brute-force", Some(mk_seq())),
			mk_rule("failed-login", None),
			mk_rule("success-login", None),
		])?;

		let brute = ruleset.index_of("brute-force").expect("brute-force missing") as u32;
		let failed = ruleset.index_of("failed-login").expect("failed-login missing") as u32;
		let success = ruleset.index_of("success-login").expect("success-login missing") as u32;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		// "failed-login" appears twice in the sequence; the root is listed once.
		assert_eq!(index.seq_roots(failed), &[brute]);
		assert_eq!(index.seq_roots(success), &[brute]);

		// the root itself is not a step of anything
		assert!(index.seq_roots(brute).is_empty());

		Ok(())
	}

	#[test]
	fn kind_masks_match_to_fields() {
		for kind in EventKind::iter() {
			let event = dummy_event(kind);

			// the fixture really is the kind it claims to be
			assert_eq!(
				EventKind::from(&event),
				kind,
				"dummy_event({kind:?}) is the wrong variant"
			);

			assert_eq!(
				mask_of(&event.to_fields()),
				kind_fields(kind),
				"kind_fields({kind:?}) disagrees with to_fields(); update the mask table"
			);

			// chars is derived
			assert_eq!(kind_chars(kind) & !kind_fields(kind), 0);
		}
	}

	#[test]
	fn process_fields_do_not_demote_a_kind_specific_rule() {
		let used = Field::NetworkProtocol.mask() | Field::ProcessComm.mask();

		assert!(used & kind_chars(EventKind::InetSock) != 0);
		assert!(used & !kind_fields(EventKind::InetSock) == 0);

		let used = Field::NetworkDaddr.mask();
		assert!(used & kind_chars(EventKind::InetSock) != 0);
		assert!(used & !kind_fields(EventKind::InetSock) == 0);
	}

	#[test]
	fn common_fields_alone_do_not_pin_a_rule_to_a_kind() -> Result<()> {
		// process.* is carried by every kind, so it discriminates nothing.
		let rule = mk_rule_with("pid-only", vec![cond("process.pid", "equals", Value::Integer(1))])?;
		let ruleset = CompiledRuleSet::new(vec![rule])?;

		let index = RuleIndex::build(&ruleset);

		assert_eq!(index.universal().len(), 1);

		Ok(())
	}

	#[test]
	fn universal_rules_appear_in_every_kind_bucket() -> Result<()> {
		// -- Setup & Fixtures
		let ruleset = CompiledRuleSet::new(vec![mk_rule("everywhere", None)])?;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		assert_eq!(index.universal().len(), 1);

		for kind in EventKind::iter() {
			let cands = index.candidates(kind);
			assert_eq!(cands.len(), 1, "{kind:?} bucket missing the universal rule");
			assert_eq!(cands[0].idx, 0);
		}

		Ok(())
	}

	#[test]
	fn kind_specific_rules_are_not_universal() -> Result<()> {
		// -- Setup & Fixtures
		// Includes process.comm on purpose: the P3 regression case.
		let rule = mk_rule_with(
			"inet-only",
			vec![
				cond("network.protocol", "==", Value::String("TCP".into())),
				cond("process.comm", "==", Value::String("curl".into())),
			],
		)?;
		let ruleset = CompiledRuleSet::new(vec![rule])?;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		assert!(index.universal().is_empty(), "rule was demoted to universal");

		for kind in EventKind::iter() {
			let expected = usize::from(kind == EventKind::InetSock);
			assert_eq!(index.candidates(kind).len(), expected, "{kind:?}");
		}

		Ok(())
	}
	#[test]
	fn required_mask_places_a_rule_under_its_kind() -> Result<()> {
		// -- Setup & Fixtures
		let rule = mk_rule_with(
			"inode-rule",
			vec![cond("inode.filename", "starts_with", Value::String("/tmp".into()))],
		)?;
		let ruleset = CompiledRuleSet::new(vec![rule])?;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		assert!(index.universal().is_empty());
		assert_eq!(index.candidates(EventKind::Inode).len(), 1);
		assert_eq!(index.candidates(EventKind::Generic).len(), 0);

		Ok(())
	}
	#[test]
	fn seq_roots_is_empty_for_unknown_index() -> Result<()> {
		let ruleset = CompiledRuleSet::new(vec![])?;
		let index = RuleIndex::build(&ruleset);

		assert!(index.seq_roots(0).is_empty());
		assert!(index.seq_roots(9999).is_empty());

		Ok(())
	}
}

// endregion: --- Tests
