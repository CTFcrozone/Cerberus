use std::{collections::HashMap, sync::Arc};

use lib_common::event::CerberusEvent;
use lib_event_schema::Field;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::rule::compiled::ruleset::CompiledRuleSet;

const COMMON: u64 =
	Field::ProcessUid.mask() | Field::ProcessPid.mask() | Field::ProcessTgid.mask() | Field::ProcessComm.mask();

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

fn rule_field_mask(rule: &crate::rule::compiled::rule::CompiledRule) -> u64 {
	rule.inner.conditions.iter().fold(0u64, |acc, c| acc | c.field.mask())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
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

pub struct RuleIndex {
	// Event kind -> rule IDs that may match that event kind.
	pub by_evt_kind: HashMap<EventKind, Vec<Arc<str>>>,

	// Rules that cannot be narrowed to a specific event kind.
	pub universal_rules: Vec<Arc<str>>,

	// Step rule ID -> root rule IDs containing that step.
	pub seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>>,
}

impl RuleIndex {
	pub fn build(ruleset: &CompiledRuleSet) -> Self {
		let mut by_evt_kind: HashMap<EventKind, Vec<Arc<str>>> = HashMap::new();
		let mut seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>> = HashMap::new();
		let mut universal_rules = Vec::new();
		for rule in ruleset.rules() {
			let rule_id = rule.inner.id.clone();
			let used = rule_field_mask(rule);
			let mut placed = false;
			for kind in EventKind::iter() {
				let discriminates = used & kind_chars(kind) != 0;
				let satisfiable = used & !kind_fields(kind) == 0;
				if discriminates && satisfiable {
					by_evt_kind.entry(kind).or_default().push(rule_id.clone());
					placed = true;
				}
			}
			if !placed {
				universal_rules.push(rule_id.clone());
			}

			if let Some(seq) = &rule.inner.sequence {
				for step in &seq.steps {
					seq_listeners.entry(step.rule_id.clone()).or_default().push(rule_id.clone());
				}
			}
		}

		for roots in seq_listeners.values_mut() {
			roots.sort_unstable();
			roots.dedup();
		}

		Self {
			by_evt_kind,
			seq_listeners,
			universal_rules,
		}
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use std::time::Duration;

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

	fn candidates_for(index: &RuleIndex, kind: EventKind) -> Vec<Arc<str>> {
		let specific = index.by_evt_kind.get(&kind).map(|v| v.as_slice()).unwrap_or(&[]);
		specific.iter().chain(index.universal_rules.iter()).cloned().collect()
	}
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
				field_mask: 0,
				required_mask: 0,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
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
			scope: None,
		}
	}

	#[test]
	fn sequence_listener_is_deduplicated_for_repeated_steps() -> Result<()> {
		// -- Setup & Fixtures
		// The step rules must exist: CompiledRuleSet::new now rejects sequences
		// that reference unknown rule ids.
		let ruleset = CompiledRuleSet::new(vec![
			mk_rule("brute-force", Some(mk_seq())),
			mk_rule("failed-login", None),
			mk_rule("success-login", None),
		])?;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		// "failed-login" appears twice in the sequence; the root is listed once.
		let roots = index.seq_listeners.get("failed-login").expect("missing failed-login listener");
		assert_eq!(roots.len(), 1);
		assert_eq!(roots[0], "brute-force".into());

		let roots = index
			.seq_listeners
			.get("success-login")
			.expect("missing success-login listener");
		assert_eq!(roots.len(), 1);
		assert_eq!(roots[0], "brute-force".into());

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

			assert_eq!(kind_chars(kind) & !kind_fields(kind), 0);
		}
	}

	#[test]
	fn process_fields_do_not_demote_a_kind_specific_rule() {
		// `all_available` and fall through to universal_rules.
		let used = Field::NetworkProtocol.mask() | Field::ProcessComm.mask();

		assert!(used & kind_chars(EventKind::InetSock) != 0);
		assert!(used & !kind_fields(EventKind::InetSock) == 0);

		// and network.daddr is both characteristic and available
		let used = Field::NetworkDaddr.mask();
		assert!(used & kind_chars(EventKind::InetSock) != 0);
		assert!(used & !kind_fields(EventKind::InetSock) == 0);
	}

	#[test]
	fn universal_rules_appear_in_every_kind_bucket() -> Result<()> {
		// -- Setup & Fixtures
		// mk_rule has no conditions, so its field mask is 0 and it can never
		// discriminate a kind: it must land in universal_rules.
		let ruleset = CompiledRuleSet::new(vec![mk_rule("everywhere", None)])?;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		assert_eq!(index.universal_rules.len(), 1);
		assert!(
			index.by_evt_kind.is_empty(),
			"a universal rule must not be placed under any specific kind"
		);

		for kind in EventKind::iter() {
			let cands = candidates_for(&index, kind);
			assert!(
				cands.iter().any(|id| id.as_ref() == "everywhere"),
				"{kind:?} does not consider the universal rule"
			);
		}

		Ok(())
	}

	#[test]
	fn kind_specific_rules_are_not_universal() -> Result<()> {
		// -- Setup & Fixtures
		let mut rule = mk_rule("inet-only", None);
		rule.inner.conditions = vec![compile_condition(Condition {
			field: "network.protocol".into(),
			op: "==".into(),
			value: Value::String("TCP".into()),
		})?];

		let ruleset = CompiledRuleSet::new(vec![rule])?;

		// -- Exec
		let index = RuleIndex::build(&ruleset);

		// -- Check
		assert!(index.universal_rules.is_empty());
		assert_eq!(index.by_evt_kind.get(&EventKind::InetSock).map(|v| v.len()), Some(1));

		// and it is considered for InetSock only
		for kind in EventKind::iter() {
			let expected = kind == EventKind::InetSock;
			assert_eq!(
				candidates_for(&index, kind).iter().any(|id| id.as_ref() == "inet-only"),
				expected,
				"{kind:?}"
			);
		}

		Ok(())
	}
}

// endregion: --- Tests
