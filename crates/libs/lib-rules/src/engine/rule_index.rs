use std::{collections::HashMap, sync::Arc};

use lib_common::event::CerberusEvent;
use lib_event_schema::Field;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::rule::compiled::{response::CompiledResponseChain, ruleset::CompiledRuleSet};

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

fn characteristic_fields(kind: EventKind) -> &'static [Field] {
	match kind {
		EventKind::Generic => &[],
		EventKind::InetSock => &[
			Field::NetworkProtocol,
			Field::NetworkSport,
			Field::NetworkDport,
			Field::NetworkSaddr,
			Field::NetworkDaddr,
			Field::SocketOldState,
			Field::SocketNewState,
		],
		EventKind::Socket => &[Field::SocketPort, Field::SocketFamily, Field::SocketOp],
		EventKind::Bprm => &[Field::ProcessFilepath],
		EventKind::Module => &[Field::ModuleName, Field::ModuleOp],
		EventKind::Inode => &[Field::InodeFilename, Field::InodeOp],
		EventKind::InodeMutate => &[Field::InodeNewFilename, Field::InodeOldFilename, Field::InodeMutationType],
		EventKind::PtraceAccessCheck => &[
			Field::PtraceMode,
			Field::PtraceStage,
			Field::ProcessTargetPid,
			Field::ProcessTargetTgid,
			Field::ProcessTargetUid,
			Field::ProcessTargetComm,
		],
		EventKind::BpfProgLoad => &[Field::BpfProgType, Field::BpfProgAttachType, Field::BpfProgFlags],
		EventKind::BpfMap => &[Field::BpfMapName, Field::BpfMapType, Field::BpfMapId],
	}
}

fn field_in(kind: EventKind, field: Field) -> bool {
	match kind {
		EventKind::Generic => matches!(
			field,
			Field::ProcessUid | Field::ProcessPid | Field::ProcessTgid | Field::ProcessComm
		),

		EventKind::InetSock => matches!(
			field,
			Field::SocketOldState
				| Field::SocketNewState
				| Field::NetworkSport
				| Field::NetworkDport
				| Field::NetworkProtocol
		),
		EventKind::Bprm => matches!(
			field,
			Field::ProcessUid | Field::ProcessPid | Field::ProcessTgid | Field::ProcessComm | Field::ProcessFilepath
		),

		EventKind::Module => matches!(
			field,
			Field::ProcessUid
				| Field::ProcessPid
				| Field::ProcessTgid
				| Field::ProcessComm
				| Field::ModuleName
				| Field::ModuleOp
		),
		EventKind::Inode => matches!(
			field,
			Field::ProcessUid
				| Field::ProcessPid
				| Field::ProcessTgid
				| Field::ProcessComm
				| Field::InodeFilename
				| Field::InodeOp
		),
		EventKind::PtraceAccessCheck => matches!(
			field,
			Field::ProcessUid
				| Field::ProcessPid
				| Field::ProcessTgid
				| Field::ProcessComm
				| Field::ProcessTargetPid
				| Field::ProcessTargetTgid
				| Field::ProcessTargetUid
				| Field::ProcessTargetComm
				| Field::PtraceMode
				| Field::PtraceStage
		),

		EventKind::InodeMutate => matches!(
			field,
			Field::ProcessUid
				| Field::ProcessPid
				| Field::ProcessTgid
				| Field::ProcessComm
				| Field::InodeNewFilename
				| Field::InodeOldFilename
				| Field::InodeMutationType
		),
		EventKind::Socket => matches!(field, Field::SocketPort | Field::SocketFamily | Field::SocketOp),
		EventKind::BpfProgLoad => matches!(
			field,
			Field::ProcessUid
				| Field::ProcessPid
				| Field::ProcessTgid
				| Field::ProcessComm
				| Field::BpfProgType
				| Field::BpfProgAttachType
				| Field::BpfProgFlags
		),
		EventKind::BpfMap => matches!(
			field,
			Field::ProcessUid
				| Field::ProcessPid
				| Field::ProcessTgid
				| Field::ProcessComm
				| Field::BpfMapName
				| Field::BpfMapType
				| Field::BpfMapId
		),
	}
}

pub struct RuleIndex {
	// evt kind -> root rule ids
	pub by_evt_kind: HashMap<EventKind, Vec<Arc<str>>>,
	// step rule id -> root rule ids that have a sequence with this rule from the step
	pub universal_rules: Vec<Arc<str>>,
	pub seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>>,
}

impl RuleIndex {
	pub fn build(ruleset: &CompiledRuleSet) -> Self {
		let mut by_evt_kind: HashMap<EventKind, Vec<Arc<str>>> = HashMap::new();
		let mut seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>> = HashMap::new();
		let mut universal_rules = Vec::new();
		for rule in ruleset.rules() {
			let rule_id = rule.inner.id.clone();
			let rule_fields: Vec<Field> = rule.inner.conditions.iter().map(|c| c.field).collect();
			let mut placed = false;
			for kind in EventKind::iter() {
				let chars = characteristic_fields(kind);
				let has_char = chars.iter().any(|cf| rule_fields.contains(cf));
				let all_available = rule_fields.iter().all(|f| field_in(kind, *f));

				if has_char && all_available {
					by_evt_kind.entry(kind).or_insert_with(Vec::new).push(rule_id.clone());
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
