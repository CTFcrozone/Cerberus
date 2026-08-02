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
	pub seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>>,
	pub rule_response_chains: HashMap<Arc<str>, CompiledResponseChain>,
}

impl RuleIndex {
	pub fn build(ruleset: &CompiledRuleSet) -> Self {
		let mut by_evt_kind: HashMap<EventKind, Vec<Arc<str>>> = HashMap::new();
		let mut seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>> = HashMap::new();
		let mut rule_response_chains: HashMap<Arc<str>, CompiledResponseChain> = HashMap::new();

		for rule in ruleset.rules() {
			let rule_id = rule.inner.id.clone();

			for kind in EventKind::iter() {
				let matches = rule.inner.conditions.iter().all(|c| field_in(kind, c.field));

				if matches {
					by_evt_kind.entry(kind).or_insert_with(Vec::new).push(rule_id.clone());
				}
			}

			if let Some(seq) = &rule.inner.sequence {
				for step in &seq.steps {
					seq_listeners.entry(step.rule_id.clone()).or_default().push(rule_id.clone());
				}
			}

			if let Some(chain) = &rule.inner.response_chain {
				rule_response_chains.insert(rule_id, chain.clone());
			}
		}

		Self {
			by_evt_kind,
			seq_listeners,
			rule_response_chains,
		}
	}
}
