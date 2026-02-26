use std::{collections::HashMap, sync::Arc};

use lib_common::event::CerberusEvent;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::RuleSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum EventKind {
	Generic,
	InetSock,
	SocketConnect,
	Module,
	BpfProgLoad,
	Bprm,
}

impl From<&CerberusEvent> for EventKind {
	fn from(value: &CerberusEvent) -> Self {
		match value {
			CerberusEvent::Generic(_) => EventKind::Generic,
			CerberusEvent::Bprm(_) => EventKind::Bprm,
			CerberusEvent::InetSock(_) => EventKind::InetSock,
			CerberusEvent::Module(_) => EventKind::Module,
			CerberusEvent::SocketConnect(_) => EventKind::SocketConnect,
			CerberusEvent::BpfProgLoad(_) => EventKind::BpfProgLoad,
		}
	}
}

fn field_in(kind: EventKind, field: &str) -> bool {
	match kind {
		EventKind::Generic => matches!(field, "name" | "uid" | "pid" | "tgid" | "comm"),
		EventKind::InetSock => matches!(field, "old_state" | "new_state" | "sport" | "dport" | "protocol"),
		EventKind::Bprm => matches!(field, "uid" | "pid" | "tgid" | "comm" | "filepath"),
		EventKind::Module => matches!(field, "uid" | "pid" | "tgid" | "comm" | "module_name"),
		EventKind::SocketConnect => matches!(field, "port" | "family"),
		EventKind::BpfProgLoad => matches!(
			field,
			"uid"
				| "pid" | "tgid"
				| "comm" | "bpf_prog.prog_type"
				| "bpf_prog.attach_type"
				| "bpf_prog.flags"
				| "bpf_prog.tag"
		),
	}
}

pub struct RuleIndex {
	// evt kind -> root rule ids
	pub by_evt_kind: HashMap<EventKind, Vec<Arc<str>>>,
	// step rule id -> root rule ids that have a sequence with this rule from the step
	pub seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>>,
}

impl RuleIndex {
	pub fn build(ruleset: RuleSet) -> Self {
		let mut by_evt_kind: HashMap<EventKind, Vec<Arc<str>>> = HashMap::new();
		let mut seq_listeners: HashMap<Arc<str>, Vec<Arc<str>>> = HashMap::new();

		for rule in ruleset.ruleset {
			let mut supported = Vec::new();
			let rule_id: Arc<str> = rule.inner.id.into();

			for kind in EventKind::iter() {
				let ok = rule.inner.conditions.iter().all(|c| field_in(kind, &c.field));
				if ok {
					supported.push(kind);
				}
			}

			for kind in supported {
				by_evt_kind.entry(kind).or_default().push(rule_id.clone());
			}

			if let Some(seq) = rule.inner.sequence {
				for step in seq.steps {
					seq_listeners.entry(step.rule_id.into()).or_default().push(rule_id.clone());
				}
			}
		}

		Self {
			by_evt_kind,
			seq_listeners,
		}
	}
}
