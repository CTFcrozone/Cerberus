use std::{collections::HashMap, time::Instant};

use lib_event::app_evt_types::EvaluatedEvent;

use crate::{
	rule::{self, RuleInner},
	sequence::{Sequence, SequenceProgress},
};

#[derive(Debug, Clone)]
pub struct CorrelatedAlert {
	pub rule_id: String,
	pub pid: u32,
	pub severity: String,
}

pub struct CorrelationEngine {
	pub active: HashMap<(String, u32), SequenceProgress>,
}

impl CorrelationEngine {
	pub fn new() -> Self {
		Self { active: HashMap::new() }
	}
	fn process_rule_sequence(
		&mut self,
		seq: &Sequence,
		rule: &RuleInner,
		evt: &EvaluatedEvent,
	) -> Option<CorrelatedAlert> {
		todo!()
	}

	pub fn event_match(&mut self, rule_inner: &RuleInner, evt: &EvaluatedEvent) -> Option<CorrelatedAlert> {
		match &rule_inner.sequence {
			Some(seq) => match seq.kind {
				crate::sequence::SequenceKind::Event => None, // TODO
				crate::sequence::SequenceKind::Rule => self.process_rule_sequence(&seq, rule_inner, evt),
			},
			None => None,
		}
	}
}
