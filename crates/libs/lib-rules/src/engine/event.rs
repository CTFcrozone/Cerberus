use std::{collections::HashMap, sync::Arc};

use derive_more::From;
use lib_common::event::EventMeta;
use lib_event_schema::{Field, FieldValue};
use strum::EnumCount;

use crate::rule::{Severity, compiled::response::CompiledResponseChain};

#[derive(Debug, Clone, From)]
pub enum EngineEvent {
	#[from]
	Matched(EvaluatedEvent),
	#[from]
	Correlation(CorrelationEvent),
	#[from]
	Response(ResponseRequest),
}

#[derive(Debug, Clone)]
pub struct EvaluatedEvent {
	pub rule_id: Arc<str>,
	pub rule_hash: Arc<str>,
	pub severity: Severity,
	pub event_meta: EventMeta,
}
#[derive(Debug, Clone)]
pub enum CorrelationEvent {
	Step {
		root_rule_id: Arc<str>,
		seq_id: Arc<str>,
		seq_instance_id: Arc<str>,
		step_idx: usize,
		matched_rule_id: Arc<str>,
	},
	Completed {
		root_rule_id: Arc<str>,
		seq_id: Arc<str>,
		seq_instance_id: Arc<str>,
		path: Vec<Arc<str>>,
		steps: usize,
		event_meta: EventMeta,
	},
}

#[derive(Debug, Clone)]
pub struct ResponseRequest {
	pub rule_id: Arc<str>,
	pub response_chain: CompiledResponseChain,
	pub event_meta: EventMeta,
	pub fields: Arc<[Option<FieldValue>; Field::COUNT]>,
}
