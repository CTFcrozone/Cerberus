use std::sync::Arc;

use derive_more::From;
use lib_common::event::EventMeta;

use crate::{Response, rule::Severity};

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
	pub rule_type: Arc<str>,
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
	pub response: Response,
	pub event_meta: EventMeta,
}
