use std::sync::Arc;

use derive_more::From;
use lib_common::event::EventMeta;

use crate::{rule::Severity, Response};

#[derive(Debug, Clone, From)]
pub enum EngineEvent {
	#[from]
	Matched(EvaluatedEvent),
	#[from]
	Correlated(CorrelatedEvent),
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
		base_rule_id: Arc<str>,
		seq_rule_id: Arc<str>,
		base_rule_hash: Arc<str>,
		seq_rule_hash: Arc<str>,
		event_meta: EventMeta,
	},
	Completed {
		root_rule_id: Arc<str>,
		sequence_rule_id: Arc<str>,
		path: Vec<Arc<str>>,
		steps: usize,
		event_meta: EventMeta,
	},
}

#[derive(Debug, Clone)]
pub struct CorrelatedEvent {
	pub seq_id: Arc<str>,
	pub base_rule_id: Arc<str>,
	pub seq_rule_id: Arc<str>,
	pub base_rule_hash: Arc<str>,
	pub seq_rule_hash: Arc<str>,
	pub event_meta: EventMeta,
}

#[derive(Debug, Clone)]
pub struct ResponseRequest {
	pub rule_id: Arc<str>,
	pub response: Response,
	pub event_meta: EventMeta,
}
