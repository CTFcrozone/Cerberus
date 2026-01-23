use std::sync::Arc;

use derive_more::From;
use lib_common::event::EventMeta;

use crate::Response;

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
	pub severity: Arc<str>,
	pub rule_type: Arc<str>,
	pub event_meta: EventMeta,
}

#[derive(Debug, Clone)]
pub struct CorrelatedEvent {
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
