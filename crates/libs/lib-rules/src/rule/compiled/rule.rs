use std::sync::Arc;

use crate::{
	Error, Rule, Severity, Trigger,
	error::Result,
	rule::compiled::{
		condition::{CompiledCondition, compile_condition},
		response::{CompiledResponseChain, compile_response_chain},
		sequence::{CompiledSequence, compile_sequence},
	},
};

pub struct CompiledRule {
	pub inner: CompiledRuleInner,
	pub hash: [u8; 32],
	pub hash_hex: Arc<str>,
}

pub struct CompiledRuleInner {
	pub id: Arc<str>,
	pub description: Arc<str>,
	pub severity: Severity,
	pub conditions: Vec<CompiledCondition>,
	pub sequence: Option<CompiledSequence>,
	pub response_chain: Option<CompiledResponseChain>,
}

pub fn compile_rule(raw: Rule, hash: [u8; 32], hash_hex: Arc<str>) -> Result<CompiledRule> {
	let conditions = raw
		.inner
		.conditions
		.into_iter()
		.map(compile_condition)
		.collect::<Result<Vec<_>>>()?;

	let sequence = raw.inner.sequence.map(compile_sequence).transpose()?;

	let response_chain = raw.inner.response_chain.map(compile_response_chain).transpose()?;

	if let Some(chain) = &response_chain {
		if matches!(chain.trigger, Trigger::SequenceFinished) && sequence.is_none() {
			return Err(Error::SequenceFinishedTriggerWithoutSequence { rule_id: raw.inner.id });
		}
	}

	Ok(CompiledRule {
		hash,
		hash_hex,
		inner: CompiledRuleInner {
			id: raw.inner.id.into(),
			description: raw.inner.description.into(),
			severity: raw.inner.severity,
			conditions,
			sequence,
			response_chain,
		},
	})
}
