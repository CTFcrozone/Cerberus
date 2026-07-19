use std::{net::IpAddr, sync::Arc, time::Duration};

use regex::Regex;

use crate::{
	Rule, Severity,
	error::Result,
	rule::compiled::{
		condition::{CompiledCondition, compile_condition},
		response::{CompiledResponse, compile_response},
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
	pub response: Option<CompiledResponse>,
}

pub fn compile_rule(raw: Rule, hash: [u8; 32], hash_hex: Arc<str>) -> Result<CompiledRule> {
	Ok(CompiledRule {
		hash,
		hash_hex,

		inner: CompiledRuleInner {
			id: raw.inner.id.into(),
			description: raw.inner.description.into(),

			severity: raw.inner.severity,

			conditions: raw
				.inner
				.conditions
				.into_iter()
				.map(compile_condition)
				.collect::<Result<Vec<_>>>()?,

			sequence: raw.inner.sequence.map(compile_sequence).transpose()?,

			response: raw.inner.response.map(compile_response).transpose()?,
		},
	})
}
