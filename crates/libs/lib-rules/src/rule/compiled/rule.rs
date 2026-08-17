use std::sync::Arc;

use lib_event_schema::FieldValue;

use crate::{
	Error, Rule, Severity, Trigger,
	error::Result,
	rule::compiled::{
		condition::{CompiledCondition, compile_condition},
		op::Op,
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
	pub response_chain: Option<Arc<CompiledResponseChain>>,
	/// Fields whose *absence* makes this rule fail. Drives the runtime prefilter:
	/// `required_mask & !ctx.present() != 0` means the rule cannot possibly match,
	/// without evaluating a single condition.
	pub required_mask: u64,
}

fn op_cost(cond: &CompiledCondition) -> u8 {
	use FieldValue as V;

	match (cond.op, &cond.value) {
		// presence check, no comparison at all
		(Op::Exists, _) => 0,

		// single-word integer work
		(Op::BitAnd, _) => 1,
		(Op::Gt | Op::Gte | Op::Lt | Op::Lte, _) => 1,
		(Op::Eq | Op::NotEq, V::Int(_) | V::Ip(_) | V::Bool(_)) => 1,

		// string equality: length check, then memcmp
		(Op::Eq | Op::NotEq, _) => 2,

		// linear scan over scalars
		(Op::In | Op::NotIn, V::IntSet(_) | V::IpSet(_)) => 3,

		// linear scan with a string compare per element
		(Op::In | Op::NotIn, _) => 4,

		(Op::StartsWith, _) => 5,
		(Op::Contains, _) => 6,
		(Op::Regex, _) => 7,
	}
}

pub fn compile_rule(raw: Rule, hash: [u8; 32], hash_hex: Arc<str>) -> Result<CompiledRule> {
	let mut conditions = raw
		.inner
		.conditions
		.into_iter()
		.map(compile_condition)
		.collect::<Result<Vec<_>>>()?;

	if conditions.is_empty() {
		return Err(Error::RuleWithoutConditions { rule_id: raw.inner.id });
	}

	conditions.sort_by_key(op_cost);

	let required_mask = conditions.iter().fold(0u64, |acc, c| acc | c.field.mask());

	let sequence = raw.inner.sequence.map(compile_sequence).transpose()?;

	let response_chain = raw.inner.response_chain.map(compile_response_chain).transpose()?.map(Arc::new);

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
			required_mask,
		},
	})
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use lib_event_schema::Field;
	use toml::Value;

	use super::*;
	use crate::rule::{Condition, RuleInner};

	fn cond(field: &str, op: &str, value: Value) -> Condition {
		Condition {
			field: field.into(),
			op: op.into(),
			value,
		}
	}

	fn raw_rule(id: &str, conditions: Vec<Condition>) -> Rule {
		Rule {
			inner: RuleInner {
				id: id.to_string(),
				description: "test".to_string(),
				severity: Severity::Low,
				conditions,
				sequence: None,
				response_chain: None,
			},
			hash: [0u8; 32],
			hash_hex: Arc::from("0".repeat(64)),
		}
	}

	fn compile(raw: Rule) -> Result<CompiledRule> {
		Ok(compile_rule(raw, [0u8; 32], Arc::from("0".repeat(64)))?)
	}

	#[test]
	fn masks_cover_every_referenced_field() -> Result<()> {
		// -- Setup & Fixtures
		let raw = raw_rule(
			"masked",
			vec![
				cond("process.pid", "equals", Value::Integer(1)),
				cond("process.comm", "==", Value::String("bash".into())),
			],
		);

		// -- Exec
		let compiled = compile(raw)?;

		// -- Check
		let expected = Field::ProcessPid.mask() | Field::ProcessComm.mask();
		assert_eq!(compiled.inner.required_mask, expected);

		Ok(())
	}

	#[test]
	fn not_in_requires_presence_like_every_other_op() -> Result<()> {
		let raw = raw_rule(
			"not-in-rule",
			vec![
				cond("process.pid", "equals", Value::Integer(1)),
				cond("process.uid", "not_in", Value::Array(vec![Value::Integer(0)])),
			],
		);

		let compiled = compile(raw)?;

		assert_eq!(
			compiled.inner.required_mask,
			Field::ProcessPid.mask() | Field::ProcessUid.mask()
		);

		Ok(())
	}

	#[test]
	fn empty_conditions_are_rejected() {
		let raw = raw_rule("matches-everything", vec![]);

		let err = compile_rule(raw, [0u8; 32], Arc::from("0".repeat(64)));

		assert!(matches!(err, Err(Error::RuleWithoutConditions { .. })));
	}

	#[test]
	fn exists_is_a_presence_requirement() -> Result<()> {
		// -- Setup & Fixtures
		let raw = raw_rule(
			"exists-rule",
			vec![cond("process.filepath", "exists", Value::Boolean(true))],
		);

		// -- Exec
		let compiled = compile(raw)?;

		// -- Check
		assert_eq!(compiled.inner.required_mask, Field::ProcessFilepath.mask());

		Ok(())
	}

	#[test]
	fn every_op_requires_presence() -> Result<()> {
		// -- Setup & Fixtures
		let cases = [
			("equals", Value::Integer(1)),
			("not_equals", Value::Integer(1)),
			(">", Value::Integer(1)),
			("<=", Value::Integer(1)),
			("bit_and", Value::Integer(1)),
			("not_in", Value::Array(vec![Value::Integer(1)])),
			("exists", Value::Boolean(true)),
			("in", Value::Array(vec![Value::Integer(1)])),
		];

		for (op, value) in cases {
			// -- Exec
			let compiled = compile(raw_rule("op-case", vec![cond("process.pid", op, value)]))?;

			// -- Check
			assert_eq!(
				compiled.inner.required_mask,
				Field::ProcessPid.mask(),
				"op '{op}' should require presence"
			);
		}

		Ok(())
	}
	#[test]
	fn conditions_are_sorted_cheapest_first() -> Result<()> {
		// -- Setup & Fixtures: authored worst-first
		let raw = raw_rule(
			"ordered",
			vec![
				cond("process.comm", "regex", Value::String("^sshd".into())),
				cond("process.filepath", "contains", Value::String("/tmp".into())),
				cond("process.pid", "equals", Value::Integer(42)),
			],
		);

		// -- Exec
		let compiled = compile(raw)?;

		// -- Check
		let costs: Vec<u8> = compiled.inner.conditions.iter().map(op_cost).collect();
		assert_eq!(costs, vec![1, 6, 7], "conditions were not reordered");

		Ok(())
	}

	#[test]
	fn equal_cost_conditions_keep_authored_order() -> Result<()> {
		let raw = raw_rule(
			"stable",
			vec![
				cond("process.tgid", "equals", Value::Integer(1)),
				cond("process.pid", "equals", Value::Integer(2)),
				cond("process.uid", "equals", Value::Integer(3)),
			],
		);

		let compiled = compile(raw)?;

		let fields: Vec<Field> = compiled.inner.conditions.iter().map(|c| c.field).collect();
		assert_eq!(fields, vec![Field::ProcessTgid, Field::ProcessPid, Field::ProcessUid]);

		Ok(())
	}
}

// endregion: --- Tests
