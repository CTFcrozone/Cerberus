use std::sync::Arc;

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
	/// Every field this rule mentions. Drives index placement.
	pub field_mask: u64,
	/// Fields whose *absence* makes this rule fail. Drives the runtime prefilter:
	/// `required_mask & !ctx.present() != 0` means the rule cannot possibly match,
	/// without evaluating a single condition.
	pub required_mask: u64,
}

fn condition_masks(conditions: &[CompiledCondition]) -> (u64, u64) {
	let mut field_mask = 0u64;
	let mut required_mask = 0u64;

	for c in conditions {
		let bit = c.field.mask();
		field_mask |= bit;

		if !matches!(c.op, Op::NotIn) {
			required_mask |= bit;
		}
	}

	(field_mask, required_mask)
}

pub fn compile_rule(raw: Rule, hash: [u8; 32], hash_hex: Arc<str>) -> Result<CompiledRule> {
	let conditions = raw
		.inner
		.conditions
		.into_iter()
		.map(compile_condition)
		.collect::<Result<Vec<_>>>()?;

	if conditions.is_empty() {
		return Err(Error::RuleWithoutConditions { rule_id: raw.inner.id });
	}

	let (field_mask, required_mask) = condition_masks(&conditions);

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
			field_mask,
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
		assert_eq!(compiled.inner.field_mask, expected);
		assert_eq!(compiled.inner.required_mask, expected);

		Ok(())
	}

	#[test]
	fn not_in_is_excluded_from_required_mask() -> Result<()> {
		// -- Setup & Fixtures
		// `not_in` on a missing field evaluates to TRUE, so it must not be treated as
		// a presence requirement. This is the mask bug that silently drops matches.
		let raw = raw_rule(
			"not-in-rule",
			vec![
				cond("process.pid", "equals", Value::Integer(1)),
				cond("process.uid", "not_in", Value::Array(vec![Value::Integer(0)])),
			],
		);

		// -- Exec
		let compiled = compile(raw)?;

		// -- Check
		assert_eq!(
			compiled.inner.field_mask,
			Field::ProcessPid.mask() | Field::ProcessUid.mask()
		);
		assert_eq!(compiled.inner.required_mask, Field::ProcessPid.mask());
		assert_eq!(compiled.inner.required_mask & Field::ProcessUid.mask(), 0);

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
	fn every_op_except_not_in_requires_presence() -> Result<()> {
		// -- Setup & Fixtures
		// Guards against a new op being added to Evaluator without revisiting
		// condition_masks.
		let cases = [
			("equals", Value::Integer(1)),
			("not_equals", Value::Integer(1)),
			(">", Value::Integer(1)),
			("<=", Value::Integer(1)),
			("bit_and", Value::Integer(1)),
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
}

// endregion: --- Tests
