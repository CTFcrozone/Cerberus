use lib_event_schema::FieldValue;

use crate::{
	engine::EvalCtx,
	rule::compiled::{condition::CompiledCondition, op::Op, rule::CompiledRuleInner},
};

pub struct Evaluator;

impl Evaluator {
	pub fn eval_condition_compiled(left: Option<&FieldValue>, cond: &CompiledCondition) -> bool {
		match cond.op {
			Op::Eq => left.map_or(false, |l| Self::equals_compiled(l, &cond.value)),
			Op::NotEq => left.map_or(false, |l| !Self::equals_compiled(l, &cond.value)),

			Op::StartsWith => match (left, &cond.value) {
				(Some(FieldValue::String(a)), FieldValue::String(b)) => a.starts_with(b.as_ref()),
				_ => false,
			},
			Op::Contains => match (left, &cond.value) {
				(Some(FieldValue::String(a)), FieldValue::String(b)) => a.contains(b.as_ref()),
				_ => false,
			},
			Op::Regex => match (left, &cond.value) {
				(Some(FieldValue::String(text)), FieldValue::Regex(regex)) => regex.is_match(text),
				_ => false,
			},

			Op::BitAnd => match (left, &cond.value) {
				(Some(FieldValue::Int(a)), FieldValue::Int(b)) => (a & b) != 0,
				_ => false,
			},

			Op::In => Self::eval_in(left, &cond.value),
			Op::NotIn => !Self::eval_in(left, &cond.value),
			Op::Exists => left.is_some(),
			Op::Gt => Self::numeric_cmp_compiled(left, &cond.value, |a, b| a > b),
			Op::Gte => Self::numeric_cmp_compiled(left, &cond.value, |a, b| a >= b),
			Op::Lt => Self::numeric_cmp_compiled(left, &cond.value, |a, b| a < b),
			Op::Lte => Self::numeric_cmp_compiled(left, &cond.value, |a, b| a <= b),
		}
	}

	fn eval_in(left: Option<&FieldValue>, right: &FieldValue) -> bool {
		let Some(left) = left else {
			return false;
		};

		match (left, right) {
			(FieldValue::Int(v), FieldValue::IntSet(set)) => set.contains(v),
			(FieldValue::String(v), FieldValue::StringSet(set)) => set.iter().any(|x| x == v),
			(FieldValue::Ip(v), FieldValue::IpSet(set)) => set.contains(v),
			_ => false,
		}
	}

	fn numeric_cmp_compiled<F>(left: Option<&FieldValue>, right: &FieldValue, cmp: F) -> bool
	where
		F: Fn(f64, f64) -> bool,
	{
		let Some(FieldValue::Int(a)) = left else {
			return false;
		};

		let Some(FieldValue::Int(b)) = Some(right) else {
			return false;
		};

		cmp(*a as f64, *b as f64)
	}

	fn equals_compiled(left: &FieldValue, right: &FieldValue) -> bool {
		match (left, right) {
			(FieldValue::Int(a), FieldValue::Int(b)) => a == b,

			(FieldValue::String(a), FieldValue::String(b)) => a == b,

			(FieldValue::Bool(a), FieldValue::Bool(b)) => a == b,

			(FieldValue::Ip(a), FieldValue::Ip(b)) => a == b,
			_ => false,
		}
	}

	pub fn rule_matches_compiled(rule: &CompiledRuleInner, ctx: &EvalCtx) -> bool {
		rule.conditions.iter().all(|cond| {
			let left = ctx.get_field(&cond.field);
			Self::eval_condition_compiled(left, cond)
		})
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use crate::{
		Severity,
		rule::{Condition, compiled::condition::compile_condition},
	};

	use super::*;
	use lib_event_schema::Field;
	use std::collections::HashMap;
	use toml::Value;

	fn ctx(fields: &[(Field, FieldValue)]) -> EvalCtx {
		let map: HashMap<Field, FieldValue> = fields.iter().map(|(k, v)| (*k, v.clone())).collect();

		EvalCtx::new(map)
	}

	fn compiled_cond(field: &str, op: &str, value: Value) -> Result<CompiledCondition> {
		Ok(compile_condition(Condition {
			field: field.into(),
			op: op.into(),
			value,
		})?)
	}

	#[test]
	fn eval_equals_and_exists() -> Result<()> {
		// -- Setup & Fixtures
		let equals = compiled_cond("process.pid", "equals", Value::Integer(42))?;
		let exists = compiled_cond("process.pid", "exists", Value::Boolean(true))?;
		let ctx = ctx(&[(Field::ProcessPid, FieldValue::Int(42))]);
		// -- Exec
		let equals_res = Evaluator::eval_condition_compiled(ctx.get_field(&equals.field), &equals);
		let exists_res = Evaluator::eval_condition_compiled(ctx.get_field(&exists.field), &exists);
		// -- Check
		assert!(equals_res);
		assert!(exists_res);

		Ok(())
	}

	#[test]
	fn eval_in_and_not_in() -> Result<()> {
		// -- Setup & Fixtures
		let in_cond = compiled_cond(
			"process.uid",
			"in",
			Value::Array(vec![Value::Integer(1000), Value::Integer(2000)]),
		)?;

		let not_in_cond = compiled_cond(
			"process.uid",
			"not_in",
			Value::Array(vec![Value::Integer(0), Value::Integer(1)]),
		)?;

		let ctx = ctx(&[(Field::ProcessUid, FieldValue::Int(1000))]);

		// -- Exec
		let in_res = Evaluator::eval_condition_compiled(ctx.get_field(&in_cond.field), &in_cond);

		let not_in_res = Evaluator::eval_condition_compiled(ctx.get_field(&not_in_cond.field), &not_in_cond);

		// -- Check
		assert!(in_res);
		assert!(not_in_res);

		Ok(())
	}

	#[test]
	fn eval_regex_and_numeric() -> Result<()> {
		// -- Setup & Fixtures
		let regex = compiled_cond("process.comm", "regex", Value::String("^sshd".into()))?;

		let gt = compiled_cond("process.pid", ">", Value::Integer(10))?;

		let lt = compiled_cond("process.pid", "<", Value::Integer(200))?;

		let ctx = ctx(&[
			(Field::ProcessComm, FieldValue::String("sshd: worker".into())),
			(Field::ProcessPid, FieldValue::Int(100)),
		]);

		// -- Exec
		let regex_res = Evaluator::eval_condition_compiled(ctx.get_field(&regex.field), &regex);

		let gt_res = Evaluator::eval_condition_compiled(ctx.get_field(&gt.field), &gt);

		let lt_res = Evaluator::eval_condition_compiled(ctx.get_field(&lt.field), &lt);

		// -- Check
		assert!(regex_res);
		assert!(gt_res);
		assert!(lt_res);

		Ok(())
	}

	#[test]
	fn rule_matches_success_and_failure() -> Result<()> {
		// -- Setup & Fixtures
		let rule_ok = CompiledRuleInner {
			id: "ok".into(),
			description: "ok".into(),
			severity: Severity::Info,

			conditions: vec![
				compiled_cond("process.pid", "equals", Value::Integer(123))?,
				compiled_cond("process.comm", "==", Value::String("bash".into()))?,
			],

			sequence: None,
			response_chain: None,
		};

		let ctx_ok = ctx(&[
			(Field::ProcessPid, FieldValue::Int(123)),
			(Field::ProcessComm, FieldValue::String("bash".into())),
		]);

		let rule_fail = CompiledRuleInner {
			id: "fail".into(),
			description: "fail".into(),
			severity: Severity::Info,

			conditions: vec![
				compiled_cond("process.pid", "equals", Value::Integer(123))?,
				compiled_cond("process.uid", "equals", Value::Integer(0))?,
			],

			sequence: None,
			response_chain: None,
		};

		let ctx_fail = ctx(&[
			(Field::ProcessPid, FieldValue::Int(123)),
			(Field::ProcessUid, FieldValue::Int(1000)),
		]);

		// -- Exec
		let ok = Evaluator::rule_matches_compiled(&rule_ok, &ctx_ok);
		let fail = Evaluator::rule_matches_compiled(&rule_fail, &ctx_fail);

		// -- Check
		assert!(ok);
		assert!(!fail);

		Ok(())
	}
}

// endregion: --- Tests
