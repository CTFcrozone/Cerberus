use std::net::IpAddr;

use toml::Value;

use crate::{
	engine::EvalCtx,
	rule::compiled::{
		condition::{CompiledCondition, CompiledConditionValue},
		op::Op,
		rule::CompiledRuleInner,
	},
};

pub struct Evaluator;

impl Evaluator {
	pub fn eval_condition_compiled(left: Option<&Value>, cond: &CompiledCondition) -> bool {
		match cond.op {
			Op::Eq => left.map_or(false, |l| Self::equals_compiled(l, &cond.value)),
			Op::NotEq => left.map_or(false, |l| !Self::equals_compiled(l, &cond.value)),
			Op::StartsWith => match (left, &cond.value) {
				(Some(Value::String(a)), CompiledConditionValue::String(b)) => a.starts_with(b.as_ref()),

				_ => false,
			},
			Op::Contains => match (left, &cond.value) {
				(Some(Value::String(a)), CompiledConditionValue::String(b)) => a.contains(b.as_ref()),
				_ => false,
			},
			Op::Regex => match (left, &cond.value) {
				(Some(Value::String(text)), CompiledConditionValue::Regex(regex)) => regex.is_match(text),

				_ => false,
			},
			Op::BitAnd => match (left, &cond.value) {
				(Some(Value::Integer(a)), CompiledConditionValue::Int(b)) => (*a & *b) != 0,
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

	fn eval_in(left: Option<&Value>, right: &CompiledConditionValue) -> bool {
		let Some(left) = left else {
			return false;
		};

		match (left, right) {
			(Value::Integer(v), CompiledConditionValue::IntSet(set)) => set.contains(v),
			(Value::String(v), CompiledConditionValue::StringSet(set)) => set.iter().any(|x| x.as_ref() == v),
			(Value::String(v), CompiledConditionValue::IpSet(set)) => {
				if let Ok(ip) = v.parse::<std::net::Ipv4Addr>() {
					let ip_u32 = u32::from_be_bytes(ip.octets());
					set.contains(&ip_u32)
				} else {
					false
				}
			}
			_ => false,
		}
	}

	fn numeric_cmp_compiled<F>(left: Option<&Value>, right: &CompiledConditionValue, cmp: F) -> bool
	where
		F: Fn(f64, f64) -> bool,
	{
		let Some(left) = left else {
			return false;
		};

		let Some(a) = left.as_integer().map(|x| x as f64).or_else(|| left.as_float()) else {
			return false;
		};

		let Some(b) = (match right {
			CompiledConditionValue::Int(x) => Some(*x as f64),
			_ => None,
		}) else {
			return false;
		};

		cmp(a, b)
	}

	fn equals_compiled(left: &Value, right: &CompiledConditionValue) -> bool {
		match (left, right) {
			(Value::Integer(a), CompiledConditionValue::Int(b)) => a == b,

			(Value::String(a), CompiledConditionValue::String(b)) => a == b.as_ref(),

			(Value::Boolean(a), CompiledConditionValue::Bool(b)) => a == b,
			(Value::String(a), CompiledConditionValue::Ip(ip_u32)) => {
				if let Ok(ip) = a.parse::<std::net::Ipv4Addr>() {
					u32::from_be_bytes(ip.octets()) == *ip_u32
				} else {
					false
				}
			}
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
	use std::collections::HashMap;
	use toml::Value;

	fn ctx(fields: &[(&str, Value)]) -> EvalCtx {
		let map: HashMap<String, Value> = fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
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
		let ctx = ctx(&[("process.pid", Value::Integer(42))]);
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
		let ctx = ctx(&[("process.uid", Value::Integer(1000))]);
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
			("process.comm", Value::String("sshd: worker".into())),
			("process.pid", Value::Integer(100)),
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
			response: None,
		};
		let ctx_ok = ctx(&[
			("process.pid", Value::Integer(123)),
			("process.comm", Value::String("bash".into())),
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
			response: None,
		};
		let ctx_fail = ctx(&[("process.pid", Value::Integer(123)), ("process.uid", Value::Integer(1000))]);
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
