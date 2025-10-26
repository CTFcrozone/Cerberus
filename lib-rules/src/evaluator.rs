use regex::Regex;
use toml::Value;

use crate::{
	ctx::EvalCtx,
	rule::{Condition, RuleInner},
};

pub struct Evaluator;

impl Evaluator {
	pub fn equals(a: &Value, b: &Value) -> bool {
		if let (Some(ai), Some(bi)) = (a.as_integer(), b.as_integer()) {
			return ai == bi;
		}
		if let (Some(af), Some(bf)) = (a.as_float(), b.as_float()) {
			return (af - bf).abs() < std::f64::EPSILON;
		}
		if let (Some(ai), Some(bf)) = (a.as_integer(), b.as_float()) {
			return (ai as f64 - bf).abs() < std::f64::EPSILON;
		}
		if let (Some(af), Some(bi)) = (a.as_float(), b.as_integer()) {
			return (af - bi as f64).abs() < std::f64::EPSILON;
		}
		if let (Some(as_), Some(bs_)) = (a.as_str(), b.as_str()) {
			return as_ == bs_;
		}
		if let (Some(ab), Some(bb)) = (a.as_bool(), b.as_bool()) {
			return ab == bb;
		}
		a == b
	}

	pub fn eval_condition(left: Option<&Value>, cond: &Condition) -> bool {
		let op = cond.op.as_str();
		let right = &cond.value;

		match op {
			"equals" | "==" => {
				if let Some(l) = left {
					Self::equals(l, right)
				} else {
					false
				}
			}
			"in" => match right {
				Value::Array(arr) => {
					if let Some(l) = left {
						arr.iter().any(|v| Evaluator::equals(l, v))
					} else {
						false
					}
				}
				_ => false,
			},
			"not_in" => match right {
				Value::Array(arr) => {
					if let Some(l) = left {
						!arr.iter().any(|v| Evaluator::equals(l, v))
					} else {
						false
					}
				}
				_ => false,
			},
			"regex" | "matches_regex" => {
				if let (Some(Value::String(s)), Value::String(pattern)) = (left, right) {
					if let Ok(re) = Regex::new(pattern) {
						re.is_match(s)
					} else {
						false
					}
				} else {
					false
				}
			}
			">" | "gt" => left.map_or(false, |l| Self::numeric_cmp(l, right, |x, y| x > y)),
			"<" | "lt" => left.map_or(false, |l| Self::numeric_cmp(l, right, |x, y| x < y)),
			">=" | "gte" => left.map_or(false, |l| Self::numeric_cmp(l, right, |x, y| x >= y)),
			"<=" | "lte" => left.map_or(false, |l| Self::numeric_cmp(l, right, |x, y| x <= y)),
			"exists" => left.is_some(),
			_ => false,
		}
	}

	pub fn rule_matches(rule: &RuleInner, ctx: &EvalCtx) -> bool {
		rule.conditions.iter().all(|cond| {
			let left = ctx.get(&cond.field);
			Self::eval_condition(left, cond)
		})
	}

	pub fn in_array(val: &Value, target: &Value) -> bool {
		target
			.as_array()
			.map(|arr| arr.iter().any(|el| Self::equals(val, el)))
			.unwrap_or(false)
	}

	pub fn numeric_cmp<F>(a: &Value, b: &Value, cmp: F) -> bool
	where
		F: Fn(f64, f64) -> bool,
	{
		let aval = a
			.as_float()
			.or_else(|| a.as_integer().map(|i| i as f64))
			.or_else(|| a.as_str().and_then(|s| s.parse::<f64>().ok()));
		let bval = b
			.as_float()
			.or_else(|| b.as_integer().map(|i| i as f64))
			.or_else(|| b.as_str().and_then(|s| s.parse::<f64>().ok()));

		match (aval, bval) {
			(Some(x), Some(y)) => cmp(x, y),
			_ => false,
		}
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;
	use std::collections::HashMap;
	use toml::Value;

	fn ctx(fields: &[(&str, Value)]) -> EvalCtx {
		let map: HashMap<String, Value> = fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
		EvalCtx::new(map)
	}

	fn cond(field: &str, op: &str, value: Value) -> Condition {
		Condition {
			field: field.to_string(),
			op: op.to_string(),
			value,
		}
	}

	#[test]
	fn eval_equals_and_exists() -> Result<()> {
		// -- Setup & Fixtures
		let c1 = cond("pid", "equals", Value::Integer(42));
		let c2 = cond("pid", "exists", Value::Boolean(true));
		let ctx = ctx(&[("pid", Value::Integer(42))]);

		// -- Exec
		let res1 = Evaluator::eval_condition(ctx.get("pid"), &c1);
		let res2 = Evaluator::eval_condition(ctx.get("pid"), &c2);

		// -- Check
		assert!(res1);
		assert!(res2);

		Ok(())
	}

	#[test]
	fn eval_in_and_not_in() -> Result<()> {
		// -- Setup & Fixtures
		let c_in = cond(
			"uid",
			"in",
			Value::Array(vec![Value::Integer(1000), Value::Integer(2000)]),
		);
		let c_not_in = cond(
			"uid",
			"not_in",
			Value::Array(vec![Value::Integer(0), Value::Integer(1)]),
		);
		let ctx = ctx(&[("uid", Value::Integer(1000))]);

		// -- Exec
		let res_in = Evaluator::eval_condition(ctx.get("uid"), &c_in);
		let res_not_in = Evaluator::eval_condition(ctx.get("uid"), &c_not_in);

		// -- Check
		assert!(res_in);
		assert!(res_not_in);

		Ok(())
	}

	#[test]
	fn eval_regex_and_numeric() -> Result<()> {
		// -- Setup & Fixtures
		let c_regex = cond("comm", "regex", Value::String("^sshd".into()));
		let c_gt = cond("pid", ">", Value::Integer(10));
		let c_lt = cond("pid", "<", Value::Integer(200));
		let ctx = ctx(&[("comm", Value::String("sshd: worker".into())), ("pid", Value::Integer(100))]);

		// -- Exec
		let res_regex = Evaluator::eval_condition(ctx.get("comm"), &c_regex);
		let res_gt = Evaluator::eval_condition(ctx.get("pid"), &c_gt);
		let res_lt = Evaluator::eval_condition(ctx.get("pid"), &c_lt);

		// -- Check
		assert!(res_regex);
		assert!(res_gt);
		assert!(res_lt);

		Ok(())
	}

	#[test]
	fn rule_matches_success_and_failure() -> Result<()> {
		// -- Setup & Fixtures
		let rule_ok = RuleInner {
			id: "ok".into(),
			description: "ok".into(),
			r#type: "generic_event".into(),
			severity: None,
			category: None,
			conditions: vec![
				cond("pid", "equals", Value::Integer(123)),
				cond("comm", "==", Value::String("bash".into())),
			],
		};

		let ctx_ok = ctx(&[("pid", Value::Integer(123)), ("comm", Value::String("bash".into()))]);

		let rule_fail = RuleInner {
			id: "fail".into(),
			description: "fail".into(),
			r#type: "generic_event".into(),
			severity: None,
			category: None,
			conditions: vec![
				cond("pid", "equals", Value::Integer(123)),
				cond("uid", "equals", Value::Integer(0)),
			],
		};

		let ctx_fail = ctx(&[("pid", Value::Integer(123)), ("uid", Value::Integer(1000))]);

		// -- Exec
		let res_ok = Evaluator::rule_matches(&rule_ok, &ctx_ok);
		let res_fail = Evaluator::rule_matches(&rule_fail, &ctx_fail);

		// -- Check
		assert!(res_ok);
		assert!(!res_fail);

		Ok(())
	}
}

// endregion: --- Tests
