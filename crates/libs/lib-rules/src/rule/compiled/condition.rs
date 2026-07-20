use std::{net::IpAddr, sync::Arc};

use regex::Regex;

use crate::{
	Error,
	error::Result,
	rule::{
		Condition,
		compiled::{
			field::{Field, FieldType, compile_field},
			op::{Op, compile_op},
		},
	},
};

pub struct CompiledCondition {
	pub field: Field,
	pub op: Op,
	pub value: CompiledConditionValue,
}

pub enum CompiledConditionValue {
	Bool(bool),
	Int(i64),
	String(Arc<str>),
	Regex(Arc<Regex>),
	IntSet(Vec<i64>),
	StringSet(Vec<Arc<str>>),
	Ip(IpAddr),
	IpSet(Vec<IpAddr>),
}

impl CompiledConditionValue {
	pub fn ty(&self) -> FieldType {
		match self {
			Self::Bool(_) => FieldType::Bool,

			Self::Int(_) | Self::IntSet(_) => FieldType::Int,

			Self::String(_) | Self::StringSet(_) | Self::Regex(_) => FieldType::String,

			Self::Ip(_) | Self::IpSet(_) => FieldType::Ip,
		}
	}
}

pub fn compile_condition(raw: Condition) -> Result<CompiledCondition> {
	let field = compile_field(&raw.field)?;
	let op = compile_op(&raw.op)?;

	let value = match op {
		Op::Regex => {
			let pattern = raw.value.as_str().ok_or(Error::InvalidRegex)?;

			CompiledConditionValue::Regex(Arc::new(Regex::new(pattern)?))
		}

		_ => compile_value(raw.value)?,
	};
	validate_condition(field, op, &value)?;
	Ok(CompiledCondition { field, op, value })
}

fn compile_value(value: toml::Value) -> Result<CompiledConditionValue> {
	match value {
		toml::Value::Boolean(v) => Ok(CompiledConditionValue::Bool(v)),
		toml::Value::Integer(v) => Ok(CompiledConditionValue::Int(v)),
		toml::Value::String(v) => Ok(CompiledConditionValue::String(v.into())),
		toml::Value::Array(values) => {
			let Some(first) = values.first() else {
				return Err(Error::InvalidConditionValue);
			};

			match first {
				toml::Value::Integer(_) => {
					let mut out = Vec::with_capacity(values.len());
					for v in values {
						out.push(v.as_integer().ok_or(Error::InvalidConditionValue)?);
					}
					Ok(CompiledConditionValue::IntSet(out))
				}

				toml::Value::String(_) => {
					let mut out = Vec::with_capacity(values.len());
					for v in values {
						out.push(Arc::<str>::from(v.as_str().ok_or(Error::InvalidConditionValue)?));
					}
					Ok(CompiledConditionValue::StringSet(out))
				}
				_ => Err(Error::InvalidConditionValue),
			}
		}
		_ => Err(Error::InvalidConditionValue),
	}
}

fn validate_condition(field: Field, op: Op, value: &CompiledConditionValue) -> Result<()> {
	let ty = field.ty();

	match op {
		Op::Eq | Op::NotEq => {
			if value.ty() != ty {
				return Err(Error::InvalidConditionValue);
			}
		}

		Op::Gt | Op::Gte | Op::Lt | Op::Lte | Op::BitAnd => {
			if ty != FieldType::Int || value.ty() != FieldType::Int {
				return Err(Error::InvalidConditionValue);
			}
		}

		Op::Contains | Op::StartsWith | Op::Regex => {
			if ty != FieldType::String {
				return Err(Error::InvalidConditionValue);
			}
		}

		Op::In | Op::NotIn => match (ty, value) {
			(FieldType::Int, CompiledConditionValue::IntSet(_)) => {}
			(FieldType::String, CompiledConditionValue::StringSet(_)) => {}
			(FieldType::Ip, CompiledConditionValue::IpSet(_)) => {}

			_ => return Err(Error::InvalidConditionValue),
		},

		Op::Exists => {}
	}

	Ok(())
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

	use toml::Value;

	use crate::rule::Condition;

	use super::*;

	fn cond(field: &str, op: &str, value: Value) -> Condition {
		Condition {
			field: field.into(),
			op: op.into(),
			value,
		}
	}

	#[test]
	fn compile_integer_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond("process.pid", ">", Value::Integer(100));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_ok());

		Ok(())
	}

	#[test]
	fn compile_string_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond("process.comm", "contains", Value::String("bash".into()));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_ok());

		Ok(())
	}

	#[test]
	fn compile_regex_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond("process.comm", "regex", Value::String("^sshd".into()));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_ok());

		Ok(())
	}

	#[test]
	fn compile_integer_in_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond(
			"process.pid",
			"in",
			Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
		);

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_ok());

		Ok(())
	}

	#[test]
	fn reject_contains_on_integer() {
		// -- Setup & Fixtures
		let condition = cond("process.pid", "contains", Value::String("123".into()));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}

	#[test]
	fn reject_regex_on_integer() {
		// -- Setup & Fixtures
		let condition = cond("process.pid", "regex", Value::String(".*".into()));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}

	#[test]
	fn reject_integer_comparison_on_string() {
		// -- Setup & Fixtures
		let condition = cond("process.comm", ">", Value::Integer(10));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}

	#[test]
	fn reject_string_equality_on_integer_field() {
		// -- Setup & Fixtures
		let condition = cond("process.pid", "==", Value::String("123".into()));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}

	#[test]
	fn reject_integer_equality_on_string_field() {
		// -- Setup & Fixtures
		let condition = cond("process.comm", "==", Value::Integer(123));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}

	#[test]
	fn reject_string_set_for_integer_field() {
		// -- Setup & Fixtures
		let condition = cond(
			"process.pid",
			"in",
			Value::Array(vec![Value::String("1".into()), Value::String("2".into())]),
		);

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}

	#[test]
	fn reject_integer_set_for_string_field() {
		// -- Setup & Fixtures
		let condition = cond(
			"process.comm",
			"in",
			Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
		);

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());
	}
}

// endregion: --- Tests
