use std::sync::Arc;

use lib_event_schema::{Field, FieldType, FieldValue};
use regex::Regex;

use crate::{
	Error,
	error::Result,
	rule::{
		Condition,
		compiled::{
			field::compile_field,
			op::{Op, compile_op},
		},
	},
};

pub struct CompiledCondition {
	pub field: Field,
	pub op: Op,
	pub value: FieldValue,
}

pub fn compile_condition(raw: Condition) -> Result<CompiledCondition> {
	let field = compile_field(&raw.field)?;
	let op = compile_op(&raw.op)?;

	let value = match op {
		Op::Regex => {
			let pattern = raw.value.as_str().ok_or(Error::InvalidRegex)?;

			FieldValue::Regex(Arc::new(Regex::new(pattern)?))
		}

		_ => compile_value(raw.value)?,
	};
	validate_condition(field, op, &value)?;
	Ok(CompiledCondition { field, op, value })
}

fn compile_value(value: toml::Value) -> Result<FieldValue> {
	match value {
		toml::Value::Boolean(v) => Ok(FieldValue::Bool(v)),
		toml::Value::Integer(v) => Ok(FieldValue::Int(v)),
		toml::Value::String(v) => {
			if let Ok(ip) = v.parse::<std::net::Ipv4Addr>() {
				Ok(FieldValue::Ip(u32::from_be_bytes(ip.octets())))
			} else {
				Ok(FieldValue::String(v.into()))
			}
		}
		toml::Value::Array(values) => {
			let Some(first) = values.first() else {
				return Err(Error::InvalidFieldValue);
			};

			match first {
				toml::Value::Integer(_) => {
					let mut out = Vec::with_capacity(values.len());
					for v in values {
						out.push(v.as_integer().ok_or(Error::InvalidFieldValue)?);
					}
					Ok(FieldValue::IntSet(out))
				}

				toml::Value::String(_) => {
					let mut ip_values = Vec::with_capacity(values.len());
					let mut string_values = Vec::with_capacity(values.len());
					let mut all_ips = true;

					for v in values {
						let s = v.as_str().ok_or(Error::InvalidFieldValue)?;
						if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
							ip_values.push(u32::from_be_bytes(ip.octets()));
						} else {
							all_ips = false;
							string_values.push(Arc::<str>::from(s));
						}
					}
					if all_ips && !ip_values.is_empty() {
						Ok(FieldValue::IpSet(ip_values))
					} else {
						Ok(FieldValue::StringSet(string_values))
					}
				}
				_ => Err(Error::InvalidFieldValue),
			}
		}
		_ => Err(Error::InvalidFieldValue),
	}
}

fn validate_condition(field: Field, op: Op, value: &FieldValue) -> Result<()> {
	let ty = field.ty();

	match op {
		Op::Eq | Op::NotEq => {
			if value.ty() != ty {
				return Err(Error::InvalidFieldValue);
			}
		}

		Op::Gt | Op::Gte | Op::Lt | Op::Lte | Op::BitAnd => {
			if ty != FieldType::Int || value.ty() != FieldType::Int {
				return Err(Error::InvalidFieldValue);
			}
		}

		Op::Contains | Op::StartsWith | Op::Regex => {
			if ty != FieldType::String {
				return Err(Error::InvalidFieldValue);
			}
		}

		Op::In | Op::NotIn => match (ty, value) {
			(FieldType::Int, FieldValue::IntSet(_)) => {}
			(FieldType::String, FieldValue::StringSet(_)) => {}
			(FieldType::Ip, FieldValue::IpSet(_)) => {}

			_ => return Err(Error::InvalidFieldValue),
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

	#[test]
	fn compile_ip_equality_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond("network.daddr", "==", Value::String("192.168.1.100".into()));

		// -- Exec
		let compiled = compile_condition(condition)?;

		// -- Check
		assert!(matches!(compiled.value, FieldValue::Ip(_)));
		if let FieldValue::Ip(ip) = compiled.value {
			assert_eq!(ip, u32::from_be_bytes([192, 168, 1, 100]));
		}

		Ok(())
	}
	#[test]
	fn compile_ip_in_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond(
			"network.daddr",
			"in",
			Value::Array(vec![
				Value::String("192.168.1.100".into()),
				Value::String("10.0.0.1".into()),
				Value::String("172.16.0.1".into()),
			]),
		);

		// -- Exec
		let compiled = compile_condition(condition)?;

		// -- Check
		assert!(matches!(compiled.value, FieldValue::IpSet(_)));
		if let FieldValue::IpSet(ips) = compiled.value {
			assert_eq!(ips.len(), 3);
			assert!(ips.contains(&u32::from_be_bytes([192, 168, 1, 100])));
			assert!(ips.contains(&u32::from_be_bytes([10, 0, 0, 1])));
			assert!(ips.contains(&u32::from_be_bytes([172, 16, 0, 1])));
		}

		Ok(())
	}
	#[test]
	fn compile_invalid_ip_fails_to_compile() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond("network.daddr", "==", Value::String("999.999.999.999".into()));

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());

		Ok(())
	}
	#[test]
	fn reject_ip_field_with_string_set_validation() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond(
			"network.daddr",
			"in",
			Value::Array(vec![
				Value::String("192.168.1.100".into()),
				Value::String("not-an-ip".into()),
			]),
		);

		// -- Exec
		let compiled = compile_condition(condition);

		// -- Check
		assert!(compiled.is_err());

		Ok(())
	}

	#[test]
	fn compile_ip_not_in_condition() -> Result<()> {
		// -- Setup & Fixtures
		let condition = cond(
			"network.daddr",
			"not_in",
			Value::Array(vec![
				Value::String("192.168.1.100".into()),
				Value::String("10.0.0.1".into()),
			]),
		);

		// -- Exec
		let compiled = compile_condition(condition)?;

		// -- Check
		assert!(matches!(compiled.value, FieldValue::IpSet(_)));

		Ok(())
	}
}

// endregion: --- Tests
