use std::{net::IpAddr, sync::Arc};

use regex::Regex;

use crate::{
	Error,
	error::Result,
	rule::{
		Condition,
		compiled::{
			field::{Field, compile_field},
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
