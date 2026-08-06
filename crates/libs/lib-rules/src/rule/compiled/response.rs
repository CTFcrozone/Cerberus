use std::{net::Ipv4Addr, str::FromStr};

use lib_event_schema::{Field, FieldType, FieldValue};
use strum::EnumCount;

use crate::{
	Error,
	error::Result,
	rule::{Action, ActionValue, ResponseChain, Trigger},
};

#[derive(Debug, Clone)]
pub enum CompiledActionValue {
	Literal(FieldValue),
	Field(Field),
}

#[derive(Debug, Clone)]
pub enum CompiledAction {
	KillProcess { pid: CompiledActionValue },
	BlockIp { ip: CompiledActionValue },
	DenyExec { path: CompiledActionValue },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedAction {
	KillProcess { pid: u32 },
	BlockIp { ip: Ipv4Addr },
	DenyExec { path_key: [u8; 128] },
}

#[derive(Debug, Clone)]
pub struct CompiledResponseChain {
	pub trigger: Trigger,
	pub actions: Vec<CompiledAction>,
}

pub fn compile_response_chain(raw: ResponseChain) -> Result<CompiledResponseChain> {
	let actions: Vec<CompiledAction> = raw.actions.into_iter().map(compile_action).collect::<Result<Vec<_>>>()?;

	Ok(CompiledResponseChain {
		trigger: raw.trigger,
		actions,
	})
}
pub fn resolve_action(action: &CompiledAction, fields: &[Option<FieldValue>; Field::COUNT]) -> Result<ResolvedAction> {
	match action {
		CompiledAction::BlockIp { ip } => {
			let value = resolve_param(ip, fields)?;

			match value {
				FieldValue::Ip(ip) => Ok(ResolvedAction::BlockIp { ip: ip.into() }),

				other => Err(Error::InvalidActionParamValue {
					expected: "ip".into(),
					actual: other.ty().as_str().into(),
				}),
			}
		}

		CompiledAction::KillProcess { pid } => {
			let value = resolve_param(pid, fields)?;

			match value {
				FieldValue::Int(pid) => {
					let pid = u32::try_from(pid).map_err(|_| Error::InvalidActionParamValue {
						expected: "non-negative 32-bit integer".into(),
						actual: pid.to_string(),
					})?;

					Ok(ResolvedAction::KillProcess { pid })
				}

				other => Err(Error::InvalidActionParamValue {
					expected: "integer".into(),
					actual: other.ty().as_str().into(),
				}),
			}
		}
		CompiledAction::DenyExec { path } => {
			let value = resolve_param(path, fields)?;
			match value {
				FieldValue::String(s) => Ok(ResolvedAction::DenyExec {
					path_key: path_to_deny_key(&s),
				}),
				other => Err(Error::InvalidActionParamValue {
					expected: "string".into(),
					actual: other.ty().as_str().into(),
				}),
			}
		}
	}
}
fn compile_action(action: Action) -> Result<CompiledAction> {
	Ok(match action {
		Action::KillProcess { pid } => CompiledAction::KillProcess {
			pid: compile_action_value(pid, FieldType::Int)?,
		},

		Action::BlockIp { ip } => CompiledAction::BlockIp {
			ip: compile_action_value(ip, FieldType::Ip)?,
		},
		Action::DenyExec { path } => CompiledAction::DenyExec {
			path: compile_action_value(path, FieldType::String)?,
		},
	})
}
fn compile_action_value(raw: ActionValue, expected: FieldType) -> Result<CompiledActionValue> {
	match raw {
		ActionValue::Field(name) => {
			let field = Field::from_str(&name).map_err(|_| Error::UnknownField { field: name })?;

			if field.ty() != expected {
				return Err(Error::InvalidBinding {
					field: field.as_str().into(),
					expected: expected.as_str().into(),
					actual: field.ty().as_str().into(),
				});
			}

			Ok(CompiledActionValue::Field(field))
		}
		ActionValue::Literal(v) => {
			let field_value = compile_literal(v, expected)?;
			Ok(CompiledActionValue::Literal(field_value))
		}
	}
}
fn compile_literal(value: toml::Value, expected: FieldType) -> Result<FieldValue> {
	let expected_name = expected.as_str().to_string();
	match expected {
		FieldType::Int => match value {
			toml::Value::Integer(v) => Ok(FieldValue::Int(v)),
			other => Err(Error::ExpectedType {
				expected: expected_name,
				found: other.type_str().into(),
			}),
		},

		FieldType::String => match value {
			toml::Value::String(v) => Ok(FieldValue::String(v.into())),
			other => Err(Error::ExpectedType {
				expected: expected_name,
				found: other.type_str().into(),
			}),
		},

		FieldType::Ip => match value {
			toml::Value::String(v) => {
				let ip: Ipv4Addr = v.parse()?;
				Ok(FieldValue::Ip(ip.into()))
			}
			other => Err(Error::ExpectedType {
				expected: expected_name,
				found: other.type_str().into(),
			}),
		},

		FieldType::Bool => match value {
			toml::Value::Boolean(v) => Ok(FieldValue::Bool(v)),
			other => Err(Error::ExpectedType {
				expected: expected_name,
				found: other.type_str().into(),
			}),
		},
	}
}
fn resolve_param(param: &CompiledActionValue, fields: &[Option<FieldValue>; Field::COUNT]) -> Result<FieldValue> {
	match param {
		CompiledActionValue::Literal(v) => Ok(v.clone()),

		CompiledActionValue::Field(field) => fields[field.index()].clone().ok_or(Error::MissingField {
			field: field.as_str().to_string(),
		}),
	}
}
fn path_to_deny_key(path: &str) -> [u8; 128] {
	let bytes = path.as_bytes();
	let len = bytes.len().min(128);
	let mut key = [0u8; 128];
	let start = 128 - len;
	key[start..].copy_from_slice(&bytes[..len]);
	key
}
// pub fn compile_response_chain(raw: ResponseChain) -> Result<CompiledResponseChain> {
// 	Ok(raw.into())
// }
