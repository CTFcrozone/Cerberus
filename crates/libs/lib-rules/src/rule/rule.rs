use std::{path::Path, sync::Arc};

use crate::{
	error::{Error, Result},
	hash_utils,
	rule::{Sequence, Trigger, common::Severity},
};
use serde::{Deserialize, Deserializer};
use simple_fs::SPath;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
	pub inner: RuleInner,
	pub hash: [u8; 32],
	pub hash_hex: Arc<str>,
}

#[derive(Deserialize)]
struct RuleRaw {
	rule: RuleInner,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct RuleInner {
	pub id: String,
	pub description: String,
	pub severity: Severity,
	pub conditions: Vec<Condition>,
	#[serde(default)]
	pub sequence: Option<Sequence>,
	#[serde(default)]
	pub response_chain: Option<ResponseChain>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct ResponseChain {
	pub trigger: Trigger,
	pub actions: Vec<Action>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Condition {
	pub field: String,
	pub op: String,
	pub value: toml::Value,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ActionValue {
	Literal(toml::Value),
	Field(String),
}

impl<'de> Deserialize<'de> for ActionValue {
	fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = toml::Value::deserialize(deserializer)?;

		match value {
			toml::Value::String(s) => {
				if let Some(field) = s.strip_prefix('$') {
					Ok(ActionValue::Field(field.to_string()))
				} else {
					Ok(ActionValue::Literal(toml::Value::String(s)))
				}
			}

			other => Ok(ActionValue::Literal(other)),
		}
	}
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", content = "params", rename_all = "snake_case")]
pub enum Action {
	KillProcess { pid: ActionValue },
	BlockIp { ip: ActionValue },
	DenyExec { path: ActionValue },
}

impl Rule {
	pub fn from_str(s: &str) -> Result<Self> {
		let rule_raw: RuleRaw = toml::from_str(&s)?;
		let hash = hash_utils::blake3(&s);
		let hash_hex = hash_utils::hex_encode(hash);

		Ok(Rule {
			inner: rule_raw.rule,
			hash,
			hash_hex,
		})
	}

	pub fn from_file(rule_path: impl AsRef<Path>) -> Result<Self> {
		let file_path = SPath::from_std_path(rule_path)?;

		if !file_path.exists() {
			return Err(Error::RulePathNotFound(file_path.into()));
		}

		let str = std::fs::read_to_string(file_path)?;
		let rule_raw: RuleRaw = toml::from_str(&str)?;
		let hash = hash_utils::blake3(&str);
		let hash_hex = hash_utils::hex_encode(hash);

		Ok(Rule {
			inner: rule_raw.rule,
			hash,
			hash_hex,
		})
	}
}

// impl From<RuleInner> for Rule {
// 	fn from(value: RuleInner) -> Self {
// 		Self { rule: value }
// 	}
// }

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;

	#[test]
	fn parse_rule_from_file_ok() -> Result<()> {
		// -- Setup & Fixtures
		let fx_rule_path = "rules/test-rule-1.toml";
		let fx_rule_inner = RuleInner {
			id: "test-rule".to_string(),
			description: "Suspicious action in /tmp".to_string(),
			severity: Severity::VeryLow,

			conditions: vec![
				Condition {
					field: "process.filepath".to_string(),
					op: "regex".to_string(),
					value: toml::Value::String("^/tmp".to_string()),
				},
				Condition {
					field: "process.uid".to_string(),
					op: "not_in".to_string(),
					value: toml::Value::Array(vec![toml::Value::Integer(0)]),
				},
			],
			sequence: None,
			response_chain: None,
		};
		let fx_rule = Rule {
			inner: fx_rule_inner,
			hash: [
				67, 183, 137, 15, 216, 243, 22, 38, 207, 119, 249, 13, 100, 163, 5, 254, 158, 175, 145, 39, 235, 200,
				24, 42, 91, 39, 6, 93, 172, 29, 90, 101,
			],
			hash_hex: Arc::from("43b7890fd8f31626cf77f90d64a305fe9eaf9127ebc8182a5b27065dac1d5a65"),
		};
		// -- Exec
		let rule = Rule::from_file(fx_rule_path)?;
		println!("{:?}", rule.hash);
		// -- Check
		assert_eq!(fx_rule, rule);

		Ok(())
	}
}

// endregion: --- Tests
