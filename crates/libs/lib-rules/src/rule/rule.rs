use std::{path::Path, sync::Arc};

use crate::{
	error::{Error, Result},
	hash_utils,
	rule::Sequence,
};
use regex::Regex;
use serde::Deserialize;
use simple_fs::SPath;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
	pub inner: RuleInner,
	pub hash: [u8; 32],
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
	pub r#type: String,
	pub severity: Option<String>,
	pub category: Option<String>,
	pub conditions: Vec<Condition>,
	#[serde(default)]
	pub sequence: Option<Sequence>,
	#[serde(default)]
	pub response: Option<Response>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct Condition {
	pub field: String,
	pub op: String,
	pub value: toml::Value,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
	KillProcess,
	DenyExec,
	IsolateContainer,
	ThrottleNetwork,
	EmitSignal { signal: i32 },
	Notify { message: String },
}

impl Rule {
	pub fn from_str(s: &str) -> Result<Self> {
		let rule: Rule = toml::from_str(s)?;
		Ok(rule)
	}

	pub fn hash_hex(&self) -> Arc<str> {
		hex::encode(self.hash).into()
	}

	pub fn from_file(rule_path: impl AsRef<Path>) -> Result<Self> {
		let file_path = SPath::from_std_path(rule_path)?;

		if !file_path.exists() {
			return Err(Error::RulePathNotFound(file_path.into()));
		}

		let str = std::fs::read_to_string(file_path)?;
		let rule_raw: RuleRaw = toml::from_str(&str)?;
		let hash = hash_utils::blake3(&str);

		Ok(Rule {
			inner: rule_raw.rule,
			hash,
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
			r#type: "file_event".to_string(),
			severity: Some("very-low".to_string()),
			category: Some("test".to_string()),

			conditions: vec![
				Condition {
					field: "path".to_string(),
					op: "regex".to_string(),
					value: toml::Value::String("^/tmp".to_string()),
				},
				Condition {
					field: "uid".to_string(),
					op: "not_in".to_string(),
					value: toml::Value::Array(vec![toml::Value::Integer(0)]),
				},
			],
			sequence: None,
			response: None,
		};
		let fx_rule = Rule {
			inner: fx_rule_inner,
			hash: [
				13, 57, 132, 16, 246, 117, 10, 68, 219, 132, 63, 208, 143, 207, 6, 180, 33, 12, 197, 109, 188, 84, 37,
				206, 149, 192, 162, 6, 61, 160, 251, 34,
			],
		};
		// -- Exec
		let rule = Rule::from_file(fx_rule_path)?;
		// -- Check
		assert_eq!(fx_rule, rule);

		Ok(())
	}
}

// endregion: --- Tests
