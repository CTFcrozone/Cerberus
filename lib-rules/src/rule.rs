use std::path::Path;

use crate::error::{Error, Result};
use serde::Deserialize;
use simple_fs::SPath;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize)]
pub struct Rule {
	pub rule: RuleInner,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize)]
pub struct RuleInner {
	pub id: String,
	pub description: String,
	pub r#type: String,
	pub severity: Option<String>,
	pub category: Option<String>,
	pub conditions: Vec<Condition>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize)]
pub struct Prefilter {
	// filter by uid, path_prefix, etc
	pub uid_include: Option<Vec<u32>>,
	pub uid_exclude: Option<Vec<u32>>,
	pub path_prefix: Option<Vec<String>>,
}
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize)]
pub struct Condition {
	pub field: String,
	pub op: String,
	pub value: toml::Value,
}

impl Rule {
	pub fn from_str(s: &str) -> Result<Self> {
		let rule: Rule = toml::from_str(s)?;
		Ok(rule)
	}

	pub fn from_file(rule_path: impl AsRef<Path>) -> Result<Self> {
		let file_path = SPath::from_std_path(rule_path)?;

		if !file_path.exists() {
			return Err(Error::RulePathNotFound(file_path.into()));
		}

		let str = std::fs::read_to_string(file_path)?;
		let rule: Rule = toml::from_str(&str)?;

		Ok(rule)
	}
}

impl From<RuleInner> for Rule {
	fn from(value: RuleInner) -> Self {
		Self { rule: value }
	}
}

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
					op: "starts_with".to_string(),
					value: toml::Value::String("/tmp".to_string()),
				},
				Condition {
					field: "uid".to_string(),
					op: "not_in".to_string(),
					value: toml::Value::Array(vec![toml::Value::Integer(0)]),
				},
			],
		};
		let fx_rule = Rule::from(fx_rule_inner);
		// -- Exec
		let rule = Rule::from_file(fx_rule_path)?;
		// -- Check
		assert_eq!(fx_rule, rule);

		Ok(())
	}
}

// endregion: --- Tests
