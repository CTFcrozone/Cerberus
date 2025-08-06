// [rule]
// id = "test-rule"
// description = "Suspicious action in /tmp"
// type = "file_event"
// category = "test"
// severity = "very-low"

// [[rule.prefilter]]
// uid_exclude = [0]
// path_prefix = ["/tmp"]

// [[rule.conditions]]
// field = "path"
// op = "starts_with"
// value = "/tmp"

// [[rule.conditions]]
// field = "uid"
// op = "not_in"
// value = [0]

use crate::error::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Rule {
	pub id: String,
	pub description: String,
	pub r#type: String,
	pub severity: Option<String>,
	pub category: Option<String>,
	pub prefilter: Option<Vec<Prefilter>>,
	pub conditions: Vec<Condition>,
}

#[derive(Debug, Deserialize)]
pub struct Prefilter {
	// filter by uid, path_prefix, etc
	pub uid_include: Option<Vec<u32>>,
	pub uid_exclude: Option<Vec<u32>>,
	pub path_prefix: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Condition {
	pub field: String,
	pub op: String,
	pub value: toml::Value,
}

impl Rule {
	pub fn from_string(s: &str) -> Result<Self> {
		let rule: Rule = toml::from_str(s)?;
		Ok(rule)
	}
}
