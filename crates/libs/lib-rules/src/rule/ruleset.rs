use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crate::Rule;
use glob::glob;
use serde::Deserialize;
use tracing::warn;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct RuleSet {
	rules: Vec<Rule>,

	#[serde(skip)]
	by_id: HashMap<Arc<str>, usize>,
}

impl RuleSet {
	pub fn new(rules: Vec<Rule>) -> RuleSet {
		let mut by_id = HashMap::new();
		for (idx, rule) in rules.iter().enumerate() {
			let id_str = rule.inner.id.as_str();
			match by_id.entry(id_str.into()) {
				Entry::Vacant(e) => {
					e.insert(idx);
				}
				Entry::Occupied(_) => {
					warn!("Duplicate rule id '{}', skipping", id_str);
				}
			}
		}
		RuleSet { rules, by_id }
	}

	pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<RuleSet> {
		let mut rules = Vec::new();
		let mut by_id = HashMap::new();

		// Make sure the path is like: `rules/` or `some/stuff/rules/` and not `rules`
		let pattern = format!("{}/**/*.toml", dir.as_ref().display());

		for glob in glob(&pattern)? {
			match glob {
				Ok(path) => {
					let rule = Rule::from_file(&path)?;
					let id_str = rule.inner.id.as_str();

					match by_id.entry(id_str.into()) {
						Entry::Vacant(e) => {
							let idx = rules.len();
							e.insert(idx);
							rules.push(rule);
						}
						Entry::Occupied(_) => {
							warn!("Duplicate rule id '{}' in {:?}, skipping", id_str, path);
						}
					}
				}
				Err(e) => warn!("Glob pattern error: {:?}", e),
			}
		}

		Ok(RuleSet { rules, by_id })
	}

	pub fn find_rule_by_id(&self, rule_id: &str) -> Option<&Rule> {
		let idx = self.by_id.get(rule_id)?;
		self.rules.get(*idx)
	}

	pub fn rules(&self) -> &[Rule] {
		&self.rules
	}

	pub fn rule_count(&self) -> usize {
		self.rules.len()
	}
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use super::*;

	#[test]
	fn load_ruleset_from_dir() -> Result<()> {
		// -- Setup & Fixtures
		let fx_rule_dir = "rules/";
		let fx_rule_count = 3;
		// -- Exec
		let ruleset = RuleSet::load_from_dir(fx_rule_dir)?;
		// -- Check
		assert_eq!(fx_rule_count, ruleset.rule_count());

		Ok(())
	}
}

// endregion: --- Tests
