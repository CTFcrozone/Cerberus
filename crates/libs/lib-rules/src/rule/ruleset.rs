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
	pub ruleset: Vec<Rule>,

	#[serde(skip)]
	pub by_id: HashMap<Arc<str>, usize>,
}

impl RuleSet {
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

					match by_id.entry(Arc::from(id_str)) {
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

		Ok(RuleSet { ruleset: rules, by_id })
	}

	pub fn rule_count(&self) -> usize {
		self.ruleset.len()
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
