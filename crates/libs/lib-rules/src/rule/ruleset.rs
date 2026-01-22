use std::path::Path;

use crate::error::Result;
use crate::Rule;
use glob::glob;
use serde::Deserialize;
use tracing::warn;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Clone)]
pub struct RuleSet {
	pub ruleset: Vec<Rule>,
}

impl RuleSet {
	pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<RuleSet> {
		let mut rules = Vec::new();

		// Make sure the path is like: `rules/` or `some/stuff/rules/` and not `rules`
		let pattern = format!("{}/**/*.toml", dir.as_ref().display());

		for glob in glob(&pattern)? {
			match glob {
				Ok(path) => {
					let rule = Rule::from_file(path)?;
					rules.push(rule);
				}
				Err(e) => warn!("Glob pattern error: {:?}", e),
			}
		}

		Ok(RuleSet { ruleset: rules })
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
		let fx_rule_count = 7;
		// -- Exec
		let ruleset = RuleSet::load_from_dir(fx_rule_dir)?;
		// -- Check
		assert_eq!(fx_rule_count, ruleset.rule_count());

		Ok(())
	}
}

// endregion: --- Tests
