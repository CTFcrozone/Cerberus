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
	#[serde(skip)]
	seq_by_id: HashMap<Arc<str>, Arc<str>>,
}

impl RuleSet {
	pub fn new(rules: Vec<Rule>) -> Result<RuleSet> {
		let mut by_id = HashMap::new();
		let mut seq_by_id = HashMap::new();
		for (idx, rule) in rules.iter().enumerate() {
			let rule_id: Arc<str> = rule.inner.id.as_str().into();

			if by_id.contains_key(&rule_id) {
				return Err(crate::Error::DuplicateRuleId {
					id: rule_id.to_string(),
				});
			}

			by_id.insert(rule_id.clone(), idx);

			if let Some(seq) = &rule.inner.sequence {
				let seq_id: Arc<str> = seq.id.as_str().into();

				if seq_by_id.contains_key(&seq_id) {
					return Err(crate::Error::DuplicateSequenceId { id: seq_id.to_string() });
				}

				seq_by_id.insert(seq_id, rule_id.clone());
			}
		}
		Ok(RuleSet {
			rules,
			by_id,
			seq_by_id,
		})
	}

	pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<RuleSet> {
		let mut rules = Vec::new();
		let mut by_id = HashMap::new();
		let mut seq_by_id = HashMap::new();

		// Make sure the path is like: `rules/` or `some/stuff/rules/` and not `rules`
		let pattern = format!("{}/**/*.toml", dir.as_ref().display());

		for glob in glob(&pattern)? {
			match glob {
				Ok(path) => {
					let rule = Rule::from_file(&path)?;
					let rule_id: Arc<str> = rule.inner.id.as_str().into();

					if by_id.contains_key(&rule_id) {
						return Err(crate::Error::DuplicateRuleId {
							id: rule_id.to_string(),
						});
					}

					let idx = rules.len();
					by_id.insert(rule_id.clone(), idx);

					if let Some(seq) = &rule.inner.sequence {
						let seq_id: Arc<str> = seq.id.as_str().into();

						if seq_by_id.contains_key(&seq_id) {
							return Err(crate::Error::DuplicateSequenceId { id: seq_id.to_string() });
						}

						seq_by_id.insert(seq_id, rule_id.clone());
					}

					rules.push(rule);
				}
				Err(e) => warn!("Glob pattern error: {:?}", e),
			}
		}

		Ok(RuleSet {
			rules,
			by_id,
			seq_by_id,
		})
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
